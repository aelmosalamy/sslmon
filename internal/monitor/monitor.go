// Package monitor tails Certificate Transparency logs and reports
// certificates issued for a target domain (and, by default, its subdomains).
//
// Each log is polled directly through the official client (GetSTH +
// GetRawEntries) rather than the library's scanner.Fetcher, so that a single
// misbehaving log cannot stall or flood the whole run: CT logs are routinely
// load-balanced across slightly out-of-sync replicas, which produces transient
// HTTP 400s and short reads near the tree's tip. Those are handled here with
// backoff instead of a tight retry loop.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"

	"sslmon/internal/loglist"
	"sslmon/internal/state"
)

const (
	defaultBatchSize    = 1000
	defaultPollInterval = 30 * time.Second
	errBackoffMin       = 2 * time.Second
	errBackoffMax       = 60 * time.Second

	// rateLimitPause is how long to wait after an HTTP 429 before touching a log
	// again. A 429 means we're asking too fast, so we slow down rather than
	// retry — retrying immediately only makes it worse.
	rateLimitPause = 60 * time.Second

	// onceMaxFailures bounds how many times -once mode retries a failing log
	// before skipping it, so a broken log can never hang a one-shot run.
	onceMaxFailures = 6
)

// Monitor tails a set of CT logs and invokes OnCert for every certificate that
// matches the target domain.
type Monitor struct {
	Domain     string
	Exact      bool
	Logs       []loglist.Log
	State      *state.Store
	HTTPClient *http.Client

	// Continuous keeps tailing each log as it grows. When false, each log is
	// read once from its checkpoint up to the current tree size and then the
	// run ends — useful for cron-style polling.
	Continuous bool

	// BatchSize is the number of entries requested per get-entries call.
	BatchSize int

	// PollInterval is how long to wait between catch-up passes in Continuous
	// mode. Defaults to 30s.
	PollInterval time.Duration

	// OnCert is called for each matching certificate. It must be safe for
	// concurrent use: logs are tailed in parallel.
	OnCert func(Cert)

	// Logf, if set, receives human-readable status and error messages.
	Logf func(format string, args ...any)
}

// Run tails every configured log concurrently. It returns when ctx is
// cancelled (Continuous mode) or when every log has been read up to its
// current tree size (one-shot mode).
func (m *Monitor) Run(ctx context.Context) error {
	match := NewMatcher(m.Domain, m.Exact)

	var wg sync.WaitGroup
	for _, lg := range m.Logs {
		wg.Add(1)
		go func(lg loglist.Log) {
			defer wg.Done()
			if err := m.tail(ctx, lg, match); err != nil && ctx.Err() == nil {
				m.logf("%s: stopped: %v", lg.URL, err)
			}
		}(lg)
	}
	wg.Wait()
	return ctx.Err()
}

// tail follows a single log: it learns the starting point, then repeatedly
// reads the current tree size and fetches any new entries.
func (m *Monitor) tail(ctx context.Context, lg loglist.Log, match Matcher) error {
	lc, err := client.New(lg.URL, m.HTTPClient, jsonclient.Options{UserAgent: "sslmon"})
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	next, ok := m.State.Next(lg.URL)
	if !ok {
		// First time we see this log: start from the current tip so we only
		// report newly-issued certificates.
		sth, err := lc.GetSTH(ctx)
		if err != nil {
			return fmt.Errorf("get STH: %w", err)
		}
		next = int64(sth.TreeSize)
		m.State.SetNext(lg.URL, next)
	}

	backoff := errBackoffMin
	failures := 0
	rateLimited := false
	for ctx.Err() == nil {
		sth, err := lc.GetSTH(ctx)
		var advanced bool
		if err == nil {
			advanced, err = m.catchUp(ctx, lc, lg, match, &next, int64(sth.TreeSize))
		}
		if advanced {
			// Progress this pass clears any earlier transient failures.
			failures, backoff = 0, errBackoffMin
		}

		if err != nil {
			if ctx.Err() != nil {
				break
			}

			// A 429 means we're requesting too fast. Don't retry into it —
			// pace down and resume on the next cycle (or stop, in -once mode).
			if isRateLimited(err) {
				if !m.Continuous {
					m.logf("%s: rate limited; stopping (rerun to resume)", lg.URL)
					return nil
				}
				if !rateLimited {
					m.logf("%s: rate limited (429); pausing %s between attempts", lg.URL, rateLimitPause)
					rateLimited = true
				}
				if !SleepFor(ctx, rateLimitPause) {
					break
				}
				continue
			}

			failures++
			if failures == 1 {
				m.logf("%s: %v (retrying)", lg.URL, err)
			}
			if !m.Continuous && failures >= onceMaxFailures {
				return fmt.Errorf("giving up after %d attempts: %w", failures, err)
			}
			if !sleep(ctx, &backoff) {
				break
			}
			continue
		}

		if failures > 0 || rateLimited {
			m.logf("%s: recovered", lg.URL)
			failures, backoff, rateLimited = 0, errBackoffMin, false
		}

		if !m.Continuous {
			return nil
		}
		if !SleepFor(ctx, m.pollInterval()) {
			break
		}
	}
	return ctx.Err()
}

// catchUp reads entries from *next up to treeSize a batch at a time, processing
// matches and advancing *next (and the persisted checkpoint) as it goes. It
// reports whether any entries were read so callers can treat partial progress
// as success.
func (m *Monitor) catchUp(ctx context.Context, lc *client.LogClient, lg loglist.Log, match Matcher, next *int64, treeSize int64) (advanced bool, err error) {
	batch := int64(m.BatchSize)
	if batch <= 0 {
		batch = defaultBatchSize
	}

	for *next < treeSize {
		if ctx.Err() != nil {
			return advanced, ctx.Err()
		}

		end := min(*next+batch, treeSize)
		resp, err := lc.GetRawEntries(ctx, *next, end-1)
		if err != nil {
			return advanced, fmt.Errorf("get entries [%d, %d): %w", *next, end, err)
		}
		if len(resp.Entries) == 0 {
			// A lagging replica can advertise more entries in its STH than it
			// will actually serve. Surface it as a retryable error rather than
			// spinning on the same empty range.
			return advanced, fmt.Errorf("no entries returned for [%d, %d)", *next, end)
		}

		m.process(lg, *next, resp.Entries, match)
		*next += int64(len(resp.Entries))
		m.State.SetNext(lg.URL, *next)
		advanced = true
	}
	return advanced, nil
}

// process parses a contiguous run of entries starting at startIndex and reports
// any that match the target domain.
func (m *Monitor) process(lg loglist.Log, startIndex int64, entries []ct.LeafEntry, match Matcher) {
	now := time.Now()
	for i := range entries {
		index := startIndex + int64(i)

		entry, err := ct.LogEntryFromLeaf(index, &entries[i])
		if err != nil && x509.IsFatal(err) {
			m.logf("%s: skipping entry %d: %v", lg.URL, index, err)
			continue
		}
		if entry == nil {
			continue
		}

		cert, der, isPrecert := leafCert(entry)
		if cert == nil || !match.Match(cert) {
			continue
		}
		m.OnCert(newCert(lg, index, cert, der, isPrecert, now))
	}
}

// isRateLimited reports whether err is an HTTP 429 from a CT log.
func isRateLimited(err error) bool {
	var rsp client.RspError
	return errors.As(err, &rsp) && rsp.StatusCode == http.StatusTooManyRequests
}

func (m *Monitor) pollInterval() time.Duration {
	if m.PollInterval > 0 {
		return m.PollInterval
	}
	return defaultPollInterval
}

func (m *Monitor) logf(format string, args ...any) {
	if m.Logf != nil {
		m.Logf(format, args...)
	}
}

// SleepFor waits for d or until ctx is cancelled. It reports false if ctx was
// cancelled. It is exported so callers outside this package (e.g. the crt.sh
// retry loop) can share one context-aware sleep instead of re-implementing it.
func SleepFor(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// sleep waits for the current backoff, then doubles it up to errBackoffMax. It
// reports false if ctx was cancelled.
func sleep(ctx context.Context, backoff *time.Duration) bool {
	ok := SleepFor(ctx, *backoff)
	if *backoff *= 2; *backoff > errBackoffMax {
		*backoff = errBackoffMax
	}
	return ok
}
