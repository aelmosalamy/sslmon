package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aelmosalamy/sslmon/internal/crtsh"
	"github.com/aelmosalamy/sslmon/internal/monitor"
	"github.com/aelmosalamy/sslmon/internal/store"
)

// runList is sslmon's default action. With a domain it lists that domain's
// certificates (from crt.sh, cached); with no domain it browses everything in
// the local store. -i opens an interactive list instead of printing rows.
func runList(ctx context.Context, args []string) error {
	fs := newFlagSet("list", "[flags] <domain>",
		"List a domain's certificates (via crt.sh). With no domain, browse the whole cache.")
	var (
		since      = fs.String("since", "1y", "how far back to include: e.g. 90d, 6w, 3m, 1y")
		onlyDomain = fs.Bool("only-domain", false, "match only the exact domain, not its subdomains")
		valid      = fs.Bool("valid", false, "only show certificates that are currently valid")
		all        = fs.Bool("all", false, "with -f txt, emit every SAN/CN, not just names matching the query")
		limit      = fs.Int("limit", 1000, "max certificates to fetch from crt.sh")
		refetch    = fs.Bool("refetch", false, "bypass the cache and re-fetch from crt.sh")
		cachePath  = fs.String("cache", defaultStorePath(), "path to the cache/state file")
		cacheTTL   = fs.Duration("cache-ttl", 24*time.Hour, "how long cached results stay fresh")
		connStr    = fs.String("crtsh", crtsh.DefaultConnString, "crt.sh PostgreSQL connection string")
	)
	var interactive bool
	fs.BoolVar(&interactive, "interactive", false, "browse results in an interactive, filterable list")
	fs.BoolVar(&interactive, "i", false, "shorthand for -interactive")
	var formatStr string
	fs.StringVar(&formatStr, "format", "txt", "output format: txt (names), tsv or json")
	fs.StringVar(&formatStr, "f", "txt", "shorthand for -format")
	outFile := fs.String("o", "", "write results to this file instead of stdout")

	if showHelp(fs, args) {
		return nil
	}
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	format, err := parseFormat(formatStr)
	if err != nil {
		return err
	}
	if *limit <= 0 {
		return fmt.Errorf("-limit must be a positive number (got %d)", *limit)
	}
	cutoff, err := parseSince(*since, time.Now())
	if err != nil {
		return err
	}

	st, err := store.Open(*cachePath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}

	var (
		items  []certItem
		match  monitor.Matcher
		browse bool
	)
	if len(positionals) > 0 && positionals[0] != "" {
		domain := monitor.Normalize(positionals[0])
		certs, source, err := fetchCerts(ctx, st, domain, cutoff, queryOpts{
			Limit: *limit, Refetch: *refetch, CacheTTL: *cacheTTL, ConnString: *connStr,
		})
		if err != nil {
			return err
		}
		// crt.sh's search is broader than our matching rules, so match precisely
		// and re-apply the window.
		match = monitor.NewMatcher(domain, *onlyDomain)
		for _, c := range certs {
			if !c.NotBefore.Before(cutoff) && (match.Covers(c.CommonName) || match.MatchNames(c.Names)) {
				items = append(items, certItem{domain: domain, cert: c})
			}
		}
		fmt.Fprintf(os.Stderr, "%d certificate(s) for %q since %s [%s]\n", len(items), domain, *since, source)
	} else {
		browse = true
		items = cachedItems(st, cutoff)
		if len(items) == 0 {
			fmt.Fprintln(os.Stderr, `cache is empty; run "sslmon <domain>" first`)
			return nil
		}
		fmt.Fprintf(os.Stderr, "%d cached certificate(s) since %s\n", len(items), *since)
	}

	if *valid {
		items = filterValid(items, time.Now())
	}

	// Newest first; break ties by crt.sh id so the order is deterministic for
	// certs sharing a not_before (common for precert/leaf pairs).
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i].cert, items[j].cert
		if !a.NotBefore.Equal(b.NotBefore) {
			return a.NotBefore.After(b.NotBefore)
		}
		return a.ID > b.ID
	})

	if interactive {
		return runTUI(ctx, items)
	}

	out := io.Writer(os.Stdout)
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	// txt is the clean, sorted, de-duplicated name list; tsv/json carry the full
	// per-certificate record.
	if format == formatText {
		for _, name := range collectNames(items, match, *all || browse) {
			fmt.Fprintln(out, name)
		}
		return nil
	}
	w := newRowWriter(out, format)
	for _, it := range items {
		w.write(rowFromCrtsh(it.cert))
	}
	return nil
}

// collectNames returns the de-duplicated, sorted set of names to print for
// -f txt. When all is true every SAN/CN is included; otherwise only names that
// match the query are kept (clean subdomain enumeration).
func collectNames(items []certItem, match monitor.Matcher, all bool) []string {
	set := map[string]struct{}{}
	for _, it := range items {
		for _, n := range allNames(it.cert) {
			nn := monitor.Normalize(n)
			if nn == "" {
				continue
			}
			if all || match.Covers(nn) {
				set[nn] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// filterValid keeps only certificates whose validity window contains now.
func filterValid(items []certItem, now time.Time) []certItem {
	out := items[:0]
	for _, it := range items {
		if currentlyValid(it.cert.NotBefore, it.cert.NotAfter, now) {
			out = append(out, it)
		}
	}
	return out
}

// cachedItems returns every cached certificate newer than cutoff, de-duplicated
// across domains by crt.sh id.
func cachedItems(st *store.Store, cutoff time.Time) []certItem {
	seen := map[int64]bool{}
	var items []certItem
	for _, e := range st.CachedEntries() {
		for _, c := range e.Certs {
			if c.NotBefore.Before(cutoff) || seen[c.ID] {
				continue
			}
			seen[c.ID] = true
			items = append(items, certItem{domain: e.Domain, cert: c})
		}
	}
	return items
}

// parseSince turns a relative window like "90d", "6w", "3m" or "1y" into a
// cutoff time (now minus that span). Unlike Go durations, the unit "m" means
// months, since these windows are calendar-scale.
func parseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	invalid := fmt.Errorf("invalid -since %q (use e.g. 90d, 6w, 3m, 1y)", s)
	if len(s) < 2 {
		return time.Time{}, invalid
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n < 0 {
		return time.Time{}, invalid
	}
	switch s[len(s)-1] {
	case 'd':
		return now.AddDate(0, 0, -n), nil
	case 'w':
		return now.AddDate(0, 0, -7*n), nil
	case 'm':
		return now.AddDate(0, -n, 0), nil
	case 'y':
		return now.AddDate(-n, 0, 0), nil
	default:
		return time.Time{}, invalid
	}
}

type queryOpts struct {
	Limit      int
	Refetch    bool
	CacheTTL   time.Duration
	ConnString string
}

// fetchCerts returns the de-duplicated certificates for domain, preferring a
// usable cache entry and falling back to crt.sh. The source is "cache" or
// "crt.sh".
func fetchCerts(ctx context.Context, st *store.Store, domain string, cutoff time.Time, opts queryOpts) ([]crtsh.Cert, string, error) {
	now := time.Now()
	if !opts.Refetch {
		if cached, ok := st.Lookup(domain, cutoff, now, opts.CacheTTL); ok {
			return cached, "cache", nil
		}
	}

	fmt.Fprintf(os.Stderr, "querying crt.sh for %q (this can take a while)...\n", domain)
	raw, err := queryWithRetry(ctx, crtsh.New(opts.ConnString), domain, cutoff, opts.Limit)
	if err != nil {
		return nil, "", fmt.Errorf("crt.sh query: %w", err)
	}
	certs := dedupeCerts(raw)
	if err := st.StoreCerts(domain, cutoff, now, certs); err != nil {
		fmt.Fprintln(os.Stderr, "sslmon: cache store:", err)
	}
	return certs, "crt.sh", nil
}

// queryWithRetry runs the crt.sh query, retrying a couple of times: crt.sh's
// public endpoint is a hot standby that cancels queries on timeout or
// replication conflict, and a retry usually succeeds.
func queryWithRetry(ctx context.Context, client *crtsh.Client, domain string, since time.Time, limit int) ([]crtsh.Cert, error) {
	const attempts = 3
	const perAttempt = 60 * time.Second
	backoff := 3 * time.Second

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, perAttempt)
		certs, err := client.Query(attemptCtx, domain, since, limit)
		cancel()
		if err == nil {
			return certs, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		lastErr = err
		if attempt < attempts {
			fmt.Fprintf(os.Stderr, "crt.sh attempt %d/%d failed (%v); retrying in %s...\n", attempt, attempts, err, backoff)
			if !monitor.SleepFor(ctx, backoff) {
				return nil, ctx.Err()
			}
			backoff *= 2
		}
	}
	return nil, lastErr
}

// dedupeCerts collapses the precertificate/leaf pairs (and per-log duplicates)
// crt.sh reports as separate rows but which share a serial and issuer.
func dedupeCerts(certs []crtsh.Cert) []crtsh.Cert {
	seen := make(map[string]bool, len(certs))
	out := certs[:0:0]
	for _, c := range certs {
		key := c.Serial + "|" + c.Issuer
		if c.Serial == "" {
			key = fmt.Sprintf("id:%d", c.ID)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

func defaultStorePath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".sslmon.json")
	}
	return ".sslmon.json"
}
