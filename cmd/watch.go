package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"sslmon/internal/loglist"
	"sslmon/internal/monitor"
	"sslmon/internal/store"
)

func runWatch(ctx context.Context, args []string) error {
	fs := newFlagSet("watch", "watch [flags] <domain>",
		"Tail the CT logs and report new certificates for a domain as they are logged.")
	var (
		onlyDomain = fs.Bool("only-domain", false, "match only the exact domain, not its subdomains")
		valid      = fs.Bool("valid", false, "only report certificates that are currently valid")
		all        = fs.Bool("all", false, "with -f txt, emit every SAN/CN, not just names matching the query")
		once       = fs.Bool("once", false, "read new entries once and exit (default: keep watching)")
		cachePath  = fs.String("cache", defaultStorePath(), "path to the cache/state file")
		logsFilter = fs.String("logs", "", "comma-separated substrings; only tail logs whose name, URL or operator matches")
		batch      = fs.Int("batch", 1000, "number of entries to request per fetch")
		interval   = fs.Duration("interval", 30*time.Second, "how often to poll each log for new entries")
	)
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
	if len(positionals) == 0 || positionals[0] == "" {
		fs.Usage()
		return errors.New("watch: missing domain argument")
	}
	domain := monitor.Normalize(positionals[0])

	hc := &http.Client{Timeout: 30 * time.Second}
	logs, err := loglist.FetchUsable(ctx, hc)
	if err != nil {
		return fmt.Errorf("fetch CT log list: %w", err)
	}
	logs = filterLogs(logs, *logsFilter)
	if len(logs) == 0 {
		return errors.New("no CT logs selected (check -logs filter)")
	}

	st, err := store.Open(*cachePath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
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

	match := monitor.NewMatcher(domain, *onlyDomain)
	m := &monitor.Monitor{
		Domain:       domain,
		Exact:        *onlyDomain,
		Logs:         logs,
		State:        st,
		HTTPClient:   hc,
		Continuous:   !*once,
		BatchSize:    *batch,
		PollInterval: *interval,
		OnCert:       newCertSink(out, format, match, *all, *valid),
		Logf:         func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) },
	}

	mode := "watching for new certificates"
	if *once {
		mode = "reading new entries since last run"
	}
	fmt.Fprintf(os.Stderr, "sslmon: %s for %q across %d CT logs\n", mode, domain, len(logs))

	if m.Continuous {
		go saveLoop(ctx, st, 15*time.Second)
	}
	runErr := m.Run(ctx)
	if err := st.Save(); err != nil {
		fmt.Fprintln(os.Stderr, "sslmon: save state:", err)
	}
	if errors.Is(runErr, context.Canceled) {
		return nil
	}
	return runErr
}

// newCertSink builds the OnCert callback for the chosen output format. For txt
// it streams distinct matching names as they arrive; for tsv/json it writes a
// full row per certificate.
func newCertSink(out io.Writer, f format, match monitor.Matcher, all, validOnly bool) func(monitor.Cert) {
	if f == formatText {
		sink := newNameSink(out)
		return func(c monitor.Cert) {
			if validOnly && !currentlyValid(c.NotBefore, c.NotAfter, time.Now()) {
				return
			}
			for _, n := range monitorNames(c) {
				nn := monitor.Normalize(n)
				if nn == "" {
					continue
				}
				if all || match.Covers(nn) {
					sink.emit(nn)
				}
			}
		}
	}

	w := newRowWriter(out, f)
	return func(c monitor.Cert) {
		if validOnly && !currentlyValid(c.NotBefore, c.NotAfter, time.Now()) {
			return
		}
		w.write(rowFromMonitor(c))
	}
}

// monitorNames returns every name on an observed cert: its SAN dNSNames plus its
// common name, as a fresh slice.
func monitorNames(c monitor.Cert) []string {
	out := make([]string, 0, len(c.Domains)+1)
	out = append(out, c.Domains...)
	if c.CommonName != "" {
		out = append(out, c.CommonName)
	}
	return out
}

func saveLoop(ctx context.Context, st *store.Store, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := st.Save(); err != nil {
				fmt.Fprintln(os.Stderr, "sslmon: save state:", err)
			}
		}
	}
}
