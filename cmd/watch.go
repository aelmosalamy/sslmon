package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"sslmon/internal/loglist"
	"sslmon/internal/monitor"
	"sslmon/internal/state"
)

func runWatch(ctx context.Context, args []string) error {
	fs := newFlagSet("watch", "watch [flags] <domain>",
		"Tail the CT logs and report new certificates for a domain as they are logged.")
	var (
		exact      = fs.Bool("exact", false, "match only the exact domain, not subdomains")
		out        = fs.StringP("output", "o", "text", "output format: text, tsv or json")
		once       = fs.Bool("once", false, "read new entries once and exit (default: keep watching)")
		statePath  = fs.String("state", defaultStatePath, "path to the checkpoint file")
		logsFilter = fs.String("logs", "", "comma-separated substrings; only tail logs whose name, URL or operator matches")
		batch      = fs.Int("batch", 1000, "number of entries to request per fetch")
		interval   = fs.Duration("interval", 30*time.Second, "how often to poll each log for new entries")
	)
	if showHelp(fs, args) {
		return nil
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	format, err := parseFormat(*out)
	if err != nil {
		return err
	}
	domain := fs.Arg(0)
	if domain == "" {
		fs.Usage()
		return errors.New("watch: missing domain argument")
	}

	hc := &http.Client{Timeout: 30 * time.Second}
	logs, err := loglist.FetchUsable(ctx, hc)
	if err != nil {
		return fmt.Errorf("fetch CT log list: %w", err)
	}
	logs = filterLogs(logs, *logsFilter)
	if len(logs) == 0 {
		return errors.New("no CT logs selected (check -logs filter)")
	}

	store, err := state.Load(*statePath)
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}

	w := newRowWriter(os.Stdout, format)
	m := &monitor.Monitor{
		Domain:       domain,
		Exact:        *exact,
		Logs:         logs,
		State:        store,
		HTTPClient:   hc,
		Continuous:   !*once,
		BatchSize:    *batch,
		PollInterval: *interval,
		OnCert:       func(c monitor.Cert) { w.write(rowFromMonitor(c)) },
		Logf:         func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) },
	}

	mode := "watching for new certificates"
	if *once {
		mode = "reading new entries since last run"
	}
	fmt.Fprintf(os.Stderr, "sslmon: %s for %q across %d CT logs\n", mode, domain, len(logs))

	if m.Continuous {
		go saveLoop(ctx, store, 15*time.Second)
	}
	runErr := m.Run(ctx)
	if err := store.Save(); err != nil {
		fmt.Fprintln(os.Stderr, "sslmon: save state:", err)
	}
	if errors.Is(runErr, context.Canceled) {
		return nil
	}
	return runErr
}

func saveLoop(ctx context.Context, store *state.Store, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := store.Save(); err != nil {
				fmt.Fprintln(os.Stderr, "sslmon: save state:", err)
			}
		}
	}
}
