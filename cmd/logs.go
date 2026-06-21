package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"sslmon/internal/loglist"
)

func runLogs(ctx context.Context, args []string) error {
	fs := newFlagSet("logs", "logs [flags]",
		"List the usable RFC 6962 CT logs that watch mode can tail.")
	logsFilter := fs.String("logs", "", "comma-separated substrings; only show logs whose name, URL or operator matches")
	if showHelp(fs, args) {
		return nil
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	hc := &http.Client{Timeout: 30 * time.Second}
	logs, err := loglist.FetchUsable(ctx, hc)
	if err != nil {
		return fmt.Errorf("fetch CT log list: %w", err)
	}
	logs = filterLogs(logs, *logsFilter)

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, lg := range logs {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", lg.Operator, lg.Description, lg.URL)
	}
	tw.Flush()
	fmt.Fprintf(os.Stderr, "\n%d usable RFC 6962 logs\n", len(logs))
	return nil
}

// filterLogs keeps only logs matching one of the comma-separated substrings. An
// empty filter keeps everything.
func filterLogs(logs []loglist.Log, filter string) []loglist.Log {
	var terms []string
	for _, t := range strings.Split(filter, ",") {
		if t = strings.TrimSpace(strings.ToLower(t)); t != "" {
			terms = append(terms, t)
		}
	}
	if len(terms) == 0 {
		return logs
	}

	var out []loglist.Log
	for _, lg := range logs {
		hay := strings.ToLower(lg.Description + " " + lg.URL + " " + lg.Operator)
		for _, t := range terms {
			if strings.Contains(hay, t) {
				out = append(out, lg)
				break
			}
		}
	}
	return out
}
