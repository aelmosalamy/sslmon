// Package loglist fetches the Chrome CT log list and exposes the usable
// RFC 6962 logs that this tool knows how to tail.
package loglist

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/google/certificate-transparency-go/loglist3"
)

// maxLogListBytes caps how much of the log-list response we read. The real
// Chrome log list is well under a megabyte; the cap only guards against a
// misbehaving or hostile endpoint streaming an unbounded body into memory.
const maxLogListBytes = 64 << 20 // 64 MiB

// Log is a single CT log we can tail: a human-readable description and the
// base URL of its RFC 6962 HTTP API.
type Log struct {
	Description string
	URL         string
	Operator    string
}

// FetchUsable downloads the Chrome CT log list and returns every RFC 6962 log
// currently in the "usable" state.
//
// Static CT API ("tiled") logs are deliberately skipped: the official
// client/scanner used by this tool speaks the RFC 6962 get-entries API, which
// tiled logs do not serve. This is a known coverage gap.
func FetchUsable(ctx context.Context, hc *http.Client) ([]Log, error) {
	data, err := download(ctx, hc, loglist3.LogListURL)
	if err != nil {
		return nil, err
	}
	ll, err := loglist3.NewFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse log list: %w", err)
	}

	var logs []Log
	for _, op := range ll.Operators {
		for _, lg := range op.Logs {
			if lg.State == nil || lg.State.LogStatus() != loglist3.UsableLogStatus {
				continue
			}
			logs = append(logs, Log{
				Description: lg.Description,
				URL:         lg.URL,
				Operator:    op.Name,
			})
		}
	}
	return logs, nil
}

func download(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %s", url, resp.Status)
	}
	// Read one byte past the cap so an over-large body is reported as an error
	// rather than silently truncated (which would later fail to parse anyway).
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxLogListBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if int64(len(data)) > maxLogListBytes {
		return nil, fmt.Errorf("fetch %s: response larger than %d bytes", url, maxLogListBytes)
	}
	return data, nil
}
