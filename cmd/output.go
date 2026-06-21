package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"sslmon/internal/crtsh"
	"sslmon/internal/monitor"
)

// Row is the unified output shape for a certificate, whether it came from a
// crt.sh lookup or a live CT-log observation. Keeping one shape means -o tsv and
// -o json look the same across commands, so downstream tools can be reused.
type Row struct {
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	CommonName  string    `json:"common_name"`
	Names       []string  `json:"names"`
	Issuer      string    `json:"issuer"`
	Source      string    `json:"source"`                // "crt.sh" or the CT log description
	Reference   string    `json:"reference"`             // crt.sh URL or "<log-url>#<index>"
	Fingerprint string    `json:"fingerprint,omitempty"` // SHA-256, watch mode only
}

func rowFromCrtsh(c crtsh.Cert) Row {
	return Row{
		NotBefore:  c.NotBefore,
		NotAfter:   c.NotAfter,
		CommonName: c.CommonName,
		Names:      c.Names,
		Issuer:     c.Issuer,
		Source:     "crt.sh",
		Reference:  c.URL(),
	}
}

func rowFromMonitor(c monitor.Cert) Row {
	return Row{
		NotBefore:   c.NotBefore,
		NotAfter:    c.NotAfter,
		CommonName:  c.CommonName,
		Names:       c.Domains,
		Issuer:      c.Issuer,
		Source:      c.Log,
		Reference:   fmt.Sprintf("%s#%d", c.LogURL, c.LogIndex),
		Fingerprint: c.Fingerprint,
	}
}

// format is an output encoding selected by -o.
type format int

const (
	formatText format = iota // human-readable blocks
	formatTSV                // one tab-separated line per cert, for piping
	formatJSON               // newline-delimited JSON
)

func parseFormat(s string) (format, error) {
	switch s {
	case "text":
		return formatText, nil
	case "tsv":
		return formatTSV, nil
	case "json":
		return formatJSON, nil
	default:
		return 0, fmt.Errorf("unknown output format %q (want text, tsv or json)", s)
	}
}

// rowWriter renders Rows in the chosen format. It is safe for concurrent use so
// watch mode can write from multiple log goroutines.
type rowWriter struct {
	mu     sync.Mutex
	w      io.Writer
	format format
	enc    *json.Encoder
}

func newRowWriter(w io.Writer, f format) *rowWriter {
	return &rowWriter{w: w, format: f, enc: json.NewEncoder(w)}
}

func (rw *rowWriter) write(r Row) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	switch rw.format {
	case formatJSON:
		_ = rw.enc.Encode(r)
	case formatTSV:
		fmt.Fprintln(rw.w, strings.Join([]string{
			r.NotBefore.UTC().Format(time.RFC3339),
			r.NotAfter.UTC().Format(time.RFC3339),
			primaryName(r.CommonName, r.Names),
			strings.Join(r.Names, ","),
			r.Issuer,
			r.Source,
			r.Reference,
			r.Fingerprint,
		}, "\t"))
	default:
		rw.writeText(r)
	}
}

func (rw *rowWriter) writeText(r Row) {
	fmt.Fprintf(rw.w, "%s  %s\n", r.NotBefore.Format("2006-01-02"), primaryName(r.CommonName, r.Names))
	fmt.Fprintf(rw.w, "    names:    %s\n", strings.Join(r.Names, ", "))
	fmt.Fprintf(rw.w, "    issuer:   %s\n", r.Issuer)
	fmt.Fprintf(rw.w, "    validity: %s  ->  %s\n", r.NotBefore.Format("2006-01-02"), r.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(rw.w, "    source:   %s\n", r.Source)
	if r.Fingerprint != "" {
		fmt.Fprintf(rw.w, "    sha256:   %s\n", r.Fingerprint)
	}
	fmt.Fprintf(rw.w, "    ref:      %s\n\n", r.Reference)
}

// primaryName is the best single label for a certificate: its common name, else
// its first SAN, else a placeholder. Shared by the row writers and the TUI so
// every view labels a certificate the same way.
func primaryName(commonName string, names []string) string {
	if commonName != "" {
		return commonName
	}
	if len(names) > 0 {
		return names[0]
	}
	return "(no name)"
}
