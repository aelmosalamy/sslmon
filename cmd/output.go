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
// crt.sh lookup or a live CT-log observation. Keeping one shape means -f tsv and
// -f json look the same across commands, so downstream tools can be reused.
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

// format is an output encoding selected by -f.
type format int

const (
	formatText format = iota // newline-delimited names (the clean, pipe-friendly list)
	formatTSV                // one tab-separated line per cert, for piping
	formatJSON               // newline-delimited JSON
)

func parseFormat(s string) (format, error) {
	switch s {
	case "txt", "text":
		return formatText, nil
	case "tsv":
		return formatTSV, nil
	case "json":
		return formatJSON, nil
	default:
		return 0, fmt.Errorf("unknown output format %q (want txt, tsv or json)", s)
	}
}

// rowWriter renders full Rows in TSV or JSON. It is safe for concurrent use so
// watch mode can write from multiple log goroutines. The txt format does not go
// through rowWriter — names are emitted directly (see collectNames / nameSink).
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
	default: // formatTSV
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
	}
}

// nameSink emits distinct names one per line, skipping repeats. It is safe for
// concurrent use, so watch mode can stream names from parallel log goroutines.
type nameSink struct {
	mu   sync.Mutex
	w    io.Writer
	seen map[string]struct{}
}

func newNameSink(w io.Writer) *nameSink {
	return &nameSink{w: w, seen: map[string]struct{}{}}
}

func (n *nameSink) emit(name string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.seen[name]; ok {
		return
	}
	n.seen[name] = struct{}{}
	fmt.Fprintln(n.w, name)
}

// primaryName is the best single label for a certificate: its common name, else
// its first SAN, else a placeholder. Shared by the TSV writer and the TUI so
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

// currentlyValid reports whether now falls within [notBefore, notAfter].
func currentlyValid(notBefore, notAfter, now time.Time) bool {
	return !notBefore.After(now) && notAfter.After(now)
}

// allNames returns every name on a crt.sh cert: its SAN dNSNames plus its common
// name. The result is a fresh slice, so callers may sort or extend it freely.
func allNames(c crtsh.Cert) []string {
	out := make([]string, 0, len(c.Names)+1)
	out = append(out, c.Names...)
	if c.CommonName != "" {
		out = append(out, c.CommonName)
	}
	return out
}
