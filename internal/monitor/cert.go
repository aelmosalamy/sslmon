package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"

	"sslmon/internal/loglist"
)

// Cert is a flattened, serialisable view of a single certificate observed in a
// CT log.
type Cert struct {
	Domains      []string  `json:"domains"`
	CommonName   string    `json:"common_name"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	IsPrecert    bool      `json:"is_precert"`
	Fingerprint  string    `json:"fingerprint"` // SHA-256 of the leaf certificate, hex
	Log          string    `json:"log"`         // human-readable log description
	LogURL       string    `json:"log_url"`
	LogIndex     int64     `json:"log_index"`
	SeenAt       time.Time `json:"seen_at"`
}

// leafCert extracts the parsed X.509 certificate (final or pre-certificate)
// from a CT log entry, along with its raw DER bytes and whether it is a
// pre-certificate. It returns a nil certificate for entries that hold none.
func leafCert(entry *ct.LogEntry) (cert *x509.Certificate, der []byte, isPrecert bool) {
	switch {
	case entry.X509Cert != nil:
		return entry.X509Cert, entry.X509Cert.Raw, false
	case entry.Precert != nil:
		return entry.Precert.TBSCertificate, entry.Precert.Submitted.Data, true
	default:
		return nil, nil, false
	}
}

// newCert builds a Cert from a parsed certificate and its source log entry.
func newCert(lg loglist.Log, index int64, cert *x509.Certificate, der []byte, isPrecert bool, seenAt time.Time) Cert {
	sum := sha256.Sum256(der)
	return Cert{
		Domains:      cert.DNSNames,
		CommonName:   cert.Subject.CommonName,
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IsPrecert:    isPrecert,
		Fingerprint:  hex.EncodeToString(sum[:]),
		Log:          lg.Description,
		LogURL:       lg.URL,
		LogIndex:     index,
		SeenAt:       seenAt,
	}
}
