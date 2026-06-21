package monitor

import (
	"strings"

	"github.com/google/certificate-transparency-go/x509"
)

// Matcher decides whether a certificate is relevant to the monitored domain.
// It is used both when tailing logs and when filtering crt.sh results.
type Matcher struct {
	domain string // normalised
	exact  bool   // if true, subdomains are ignored
}

// NewMatcher returns a Matcher for domain. When exact is false (the default)
// subdomains and wildcards are matched too.
func NewMatcher(domain string, exact bool) Matcher {
	return Matcher{domain: Normalize(domain), exact: exact}
}

// Match reports whether any name in the certificate (its SAN DNS names or its
// subject common name) refers to the monitored domain.
func (m Matcher) Match(cert *x509.Certificate) bool {
	if m.Covers(cert.Subject.CommonName) {
		return true
	}
	return m.MatchNames(cert.DNSNames)
}

// MatchNames reports whether any of the given names refers to the monitored
// domain.
func (m Matcher) MatchNames(names []string) bool {
	for _, name := range names {
		if m.Covers(name) {
			return true
		}
	}
	return false
}

// Covers reports whether a single certificate name refers to the monitored
// domain or, unless exact matching is requested, one of its subdomains. A
// leading "*." wildcard is handled naturally by the subdomain suffix check:
// "*.example.com" ends with ".example.com".
func (m Matcher) Covers(name string) bool {
	name = Normalize(name)
	if name == "" {
		return false
	}
	if name == m.domain {
		return true
	}
	if m.exact {
		return false
	}
	return strings.HasSuffix(name, "."+m.domain)
}

// Normalize lower-cases a domain name and trims surrounding whitespace and any
// trailing dot, so comparisons are case- and root-insensitive. It is shared by
// the matcher and the CLI so both agree on what a domain name looks like.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
