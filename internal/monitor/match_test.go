package monitor

import (
	"testing"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

func TestCoversSubdomains(t *testing.T) {
	m := NewMatcher("example.com", false)

	cases := map[string]bool{
		"example.com":          true,
		"EXAMPLE.COM":          true,  // case-insensitive
		"example.com.":         true,  // trailing root dot
		"www.example.com":      true,  // subdomain
		"a.b.example.com":      true,  // nested subdomain
		"*.example.com":        true,  // wildcard subdomain
		"*.sub.example.com":    true,  // nested wildcard
		"notexample.com":       false, // not a subdomain
		"example.com.evil.com": false, // suffix attack
		"example.org":          false,
		"":                     false,
	}
	for name, want := range cases {
		if got := m.Covers(name); got != want {
			t.Errorf("covers(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestCoversExact(t *testing.T) {
	m := NewMatcher("example.com", true)

	if !m.Covers("example.com") {
		t.Error("exact matcher should cover the domain itself")
	}
	for _, name := range []string{"www.example.com", "*.example.com"} {
		if m.Covers(name) {
			t.Errorf("exact matcher should not cover subdomain %q", name)
		}
	}
}

func TestMatchesCommonNameAndSAN(t *testing.T) {
	m := NewMatcher("example.com", false)

	cnOnly := &x509.Certificate{Subject: pkix.Name{CommonName: "www.example.com"}}
	if !m.Match(cnOnly) {
		t.Error("should match on common name")
	}

	sanOnly := &x509.Certificate{DNSNames: []string{"mail.other.org", "api.example.com"}}
	if !m.Match(sanOnly) {
		t.Error("should match on a SAN entry")
	}

	none := &x509.Certificate{DNSNames: []string{"example.org"}}
	if m.Match(none) {
		t.Error("should not match an unrelated certificate")
	}
}
