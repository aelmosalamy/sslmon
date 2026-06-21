package crtsh

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestQueryLive hits the real crt.sh PostgreSQL service. It is skipped unless
// CRTSH_LIVE is set, so the normal test run stays offline and fast.
//
//	CRTSH_LIVE=1 go test ./internal/crtsh -run Live -v
func TestQueryLive(t *testing.T) {
	if os.Getenv("CRTSH_LIVE") == "" {
		t.Skip("set CRTSH_LIVE=1 to run the live crt.sh test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	since := time.Now().AddDate(-3, 0, 0)
	certs, err := New("").Query(ctx, "elmosalamy.net", since, 100)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("expected at least one certificate")
	}

	var sawDomain bool
	for _, c := range certs {
		for _, n := range append(c.Names, c.CommonName) {
			if strings.HasSuffix(strings.ToLower(n), "elmosalamy.net") {
				sawDomain = true
			}
		}
		if c.NotBefore.Before(since) {
			t.Errorf("cert %d is older than the requested window", c.ID)
		}
	}
	if !sawDomain {
		t.Error("no returned certificate referenced the queried domain")
	}
	t.Logf("got %d certificates", len(certs))
}
