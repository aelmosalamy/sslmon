package certcache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"sslmon/internal/crtsh"
)

func newTestCache(t *testing.T) *Cache {
	t.Helper()
	c, err := Open(filepath.Join(t.TempDir(), "cache.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return c
}

func sampleCerts() []crtsh.Cert {
	return []crtsh.Cert{
		{ID: 2, CommonName: "a.example.com", Issuer: "CA", Serial: "02",
			NotBefore: time.Unix(2_000, 0).UTC(), NotAfter: time.Unix(9_000, 0).UTC(),
			Names: []string{"a.example.com", "example.com"}},
		{ID: 1, CommonName: "example.com", Issuer: "CA", Serial: "01",
			NotBefore: time.Unix(1_000, 0).UTC(), NotAfter: time.Unix(8_000, 0).UTC(),
			Names: []string{"example.com"}},
	}
}

func TestStoreAndLookupHit(t *testing.T) {
	c := newTestCache(t)
	now := time.Unix(10_000, 0)
	since := time.Unix(500, 0)

	if err := c.Store("example.com", since, now, sampleCerts()); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, ok := c.Lookup("example.com", since, now.Add(time.Minute), time.Hour)
	if !ok {
		t.Fatal("Lookup miss, want hit")
	}
	if len(got) != 2 {
		t.Fatalf("got %d certs, want 2", len(got))
	}
	if got[0].ID != 2 || got[1].ID != 1 {
		t.Errorf("expected newest-first order, got ids %d,%d", got[0].ID, got[1].ID)
	}
	if len(got[0].Names) != 2 || got[0].Names[0] != "a.example.com" {
		t.Errorf("names round-tripped wrong: %v", got[0].Names)
	}
}

func TestLookupPersistsAcrossOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	now := time.Unix(10_000, 0)

	c1, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := c1.Store("example.com", time.Unix(500, 0), now, sampleCerts()); err != nil {
		t.Fatalf("Store: %v", err)
	}

	c2, err := Open(path) // reopen: should read what c1 wrote
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got, ok := c2.Lookup("example.com", time.Unix(500, 0), now.Add(time.Minute), time.Hour); !ok || len(got) != 2 {
		t.Fatalf("after reopen: ok=%v len=%d, want hit with 2", ok, len(got))
	}
}

func TestLookupMissOnStale(t *testing.T) {
	c := newTestCache(t)
	fetchedAt := time.Unix(10_000, 0)
	if err := c.Store("example.com", time.Unix(500, 0), fetchedAt, sampleCerts()); err != nil {
		t.Fatalf("Store: %v", err)
	}
	// Look up two hours later with a one-hour TTL.
	if _, ok := c.Lookup("example.com", time.Unix(500, 0), fetchedAt.Add(2*time.Hour), time.Hour); ok {
		t.Error("expected a miss for a stale entry")
	}
}

func TestLookupMissOnWiderWindow(t *testing.T) {
	c := newTestCache(t)
	now := time.Unix(10_000, 0)
	// Cached window starts at since=2000.
	if err := c.Store("example.com", time.Unix(2_000, 0), now, sampleCerts()); err != nil {
		t.Fatalf("Store: %v", err)
	}
	// Request reaches further back (since=500) than the cache covers.
	if _, ok := c.Lookup("example.com", time.Unix(500, 0), now.Add(time.Minute), time.Hour); ok {
		t.Error("expected a miss when the request window is wider than cached")
	}
}

func TestOpenEmptyFile(t *testing.T) {
	// A 0-byte or whitespace-only file (e.g. left by an interrupted write) must
	// open as an empty cache, not fail every invocation.
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(path, []byte("  \n"), 0o644); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open empty file: %v", err)
	}
	if got := c.Entries(); len(got) != 0 {
		t.Errorf("expected an empty cache, got %d entries", len(got))
	}
}

func TestLookupWindowFilter(t *testing.T) {
	c := newTestCache(t)
	now := time.Unix(10_000, 0)
	if err := c.Store("example.com", time.Unix(500, 0), now, sampleCerts()); err != nil {
		t.Fatalf("Store: %v", err)
	}
	// Narrower request (since=1500) should drop the cert at not_before=1000.
	got, ok := c.Lookup("example.com", time.Unix(1_500, 0), now.Add(time.Minute), time.Hour)
	if !ok {
		t.Fatal("Lookup miss, want hit")
	}
	if len(got) != 1 || got[0].ID != 2 {
		t.Errorf("expected only the newer cert, got %d rows", len(got))
	}
}
