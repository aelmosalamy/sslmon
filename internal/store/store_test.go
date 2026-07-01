package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aelmosalamy/sslmon/internal/crtsh"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "sslmon.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
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
	s := newTestStore(t)
	now := time.Unix(10_000, 0)
	since := time.Unix(500, 0)

	if err := s.StoreCerts("example.com", since, now, sampleCerts()); err != nil {
		t.Fatalf("StoreCerts: %v", err)
	}

	got, ok := s.Lookup("example.com", since, now.Add(time.Minute), time.Hour)
	if !ok {
		t.Fatal("Lookup miss, want hit")
	}
	if len(got) != 2 || got[0].ID != 2 || got[1].ID != 1 {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestCacheAndCheckpointsShareOneFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sslmon.json")
	now := time.Unix(10_000, 0)

	s1, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s1.StoreCerts("example.com", time.Unix(500, 0), now, sampleCerts()); err != nil {
		t.Fatalf("StoreCerts: %v", err)
	}
	s1.SetNext("https://log.example/", 42)
	if err := s1.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reopen: both the cache and the checkpoint must survive in one file.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got, ok := s2.Lookup("example.com", time.Unix(500, 0), now.Add(time.Minute), time.Hour); !ok || len(got) != 2 {
		t.Fatalf("cache after reopen: ok=%v len=%d, want hit with 2", ok, len(got))
	}
	if idx, ok := s2.Next("https://log.example/"); !ok || idx != 42 {
		t.Fatalf("checkpoint after reopen: idx=%d ok=%v, want 42,true", idx, ok)
	}
}

func TestLookupMissOnStaleAndWindow(t *testing.T) {
	s := newTestStore(t)
	fetchedAt := time.Unix(10_000, 0)
	if err := s.StoreCerts("example.com", time.Unix(2_000, 0), fetchedAt, sampleCerts()); err != nil {
		t.Fatalf("StoreCerts: %v", err)
	}
	if _, ok := s.Lookup("example.com", time.Unix(2_000, 0), fetchedAt.Add(2*time.Hour), time.Hour); ok {
		t.Error("expected a miss for a stale entry")
	}
	if _, ok := s.Lookup("example.com", time.Unix(500, 0), fetchedAt.Add(time.Minute), time.Hour); ok {
		t.Error("expected a miss when the request window is wider than cached")
	}
}

func TestOpenEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sslmon.json")
	if err := os.WriteFile(path, []byte("  \n"), 0o644); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open empty file: %v", err)
	}
	if got := s.CachedEntries(); len(got) != 0 {
		t.Errorf("expected an empty store, got %d entries", len(got))
	}
}
