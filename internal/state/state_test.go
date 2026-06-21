package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFile(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if _, ok := s.Next("https://log.example/"); ok {
		t.Error("expected no checkpoint in a fresh store")
	}
}

func TestLoadEmptyFile(t *testing.T) {
	// An empty/whitespace-only state file must load as an empty store rather
	// than fail, so a truncated file doesn't wedge every run.
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("  \n"), 0o644); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load empty file: %v", err)
	}
	if _, ok := s.Next("https://log.example/"); ok {
		t.Error("expected an empty store from an empty file")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	s.SetNext("https://log.example/", 42)
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	s2, err := Load(path) // reopen: should read what Save wrote
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if idx, ok := s2.Next("https://log.example/"); !ok || idx != 42 {
		t.Fatalf("after reopen: idx=%d ok=%v, want 42,true", idx, ok)
	}
}
