package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteCreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")

	if err := Write(path, []byte("first"), 0o644); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "first" {
		t.Fatalf("read after first write = %q, %v; want \"first\"", got, err)
	}

	if err := Write(path, []byte("second"), 0o644); err != nil {
		t.Fatalf("Write replace: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "second" {
		t.Fatalf("read after replace = %q, %v; want \"second\"", got, err)
	}

	// The temp file must be renamed away, not left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected only the final file, found %d entries: %v", len(entries), entries)
	}
}
