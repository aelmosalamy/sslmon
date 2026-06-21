// Package state persists how far this tool has read in each CT log, so that
// restarts resume where they left off instead of replaying or skipping
// entries.
package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"sslmon/internal/atomicfile"
)

// Store maps a CT log URL to the next entry index that should be read from it.
// It is safe for concurrent use, because logs are tailed in parallel.
type Store struct {
	path string

	mu          sync.Mutex
	checkpoints map[string]int64
}

// Load reads the checkpoint file at path. A missing file yields an empty store
// (so the first run starts from each log's current tip).
func Load(path string) (*Store, error) {
	s := &Store{path: path, checkpoints: map[string]int64{}}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		// An empty or whitespace-only file (e.g. left behind by an interrupted
		// write) is treated as a fresh, empty store rather than a hard error.
		return s, nil
	}
	if err := json.Unmarshal(data, &s.checkpoints); err != nil {
		return nil, fmt.Errorf("parse state file %s: %w", path, err)
	}
	return s, nil
}

// Next returns the stored next-index for a log and whether one was recorded.
func (s *Store) Next(logURL string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.checkpoints[logURL]
	return idx, ok
}

// SetNext records the next entry index to read for a log.
func (s *Store) SetNext(logURL string, index int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkpoints[logURL] = index
}

// Save atomically writes the current checkpoints to disk via a temp file and
// rename, so a crash mid-write cannot corrupt the existing state.
func (s *Store) Save() error {
	s.mu.Lock()
	data, err := json.MarshalIndent(s.checkpoints, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return atomicfile.Write(s.path, data, 0o644)
}
