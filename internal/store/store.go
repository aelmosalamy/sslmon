// Package store is sslmon's single on-disk file. It holds both the crt.sh
// result cache (keyed by domain) and the per-log watch checkpoints, so a user
// only ever has one ~/.sslmon.json to think about instead of separate cache and
// state files.
//
// A cache lookup is a hit only if the cached entry is still fresh (within the
// TTL) and its window reaches at least as far back as the request. Watch
// checkpoints record the next entry index to read from each CT log so restarts
// resume where they left off.
package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"sslmon/internal/atomicfile"
	"sslmon/internal/crtsh"
)

// cacheEntry is the cached result of one domain query.
type cacheEntry struct {
	Since     time.Time    `json:"since"`      // oldest not_before the query covered
	FetchedAt time.Time    `json:"fetched_at"` // when crt.sh was queried
	Certs     []crtsh.Cert `json:"certs"`      // newest-first, de-duplicated
}

// CacheEntry is a cached domain together with its certificates, returned by
// CachedEntries.
type CacheEntry struct {
	Domain    string
	Since     time.Time
	FetchedAt time.Time
	Certs     []crtsh.Cert
}

// fileData is the serialised shape of the store file.
type fileData struct {
	Cache       map[string]cacheEntry `json:"cache"`
	Checkpoints map[string]int64      `json:"checkpoints"`
}

// Store is the JSON-file-backed cache and checkpoint store. It is safe for
// concurrent use, because watch tails logs in parallel.
type Store struct {
	path string

	mu   sync.Mutex
	data fileData
}

// Open loads the store file at path. A missing or empty file yields an empty
// store.
func Open(path string) (*Store, error) {
	s := &Store{path: path, data: fileData{
		Cache:       map[string]cacheEntry{},
		Checkpoints: map[string]int64{},
	}}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		// An empty or whitespace-only file (e.g. left by an interrupted write)
		// is treated as a fresh, empty store rather than a hard error.
		return s, nil
	}
	if err := json.Unmarshal(data, &s.data); err != nil {
		return nil, fmt.Errorf("parse store file %s: %w", path, err)
	}
	if s.data.Cache == nil {
		s.data.Cache = map[string]cacheEntry{}
	}
	if s.data.Checkpoints == nil {
		s.data.Checkpoints = map[string]int64{}
	}
	return s, nil
}

// Save atomically writes the whole store (cache + checkpoints) to disk.
func (s *Store) Save() error {
	s.mu.Lock()
	data, err := json.MarshalIndent(s.data, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return atomicfile.Write(s.path, data, 0o644)
}

// Lookup returns the cached certificates for domain when a usable entry exists:
// one fetched within ttl of now whose window reaches back to at least `since`.
// The result is filtered to the requested window. A miss returns ok == false.
func (s *Store) Lookup(domain string, since, now time.Time, ttl time.Duration) (certs []crtsh.Cert, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, found := s.data.Cache[domain]
	if !found {
		return nil, false
	}
	if now.Sub(e.FetchedAt) > ttl { // stale
		return nil, false
	}
	if e.Since.After(since) { // cached window doesn't reach far enough back
		return nil, false
	}

	for _, cert := range e.Certs {
		if !cert.NotBefore.Before(since) {
			certs = append(certs, cert)
		}
	}
	return certs, true
}

// StoreCerts replaces the cached certificates for domain and persists the store.
func (s *Store) StoreCerts(domain string, since, fetchedAt time.Time, certs []crtsh.Cert) error {
	s.mu.Lock()
	s.data.Cache[domain] = cacheEntry{Since: since, FetchedAt: fetchedAt, Certs: certs}
	s.mu.Unlock()
	return s.Save()
}

// CachedEntries returns every cached domain and its certificates, sorted by
// domain.
func (s *Store) CachedEntries() []CacheEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]CacheEntry, 0, len(s.data.Cache))
	for domain, e := range s.data.Cache {
		out = append(out, CacheEntry{Domain: domain, Since: e.Since, FetchedAt: e.FetchedAt, Certs: e.Certs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// Next returns the stored next-index for a log and whether one was recorded.
func (s *Store) Next(logURL string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.data.Checkpoints[logURL]
	return idx, ok
}

// SetNext records the next entry index to read for a log. It updates memory
// only; callers persist via Save (watch does so periodically and on exit).
func (s *Store) SetNext(logURL string, index int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Checkpoints[logURL] = index
}
