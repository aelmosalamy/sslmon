// Package certcache stores crt.sh query results in a local JSON file so
// repeated lookups for the same domain don't re-hit the (rate-limited, often
// slow) crt.sh service.
//
// Results are cached per domain together with the time window they cover and
// when they were fetched. A lookup is a hit only if the cached entry is still
// fresh and its window reaches at least as far back as the request.
package certcache

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

// entry is the cached result of one domain query.
type entry struct {
	Since     time.Time    `json:"since"`      // oldest not_before the query covered
	FetchedAt time.Time    `json:"fetched_at"` // when crt.sh was queried
	Certs     []crtsh.Cert `json:"certs"`      // newest-first, de-duplicated
}

// Entry is a cached domain together with its certificates, returned by Entries.
type Entry struct {
	Domain    string
	Since     time.Time
	FetchedAt time.Time
	Certs     []crtsh.Cert
}

// Cache is a JSON-file-backed store of crt.sh results, keyed by domain.
type Cache struct {
	path string

	mu      sync.Mutex
	entries map[string]entry
}

// Open loads the cache file at path. A missing file yields an empty cache.
func Open(path string) (*Cache, error) {
	c := &Cache{path: path, entries: map[string]entry{}}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		// An empty or whitespace-only file (e.g. left behind by an interrupted
		// write) is treated as a fresh, empty cache rather than a hard error.
		return c, nil
	}
	if err := json.Unmarshal(data, &c.entries); err != nil {
		return nil, fmt.Errorf("parse cache file %s: %w", path, err)
	}
	return c, nil
}

// Lookup returns the cached certificates for domain when a usable entry exists:
// one fetched within ttl of now whose window reaches back to at least `since`.
// The result is filtered to the requested window. A miss returns ok == false.
func (c *Cache) Lookup(domain string, since, now time.Time, ttl time.Duration) (certs []crtsh.Cert, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, found := c.entries[domain]
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

// Entries returns every cached domain and its certificates, sorted by domain.
func (c *Cache) Entries() []Entry {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]Entry, 0, len(c.entries))
	for domain, e := range c.entries {
		out = append(out, Entry{Domain: domain, Since: e.Since, FetchedAt: e.FetchedAt, Certs: e.Certs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// Store replaces the cached certificates for domain and writes the file
// atomically (temp file + rename).
func (c *Cache) Store(domain string, since, fetchedAt time.Time, certs []crtsh.Cert) error {
	c.mu.Lock()
	c.entries[domain] = entry{Since: since, FetchedAt: fetchedAt, Certs: certs}
	data, err := json.MarshalIndent(c.entries, "", "  ")
	c.mu.Unlock()
	if err != nil {
		return err
	}
	return atomicfile.Write(c.path, data, 0o644)
}
