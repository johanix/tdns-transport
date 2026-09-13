/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * The chunk store for query-mode CHUNK (F2b, cleanup plan step 4): the
 * sender keeps a distribution's manifest and data records under the query
 * name until the receiver has fetched them. Moved here from tdns-mp; the
 * DNS transport owns both ends of the chunk chain.
 */

package transport

import (
	"sync"
	"time"

	"github.com/johanix/tdns/v2/core"
)

// ChunkStore holds the CHUNK records of pending query-mode distributions,
// keyed by the query name the receiver asks for (receiver.distid.sender).
// Index 0 is the manifest, 1..N the data records. Entries expire.
type ChunkStore interface {
	SetChunks(qname string, chunks []*core.CHUNK)
	GetChunk(qname string, sequence uint16) (chunk *core.CHUNK, ok bool)
}

type chunkArrayEntry struct {
	chunks  []*core.CHUNK
	expires time.Time
}

const chunkStoreMaxEntries = 10000

// MemChunkStore is an in-memory ChunkStore with a TTL and a size cap. An
// expired entry is dropped when it is read, and every entry is swept on a
// write at most once per TTL, so a distribution nobody fetches does not
// outlive about twice the TTL while the store is in use.
type MemChunkStore struct {
	mu          sync.Mutex
	chunkArrays map[string]*chunkArrayEntry
	ttl         time.Duration
	nextSweep   time.Time
}

// newMemChunkStore creates a store whose entries expire after ttl
// (5 minutes when ttl is not positive).
func newMemChunkStore(ttl time.Duration) *MemChunkStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &MemChunkStore{
		chunkArrays: make(map[string]*chunkArrayEntry),
		ttl:         ttl,
	}
}

// SetChunks stores a chunk array (manifest + data chunks) under the given
// qname. The chunks are deep-copied to prevent mutation by the caller.
func (s *MemChunkStore) SetChunks(qname string, chunks []*core.CHUNK) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if now.After(s.nextSweep) {
		s.sweepExpiredLocked(now)
		s.nextSweep = now.Add(s.ttl)
	}
	if _, exists := s.chunkArrays[qname]; !exists && len(s.chunkArrays) >= chunkStoreMaxEntries {
		s.evictOldestLocked()
	}

	copied := make([]*core.CHUNK, len(chunks))
	for i, c := range chunks {
		cp := *c
		cp.Data = append([]byte(nil), c.Data...)
		if c.HMAC != nil {
			cp.HMAC = append([]byte(nil), c.HMAC...)
		}
		copied[i] = &cp
	}

	s.chunkArrays[qname] = &chunkArrayEntry{
		chunks:  copied,
		expires: now.Add(s.ttl),
	}
}

// sweepExpiredLocked removes every expired entry. Must be called with mu held.
func (s *MemChunkStore) sweepExpiredLocked(now time.Time) {
	for k, e := range s.chunkArrays {
		if now.After(e.expires) {
			delete(s.chunkArrays, k)
		}
	}
}

// GetChunk returns one chunk of a stored array by sequence number (0 is the
// manifest, 1..N the data chunks), as a copy.
func (s *MemChunkStore) GetChunk(qname string, sequence uint16) (*core.CHUNK, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.chunkArrays[qname]
	if !ok || e == nil {
		return nil, false
	}
	if time.Now().After(e.expires) {
		delete(s.chunkArrays, qname)
		return nil, false
	}
	if int(sequence) >= len(e.chunks) {
		return nil, false
	}

	c := e.chunks[sequence]
	cp := *c
	cp.Data = append([]byte(nil), c.Data...)
	if c.HMAC != nil {
		cp.HMAC = append([]byte(nil), c.HMAC...)
	}
	return &cp, true
}

// Len reports the number of stored distributions.
func (s *MemChunkStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.chunkArrays)
}

// evictOldestLocked removes the entry with the earliest expiration time.
// Must be called with mu held.
func (s *MemChunkStore) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, e := range s.chunkArrays {
		if first || e.expires.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.expires
			first = false
		}
	}
	if !first {
		delete(s.chunkArrays, oldestKey)
	}
}
