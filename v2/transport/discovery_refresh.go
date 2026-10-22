/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Looking a discovered peer up again when what discovery read for it expires
 * from the resolver's cache (tdns-mp #260).
 *
 * Discovery copies what it reads onto the peer: the URI, the addresses, the
 * keys. The TLSA set is read through the cache again before each use (the
 * TLSAChecker), but the rest was not, so a peer could stay OPERATIONAL on
 * data whose TTL and signatures had run out long ago, and whose chain might
 * have broken since. Data that validated when it was looked up is used until
 * it expires from the cache. Then it is looked up again, and the new answer
 * decides: validated, and the peer goes on; refused for want of validation
 * (with require-dnssec-validation), and the mechanism goes back to NEEDED
 * (DiscoveryResult.refused).
 */
package transport

import (
	"context"
	"time"
)

const (
	// defaultDiscoveryRefreshInterval is how often the loop looks for peers
	// whose discovery data has expired.
	defaultDiscoveryRefreshInterval = 15 * time.Second
	// minDiscoveryRefresh is the least time between two refreshes of one
	// peer: a TTL of 0, or a discovery that keeps failing, does not make the
	// loop ask on every tick.
	minDiscoveryRefresh = time.Minute
	// defaultDiscoveryLifetime is how long data lives whose expiry is not
	// known: a resolver that does not say, or a status set by hand.
	defaultDiscoveryLifetime = time.Hour
	// discoveryRefreshTimeout bounds one peer's refresh.
	discoveryRefreshTimeout = 30 * time.Second
)

// due reports whether the peer's discovery data is to be looked up again at
// now: the peer was discovered, not within minDiscoveryRefresh, and either
// the last discovery gave nothing to use or what it read has expired (when
// that is not known, defaultDiscoveryLifetime after it ran).
func (s DiscoveryStatus) due(now time.Time) bool {
	if s.At.IsZero() || now.Sub(s.At) < minDiscoveryRefresh {
		return false
	}
	if s.Failure != FailureNone {
		return true
	}
	expires := s.Expires
	if expires.IsZero() {
		expires = s.At.Add(defaultDiscoveryLifetime)
	}
	return !now.Before(expires)
}

// StartDiscoveryRefresh starts the loop that looks a discovered peer up
// again when what discovery read for it expires from the resolver's cache.
// It runs until ctx is done. The application starts it, as it decides which
// peers are discovered at all; the loop only keeps their data current.
func (tm *TransportManager) StartDiscoveryRefresh(ctx context.Context) {
	go tm.runDiscoveryRefresh(ctx, defaultDiscoveryRefreshInterval)
}

func (tm *TransportManager) runDiscoveryRefresh(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tm.refreshExpiredDiscoveries(ctx, time.Now())
		}
	}
}

// refreshExpiredDiscoveries looks up again, one at a time, every peer whose
// discovery data is due at now, and returns how many it looked up. A peer
// whose last discovery failed is looked up here only while it is in use on
// what an earlier one found: the data has expired, and a lookup that cannot
// run says nothing about it, so it is kept and asked for again. A peer that
// is not in use is the application's to discover (its retrier).
func (tm *TransportManager) refreshExpiredDiscoveries(ctx context.Context, now time.Time) int {
	if tm.PeerRegistry == nil || tm.GetImr == nil {
		return 0
	}
	n := 0
	for _, peer := range tm.PeerRegistry.All() {
		if ctx.Err() != nil {
			return n
		}
		st := peer.DiscoveryStatus()
		if !st.due(now) || (st.Failure != FailureNone && !peer.inUse()) {
			continue
		}
		n++
		lctx, cancel := context.WithTimeout(ctx, discoveryRefreshTimeout)
		err := tm.DiscoverAndRegisterPeer(lctx, peer.ID)
		cancel()
		if err != nil {
			lgTransport().Warn("the peer's DNS data expired, and looking it up again gave nothing to use", "peer", peer.ID, "err", err)
			continue
		}
		lgTransport().Debug("looked the peer up again, as its DNS data expired", "peer", peer.ID)
	}
	return n
}

// inUse reports whether a mechanism of the peer is past NEEDED: in use on
// what discovery found.
func (p *Peer) inUse() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, m := range p.Mechanisms {
		if m != nil && m.State > PeerStateNeeded && m.State != PeerStateError {
			return true
		}
	}
	return false
}
