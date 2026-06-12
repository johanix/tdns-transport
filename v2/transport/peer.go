/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Peer management for multi-provider DNSSEC coordination (HSYNC).
 * Manages the state and addresses of remote agents.
 */

package transport

import (
	"crypto"
	"fmt"
	"sync"
	"time"
)

// PeerState represents the current state of a peer relationship.
type PeerState uint8

const (
	PeerStateNeeded      PeerState = iota // Peer is needed but not yet discovered
	PeerStateDiscovering                  // Discovery in progress
	PeerStateKnown                        // Discovered but not yet contacted
	PeerStateIntroducing                  // Hello handshake in progress
	PeerStateOperational                  // Fully operational
	PeerStateDegraded                     // Operational but with issues
	PeerStateInterrupted                  // Temporarily unreachable
	PeerStateError                        // Persistent error state
)

func (s PeerState) String() string {
	switch s {
	case PeerStateNeeded:
		return "NEEDED"
	case PeerStateDiscovering:
		return "DISCOVERING"
	case PeerStateKnown:
		return "KNOWN"
	case PeerStateIntroducing:
		return "INTRODUCING"
	case PeerStateOperational:
		return "OPERATIONAL"
	case PeerStateDegraded:
		return "DEGRADED"
	case PeerStateInterrupted:
		return "INTERRUPTED"
	case PeerStateError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Peer represents a remote agent that we communicate with.
type Peer struct {
	mu sync.RWMutex

	// Identity
	ID          string // Unique identifier (typically provider name)
	DisplayName string // Human-readable name

	// State
	State        PeerState // Current relationship state
	StateReason  string    // Reason for current state
	StateChanged time.Time // When state last changed

	// Addresses
	DiscoveryAddr   *Address // Address discovered via DNS (URI/SVCB records)
	OperationalAddr *Address // Private address from Relocate (for DDoS mitigation)
	APIEndpoint     string   // Full URL for API transport (when available)
	DNSEndpoint     string   // Full dns:// URL for DNS transport (display/diagnostics;
	//                          the resolved IP lives in DiscoveryAddr/Mechanisms["DNS"].Address)

	// Cryptographic identity
	LongTermPubKey crypto.PublicKey // Peer's long-term public key
	KeyType        string           // Algorithm of the key
	TLSARecord     []byte           // TLSA record for TLS verification

	// Capabilities
	Capabilities []string // What the peer supports

	// Shared zones
	SharedZones map[string]*ZoneRelation // Zones we share with this peer

	// Communication state (single-state legacy fields, kept in sync with
	// Mechanisms via dual-write — see Bite 1 in
	// tdns-mp/docs/2026-04-25-transport-refactor-early-bites.md).
	LastHelloSent     time.Time // When we last sent a hello
	LastHelloReceived time.Time // When we last received a hello
	LastBeatSent      time.Time // When we last sent a beat
	LastBeatReceived  time.Time // When we last received a beat
	BeatSequence      uint64    // Current beat sequence number
	ConsecutiveFails  int       // Consecutive communication failures

	// Message statistics
	Stats MessageStats // Detailed per-message-type counters

	// Preferred transport
	PreferredTransport string // "API" or "DNS"

	// LivenessInterval is OUR local beat interval (seconds): how often we
	// beat this peer. Used by EffectiveState()'s age-based decay to judge
	// how many of our own beats a peer has missed. 0 ⇒ default (30s).
	LivenessInterval uint32

	// Per-mechanism state (Bite 1, additive). Keys: "API", "DNS".
	// Populated in parallel with the legacy single-state fields above
	// during the dual-write window. The legacy fields remain canonical
	// until Phase 1 of the main refactor deletes them.
	Mechanisms map[string]*MechanismState
}

// MechanismState tracks per-mechanism (e.g. "API", "DNS") state for a
// peer. Mirrors the per-mechanism shape the Agent struct in tdns-mp
// already has via ApiDetails/DnsDetails, so the eventual collapse to
// a single Peer-as-canonical model is straightforward.
//
// Added by Bite 1 of the transport refactor early-bites plan; see
// tdns-mp/docs/2026-04-25-transport-refactor-early-bites.md.
type MechanismState struct {
	State            PeerState
	StateReason      string
	StateChanged     time.Time
	Address          *Address
	LastHelloSent    time.Time
	LastHelloRecv    time.Time
	LastBeatSent     time.Time
	LastBeatRecv     time.Time
	BeatSequence     uint64
	ConsecutiveFails int
	Stats            MessageStats
	// ContactInfo is the discovery status for this mechanism, set when the
	// mechanism's endpoint is discovered (e.g. "complete"). Empty for peers
	// that were never discovered (config-only infra peers).
	ContactInfo string
}

// MessageStats tracks detailed statistics for messages exchanged with a peer.
// Separate counters for sent/received and per message type.
type MessageStats struct {
	mu sync.RWMutex

	// Last contact time (updated on any message sent or received)
	LastUsed time.Time

	// Per-message-type counters
	HelloSent       uint64
	HelloReceived   uint64
	BeatSent        uint64
	BeatReceived    uint64
	SyncSent        uint64
	SyncReceived    uint64
	PingSent        uint64
	PingReceived    uint64
	ConfirmSent     uint64
	ConfirmReceived uint64
	OtherSent       uint64
	OtherReceived   uint64

	// Total distribution count (sum of all message types)
	TotalSent     uint64
	TotalReceived uint64
}

// ZoneRelation tracks the relationship for a specific zone.
type ZoneRelation struct {
	Zone        string    // Zone name (FQDN)
	Role        string    // Our role: "primary", "secondary", "multi-signer"
	PeerRole    string    // Peer's role for this zone
	LastSync    time.Time // Last successful sync for this zone
	SyncSerial  uint32    // Last synced serial
	SyncPending bool      // Whether a sync is pending
}

// NewPeer creates a new Peer with the given ID.
func NewPeer(id string) *Peer {
	return &Peer{
		ID:           id,
		State:        PeerStateNeeded,
		StateChanged: time.Now(),
		SharedZones:  make(map[string]*ZoneRelation),
		Mechanisms: map[string]*MechanismState{
			"API": {State: PeerStateNeeded, StateChanged: time.Now()},
			"DNS": {State: PeerStateNeeded, StateChanged: time.Now()},
		},
	}
}

// HasMechanism reports whether the peer has the given mechanism
// (e.g. "API", "DNS") available — i.e. the per-mechanism address or
// endpoint is populated. The Mechanisms map being non-nil is necessary
// but not sufficient; the caller cares about reachability.
func (p *Peer) HasMechanism(name string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.Mechanisms == nil {
		return false
	}
	m, ok := p.Mechanisms[name]
	if !ok || m == nil {
		return false
	}
	switch name {
	case "DNS":
		return m.Address != nil
	case "API":
		return p.APIEndpoint != ""
	default:
		return false
	}
}

// PreferredMechanism returns the preferred mechanism name ("API" or
// "DNS") based on availability. API is preferred when both are
// available. Returns "" if neither is available.
func (p *Peer) PreferredMechanism() string {
	if p.HasMechanism("API") {
		return "API"
	}
	if p.HasMechanism("DNS") {
		return "DNS"
	}
	return ""
}

// EffectiveState returns the best state across all mechanisms, mirror
// of Agent.EffectiveState() in tdns-mp. Falls back to the legacy
// Peer.State if no mechanism has reached an active state.
//
// Liveness decay is applied on read: an active mechanism whose last
// successful beat round-trip is too old (per our LivenessInterval and
// the peer's advertised BeatInterval) reads as DEGRADED or INTERRUPTED,
// even though the stored State is still OPERATIONAL. This co-locates
// "I can reach this peer" with the beat data that proves it — promotion
// is stamped on a successful outbound beat, demotion falls out of the
// aging of that same timestamp. No external decay loop is needed.
func (p *Peer) EffectiveState() PeerState {
	p.mu.RLock()
	defer p.mu.RUnlock()

	best := PeerState(0)
	bestSet := false
	for _, name := range []string{"API", "DNS"} {
		m, ok := p.Mechanisms[name]
		if !ok || m == nil {
			continue
		}
		st := p.decayedMechanismState(m)
		switch st {
		case PeerStateOperational, PeerStateDegraded, PeerStateInterrupted:
			if !bestSet || st < best {
				best = st
				bestSet = true
			}
		}
	}
	if bestSet {
		return best
	}
	return p.State
}

// decayedMechanismState returns m.State after applying age-based liveness
// decay. Only active states (OPERATIONAL/DEGRADED/INTERRUPTED) decay; a
// mechanism not yet operational is returned unchanged. Mirrors the NG
// checkPeerState thresholds (2× ⇒ DEGRADED, 10× ⇒ INTERRUPTED) so the
// transport-owned read agrees with the NG store during the transition.
// Caller holds p.mu.
func (p *Peer) decayedMechanismState(m *MechanismState) PeerState {
	switch m.State {
	case PeerStateOperational, PeerStateDegraded, PeerStateInterrupted:
		// fall through to decay evaluation
	default:
		return m.State
	}

	localInterval := time.Duration(p.LivenessInterval) * time.Second
	if localInterval == 0 {
		localInterval = 30 * time.Second
	}

	// OPERATIONAL means "I can reach this peer", proven by our OUTBOUND
	// beat round-trip succeeding. So the decay keys on sinceS — time since
	// our last SUCCESSFUL outbound beat (LastBeatSent is stamped only on
	// success). We deliberately do NOT decay on inbound silence
	// (LastBeatRecv): a peer that stops beating US is a problem on the
	// other direction's axis, surfaced by the gossip matrix, not by our
	// own reachability state. A zero LastBeatSent means "no successful
	// beat yet" — treat as infinitely old so a mechanism that is marked
	// operational without beat evidence decays out.
	sinceS := timeSinceOrInf(m.LastBeatSent)

	if sinceS > 10*localInterval {
		return PeerStateInterrupted
	}
	if sinceS > 2*localInterval {
		return PeerStateDegraded
	}
	return PeerStateOperational
}

func timeSinceOrInf(t time.Time) time.Duration {
	if t.IsZero() {
		return 1<<62 - 1 // effectively infinite
	}
	return time.Since(t)
}

// SetMechanismState updates the per-mechanism state. Creates the
// MechanismState entry on first call for an unknown mechanism. The
// peer-level State field is not touched here; callers that want both
// updated should call SetState as well (the dual-write contract
// during Bite 1).
func (p *Peer) SetMechanismState(name string, state PeerState, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Mechanisms == nil {
		p.Mechanisms = make(map[string]*MechanismState)
	}
	m, ok := p.Mechanisms[name]
	if !ok || m == nil {
		m = &MechanismState{}
		p.Mechanisms[name] = m
	}
	m.State = state
	m.StateReason = reason
	m.StateChanged = time.Now()
}

// SetMechanismLastHelloRecv records the time a Hello was last received
// on the named mechanism. Creates the MechanismState entry on first
// call. Acquires p.mu for the duration of the write, so this is the
// safe replacement for direct map indexing of p.Mechanisms[name].
func (p *Peer) SetMechanismLastHelloRecv(name string, t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Mechanisms == nil {
		p.Mechanisms = make(map[string]*MechanismState)
	}
	m, ok := p.Mechanisms[name]
	if !ok || m == nil {
		m = &MechanismState{}
		p.Mechanisms[name] = m
	}
	m.LastHelloRecv = t
}

// SetMechanismLastBeatRecv records the time a Beat (or Ping treated as
// liveness) was last received on the named mechanism. Same locking
// contract as SetMechanismLastHelloRecv.
func (p *Peer) SetMechanismLastBeatRecv(name string, t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Mechanisms == nil {
		p.Mechanisms = make(map[string]*MechanismState)
	}
	m, ok := p.Mechanisms[name]
	if !ok || m == nil {
		m = &MechanismState{}
		p.Mechanisms[name] = m
	}
	m.LastBeatRecv = t
}

// SetMechanismLastBeatSent records the time a Beat was last sent on the
// named mechanism. Used by liveness/age evaluation to detect a peer we
// can no longer reach (no successful outbound beat for N intervals).
// Same locking contract as SetMechanismLastBeatRecv.
func (p *Peer) SetMechanismLastBeatSent(name string, t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Mechanisms == nil {
		p.Mechanisms = make(map[string]*MechanismState)
	}
	m, ok := p.Mechanisms[name]
	if !ok || m == nil {
		m = &MechanismState{}
		p.Mechanisms[name] = m
	}
	m.LastBeatSent = t
}

// SetMechanismContactInfo sets the discovery contact-info status for a
// mechanism (e.g. "complete" once the mechanism's endpoint was discovered).
// Creates the MechanismState entry on first call. Same locking contract as
// SetMechanismState.
func (p *Peer) SetMechanismContactInfo(name, status string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Mechanisms == nil {
		p.Mechanisms = make(map[string]*MechanismState)
	}
	m, ok := p.Mechanisms[name]
	if !ok || m == nil {
		m = &MechanismState{}
		p.Mechanisms[name] = m
	}
	m.ContactInfo = status
}

// MechanismContactInfo returns the discovery contact-info status for the named
// mechanism, or "" if the mechanism is unknown or was never discovered.
func (p *Peer) MechanismContactInfo(name string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.Mechanisms == nil {
		return ""
	}
	if m, ok := p.Mechanisms[name]; ok && m != nil {
		return m.ContactInfo
	}
	return ""
}

// MechanismBeatSequence returns the count of beats successfully sent on
// the named mechanism, or 0 if the mechanism is unknown. Maintained by
// RecordMechanismBeatSent on the transport's own Beat() success path.
func (p *Peer) MechanismBeatSequence(name string) uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.Mechanisms == nil {
		return 0
	}
	if m, ok := p.Mechanisms[name]; ok && m != nil {
		return m.BeatSequence
	}
	return 0
}

// MechanismEffectiveState returns the named mechanism's state with
// age-based liveness decay applied (the same decay EffectiveState uses,
// but for a single mechanism rather than the cross-mechanism best). The
// bool is false if the mechanism is not present. Used by per-transport
// display rows that want the canonical, decayed per-mechanism state.
func (p *Peer) MechanismEffectiveState(name string) (PeerState, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.Mechanisms == nil {
		return PeerState(0), false
	}
	m, ok := p.Mechanisms[name]
	if !ok || m == nil {
		return PeerState(0), false
	}
	return p.decayedMechanismState(m), true
}

// AgentMechanismSnapshot is a point-in-time view of one mechanism's
// state on an Agent (in tdns-mp terms). PopulateFromAgent uses
// instances of this struct to fill MechanismState entries on a Peer.
//
// The struct decouples transport from the MP Agent type — transport
// never imports or references *Agent directly; instead it consumes
// snapshots produced by AgentLike implementations.
//
// Added by Bite 7 of the transport refactor early-bites plan; see
// tdns-mp/docs/2026-04-25-transport-refactor-early-bites.md.
type AgentMechanismSnapshot struct {
	State            PeerState
	StateReason      string
	Address          *Address
	LastHelloSent    time.Time
	LastHelloRecv    time.Time
	LastBeatSent     time.Time
	LastBeatRecv     time.Time
	BeatSequence     uint64
	ConsecutiveFails int
}

// AgentLike is satisfied by tdns-mp's *Agent. It exposes the
// per-mechanism state needed to populate a Peer. Defined as an
// interface so transport stays decoupled from MP.
type AgentLike interface {
	APIMechanismState() AgentMechanismSnapshot
	DNSMechanismState() AgentMechanismSnapshot
}

// PopulateFromAgent fills p.Mechanisms["API"] and p.Mechanisms["DNS"]
// from an AgentLike. The mechanism map is created if absent.
//
// State, address, and timestamps are mirrored field-by-field from the
// snapshots. This is the canonical Peer-from-Agent path that
// SyncPeerFromAgent in tdns-mp delegates to during the dual-write
// window. Once Phase 7 of the main refactor deletes the duplicated
// Agent state, PopulateFromAgent (or its successor) becomes the
// single source of truth for the Peer's per-mechanism view.
//
// Note: peer.APIEndpoint is the canonical reachability marker for the
// API mechanism (a string URL); MechanismState.Address is the
// reachability marker for DNS (a host/port pair). PopulateFromAgent
// writes both — the caller must ensure peer.APIEndpoint is set
// alongside if the agent's API endpoint is known.
func (p *Peer) PopulateFromAgent(a AgentLike) {
	if a == nil {
		return
	}
	apiSnap := a.APIMechanismState()
	dnsSnap := a.DNSMechanismState()

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Mechanisms == nil {
		p.Mechanisms = make(map[string]*MechanismState)
	}

	for _, e := range []struct {
		name string
		snap AgentMechanismSnapshot
	}{
		{"API", apiSnap},
		{"DNS", dnsSnap},
	} {
		m, ok := p.Mechanisms[e.name]
		if !ok || m == nil {
			m = &MechanismState{}
			p.Mechanisms[e.name] = m
		}
		// Skip state regression: only update StateChanged if state
		// actually changed (preserves the timestamp of the last real
		// transition).
		if m.State != e.snap.State {
			m.State = e.snap.State
			m.StateReason = e.snap.StateReason
			m.StateChanged = time.Now()
		}
		if e.snap.Address != nil {
			m.Address = e.snap.Address
		}
		if !e.snap.LastHelloSent.IsZero() {
			m.LastHelloSent = e.snap.LastHelloSent
		}
		if !e.snap.LastHelloRecv.IsZero() {
			m.LastHelloRecv = e.snap.LastHelloRecv
		}
		if !e.snap.LastBeatSent.IsZero() {
			m.LastBeatSent = e.snap.LastBeatSent
		}
		if !e.snap.LastBeatRecv.IsZero() {
			m.LastBeatRecv = e.snap.LastBeatRecv
		}
		if e.snap.BeatSequence > m.BeatSequence {
			m.BeatSequence = e.snap.BeatSequence
		}
		// ConsecutiveFails: take the snapshot value verbatim (not max),
		// because a successful contact must be able to clear it.
		m.ConsecutiveFails = e.snap.ConsecutiveFails
	}
}

// SetState updates the peer's state with a reason.
func (p *Peer) SetState(state PeerState, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.State = state
	p.StateReason = reason
	p.StateChanged = time.Now()
}

// RecordMessageSent records statistics for an outgoing message.
func (ms *MessageStats) RecordMessageSent(msgType string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.LastUsed = time.Now()
	ms.TotalSent++

	switch msgType {
	case "hello":
		ms.HelloSent++
	case "beat":
		ms.BeatSent++
	case "sync", "update":
		ms.SyncSent++
	case "ping":
		ms.PingSent++
	case "confirm":
		ms.ConfirmSent++
	default:
		ms.OtherSent++
	}
}

// RecordMessageReceived records statistics for an incoming message.
func (ms *MessageStats) RecordMessageReceived(msgType string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.LastUsed = time.Now()
	ms.TotalReceived++

	switch msgType {
	case "hello":
		ms.HelloReceived++
	case "beat":
		ms.BeatReceived++
	case "sync", "update":
		ms.SyncReceived++
	case "ping":
		ms.PingReceived++
	case "confirm":
		ms.ConfirmReceived++
	default:
		ms.OtherReceived++
	}
}

// GetStats returns a snapshot of current statistics (thread-safe).
func (ms *MessageStats) GetStats() (lastUsed time.Time, sent, received uint64) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	return ms.LastUsed, ms.TotalSent, ms.TotalReceived
}

// GetDetailedStats returns all per-message-type statistics.
func (ms *MessageStats) GetDetailedStats() MessageStatsSnapshot {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	return MessageStatsSnapshot{
		LastUsed:        ms.LastUsed,
		HelloSent:       ms.HelloSent,
		HelloReceived:   ms.HelloReceived,
		BeatSent:        ms.BeatSent,
		BeatReceived:    ms.BeatReceived,
		SyncSent:        ms.SyncSent,
		SyncReceived:    ms.SyncReceived,
		PingSent:        ms.PingSent,
		PingReceived:    ms.PingReceived,
		ConfirmSent:     ms.ConfirmSent,
		ConfirmReceived: ms.ConfirmReceived,
		OtherSent:       ms.OtherSent,
		OtherReceived:   ms.OtherReceived,
		TotalSent:       ms.TotalSent,
		TotalReceived:   ms.TotalReceived,
	}
}

// MessageStatsSnapshot is a point-in-time copy of MessageStats.
type MessageStatsSnapshot struct {
	LastUsed        time.Time
	HelloSent       uint64
	HelloReceived   uint64
	BeatSent        uint64
	BeatReceived    uint64
	SyncSent        uint64
	SyncReceived    uint64
	PingSent        uint64
	PingReceived    uint64
	ConfirmSent     uint64
	ConfirmReceived uint64
	OtherSent       uint64
	OtherReceived   uint64
	TotalSent       uint64
	TotalReceived   uint64
}

// GetState returns the peer's current state.
func (p *Peer) GetState() PeerState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.State
}

// CurrentAddress returns the address to use for communication.
// Prefers OperationalAddr if available (post-Relocate), falls back to DiscoveryAddr.
func (p *Peer) CurrentAddress() *Address {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.OperationalAddr != nil {
		return p.OperationalAddr
	}
	return p.DiscoveryAddr
}

// SetDiscoveryAddress sets the address discovered via DNS.
func (p *Peer) SetDiscoveryAddress(addr *Address) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.DiscoveryAddr = addr
}

// SetOperationalAddress sets the operational address (from Relocate).
func (p *Peer) SetOperationalAddress(addr *Address) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.OperationalAddr = addr
}

// AddSharedZone adds a zone that we share with this peer.
func (p *Peer) AddSharedZone(zone, ourRole, peerRole string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.SharedZones[zone] = &ZoneRelation{
		Zone:     zone,
		Role:     ourRole,
		PeerRole: peerRole,
	}
}

// ReplaceSharedZones atomically replaces the peer's shared-zone set under the
// peer lock. Callers must not hold a registry/peer-metadata mutex across this
// call (lock order: registry -> peer-metadata -> transport.Peer).
func (p *Peer) ReplaceSharedZones(zones []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.SharedZones = make(map[string]*ZoneRelation, len(zones))
	for _, zone := range zones {
		p.SharedZones[zone] = &ZoneRelation{Zone: zone}
	}
}

// GetSharedZone returns the zone relation for a specific zone.
func (p *Peer) GetSharedZone(zone string) *ZoneRelation {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.SharedZones[zone]
}

// GetSharedZones returns all shared zone names.
func (p *Peer) GetSharedZones() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	zones := make([]string, 0, len(p.SharedZones))
	for zone := range p.SharedZones {
		zones = append(zones, zone)
	}
	return zones
}

// RecordBeatSent records that a beat was sent.
func (p *Peer) RecordBeatSent() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastBeatSent = time.Now()
	p.BeatSequence++
}

// RecordMechanismBeatSent records a successfully-sent beat on the named
// mechanism ("API"/"DNS"): it bumps the per-mechanism BeatSequence and
// LastBeatSent and the top-level aggregate, and counts the send in Stats.
// Called by the transport's own Beat() success path so BeatSequence/Stats
// are maintained transport-internally (no MP write-back required).
func (p *Peer) RecordMechanismBeatSent(name string) {
	now := time.Now()
	p.mu.Lock()
	if p.Mechanisms == nil {
		p.Mechanisms = make(map[string]*MechanismState)
	}
	m, ok := p.Mechanisms[name]
	if !ok || m == nil {
		m = &MechanismState{}
		p.Mechanisms[name] = m
	}
	m.LastBeatSent = now
	m.BeatSequence++
	p.LastBeatSent = now
	p.BeatSequence++
	p.mu.Unlock()
	p.Stats.RecordMessageSent("beat")
}

// RecordBeatReceived records that a beat was received.
func (p *Peer) RecordBeatReceived() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastBeatReceived = time.Now()
	p.ConsecutiveFails = 0
}

// RecordFailure records a communication failure.
func (p *Peer) RecordFailure() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ConsecutiveFails++
}

// IsHealthy returns true if the peer is in a healthy state.
func (p *Peer) IsHealthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.State == PeerStateOperational || p.State == PeerStateDegraded
}

// PeerRegistry manages all known peers.
type PeerRegistry struct {
	mu    sync.RWMutex
	peers map[string]*Peer
}

// NewPeerRegistry creates a new PeerRegistry.
func NewPeerRegistry() *PeerRegistry {
	return &PeerRegistry{
		peers: make(map[string]*Peer),
	}
}

// Get retrieves a peer by ID.
func (r *PeerRegistry) Get(id string) (*Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	peer, ok := r.peers[id]
	return peer, ok
}

// GetOrCreate retrieves a peer by ID, creating it if it doesn't exist.
func (r *PeerRegistry) GetOrCreate(id string) *Peer {
	r.mu.Lock()
	defer r.mu.Unlock()

	if peer, ok := r.peers[id]; ok {
		return peer
	}

	peer := NewPeer(id)
	r.peers[id] = peer
	return peer
}

// Add adds a peer to the registry.
func (r *PeerRegistry) Add(peer *Peer) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.peers[peer.ID]; exists {
		return fmt.Errorf("peer %s already exists", peer.ID)
	}

	r.peers[peer.ID] = peer
	return nil
}

// Remove removes a peer from the registry.
func (r *PeerRegistry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.peers, id)
}

// All returns all peers in the registry.
func (r *PeerRegistry) All() []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peers := make([]*Peer, 0, len(r.peers))
	for _, peer := range r.peers {
		peers = append(peers, peer)
	}
	return peers
}

// ByState returns all peers in a given state.
func (r *PeerRegistry) ByState(state PeerState) []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var peers []*Peer
	for _, peer := range r.peers {
		if peer.GetState() == state {
			peers = append(peers, peer)
		}
	}
	return peers
}

// ByZone returns all peers that share a given zone.
func (r *PeerRegistry) ByZone(zone string) []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var peers []*Peer
	for _, peer := range r.peers {
		if peer.GetSharedZone(zone) != nil {
			peers = append(peers, peer)
		}
	}
	return peers
}

// Count returns the number of peers in the registry.
func (r *PeerRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.peers)
}

// HealthyCount returns the number of healthy peers.
func (r *PeerRegistry) HealthyCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, peer := range r.peers {
		if peer.IsHealthy() {
			count++
		}
	}
	return count
}
