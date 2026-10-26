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
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
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
//
// Discovery, the receive paths and the senders touch one peer from
// different goroutines. A field that is written after the peer is shared
// is read and written under mu: through the accessors (SetAPIEndpoint,
// GetPreferredTransport, ...) from outside this package.
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

	// Capabilities
	Capabilities []string // What the peer supports

	// Communication state, single-state view: kept for display and for
	// peers that predate per-mechanism state. The send gates read
	// Mechanisms, not these. SetMechanismLastHelloRecv and
	// SetMechanismLastBeatRecv stamp the received times here too.
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

	// Per-mechanism state. Keys: "API", "DNS".
	// Per-mechanism state is what discovery and the hello/beat paths
	// write and what the send gates read (D2.5); the single-state fields
	// above stay for display and for peers that predate per-mechanism
	// state.
	Mechanisms map[string]*MechanismState

	// Per-mechanism cryptographic material discovered for this peer
	// (Phase 2.5: moved from tdns-mp's transitional agentMeta sidecar so
	// transport.Peer owns ALL per-peer connection+crypto state). Keys:
	// "API", "DNS". Access ONLY via the MechanismTLSA/JWK/KeyRR accessors
	// (they hold p.mu); lazily allocated.
	mechanismCrypto map[string]*mechanismCrypto

	// discovery is what the last discovery found out about the peer's DNS
	// data: the DNSSEC verdicts, when the data expires, and why discovery
	// failed (discovery_status.go). Through DiscoveryStatus.
	discovery DiscoveryStatus
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

// mechanismCrypto is the per-mechanism cryptographic material discovered for
// a peer: the TLSA record backing API mTLS verification, and the JWK / legacy
// KEY material backing DNS payload crypto. Phase 2.5: moved here from
// tdns-mp's transitional agentMeta sidecar (the addendum's deferred "E1
// crypto move") — transport.Peer is the sole per-peer state owner. The RR
// pointers are treated as immutable once set (discovery replaces, never
// mutates in place).
type mechanismCrypto struct {
	KeyRR        *dns.KEY // SIG(0) KEY record (DNS legacy fallback)
	TLSA         TLSASet  // TLSA RRset (API mTLS verification)
	tlsaSeq      uint64   // the lookup whose answer TLSA is (nextTLSALookup)
	JWKData      string   // JWK JSON (DNS payload crypto)
	KeyAlgorithm string   // JWK algorithm name
}

// TLSASet is a peer's TLSA RRset for one mechanism: the name it lives at,
// the usable records last seen there (usage 3, DANE-EE; usableTLSA), and
// whether that answer was DNSSEC-validated. A certificate passes when it
// matches any of the records: during a rollover the old and the new are
// published together.
type TLSASet struct {
	Owner     string      // _<port>._tcp.<host>
	Records   []*dns.TLSA // empty: none known, or the name says there is none
	Validated bool
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

// NewPeer creates a new Peer with the given ID.
func NewPeer(id string) *Peer {
	return &Peer{
		ID:           id,
		State:        PeerStateNeeded,
		StateChanged: time.Now(),
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

	st := PeerStateOperational
	if sinceS > 10*localInterval {
		st = PeerStateInterrupted
	} else if sinceS > 2*localInterval {
		st = PeerStateDegraded
	}
	// A failed outbound send on this mechanism (RecordMechanismFailure)
	// makes the cell at least DEGRADED even when beats still succeed:
	// a confirmation that always falls back is a one-way pair the
	// gossip matrix must show (tdns-mp #236). Interrupted from silence
	// stays Interrupted.
	if m.ConsecutiveFails > 0 && st == PeerStateOperational {
		return PeerStateDegraded
	}
	return st
}

func timeSinceOrInf(t time.Time) time.Duration {
	if t.IsZero() {
		return 1<<62 - 1 // effectively infinite
	}
	return time.Since(t)
}

// SetMechanismAddress records the resolved address of one mechanism
// ("API", "DNS"). Discovery writes it next to DiscoveryAddr: DiscoveryAddr
// is the single slot the DNS carrier dials (CurrentAddress), while the
// per-mechanism slot is what HasMechanism and PreferredMechanism read, so
// a mechanism whose address was discovered but never stored here would
// look absent. The HTTPS mechanism dials the API slot (MechanismAddress).
func (p *Peer) SetMechanismAddress(name string, addr *Address) {
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
	m.Address = addr
}

// MechanismAddress is the resolved address of one mechanism ("API",
// "DNS") as SetMechanismAddress recorded it, or nil.
func (p *Peer) MechanismAddress(name string) *Address {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if m := p.Mechanisms[name]; m != nil {
		return m.Address
	}
	return nil
}

// SetMechanismState updates the per-mechanism state. Creates the
// MechanismState entry on first call for an unknown mechanism. The
// peer-level State field is not touched here; a caller that wants the
// display-level State moved as well calls SetState.
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

// ensureMechanismCryptoLocked returns the crypto entry for the named
// mechanism, allocating map + entry lazily. Caller MUST hold p.mu.
func (p *Peer) ensureMechanismCryptoLocked(name string) *mechanismCrypto {
	if p.mechanismCrypto == nil {
		p.mechanismCrypto = make(map[string]*mechanismCrypto)
	}
	c, ok := p.mechanismCrypto[name]
	if !ok || c == nil {
		c = &mechanismCrypto{}
		p.mechanismCrypto[name] = c
	}
	return c
}

// SetMechanismTLSA records the TLSA RRset for the named mechanism (replace
// semantics: the set given is the set held, an empty one included). It
// counts as the newest answer.
func (p *Peer) SetMechanismTLSA(name string, set TLSASet) {
	p.storeMechanismTLSA(name, set, nextTLSALookup(), false)
}

// tlsaLookups numbers TLSA lookups in the order they start, the checker's
// and discovery's alike: of two answers for one peer, the later lookup's is
// kept, whichever is stored last.
var tlsaLookups atomic.Uint64

func nextTLSALookup() uint64 { return tlsaLookups.Add(1) }

// storeMechanismTLSA stores set, the answer of lookup seq. For the name
// held, the later lookup's answer is kept. A set for another name is a move:
// discovery's (sameOwner false) wins whatever the numbers, as the endpoint
// it moved with does; a checker's answer for another name (sameOwner) is
// never stored. It returns the set held before and whether set was stored.
func (p *Peer) storeMechanismTLSA(name string, set TLSASet, seq uint64, sameOwner bool) (TLSASet, bool) {
	set.Records = append([]*dns.TLSA(nil), set.Records...)
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.ensureMechanismCryptoLocked(name)
	prev := c.TLSA
	moved := prev.Owner != set.Owner
	if (moved && sameOwner) || (!moved && c.tlsaSeq > seq) {
		return prev, false
	}
	c.TLSA, c.tlsaSeq = set, seq
	return prev, true
}

// SetMechanismJWK records the discovered JWK material for the named
// mechanism. Callers gate on non-empty JWK data (re-discovery must not wipe
// a previously discovered JWK with an empty result — the same merge
// semantics the MP sidecar had).
func (p *Peer) SetMechanismJWK(name, jwkData, keyAlgorithm string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.ensureMechanismCryptoLocked(name)
	c.JWKData = jwkData
	c.KeyAlgorithm = keyAlgorithm
}

// SetMechanismKeyRR records the discovered legacy SIG(0) KEY record for the
// named mechanism (replace semantics, like SetMechanismTLSA).
func (p *Peer) SetMechanismKeyRR(name string, key *dns.KEY) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ensureMechanismCryptoLocked(name).KeyRR = key
}

// MechanismTLSA returns the mechanism's TLSA RRset, as last seen; the zero
// TLSASet when none was.
func (p *Peer) MechanismTLSA(name string) TLSASet {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if c := p.mechanismCrypto[name]; c != nil {
		set := c.TLSA
		set.Records = append([]*dns.TLSA(nil), set.Records...)
		return set
	}
	return TLSASet{}
}

// APIUsable reports whether HTTPS to the peer can be attempted: it has an
// API endpoint, and a TLSA to check its certificate against.
func (p *Peer) APIUsable() bool {
	return p.GetAPIEndpoint() != "" && p.HasMechanismTLSA("API")
}

// mechanismNeedsDiscovery reports whether one of the peer's mechanisms was
// found in part and is still NEEDED: an API endpoint without an address or
// without a usable TLSA, say. A mechanism the peer never offered is NEEDED
// too, from NewPeer on, and does not count.
func (p *Peer) mechanismNeedsDiscovery() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, m := range p.Mechanisms {
		if m != nil && m.ContactInfo == "partial" && m.State <= PeerStateDiscovering {
			return true
		}
	}
	return false
}

// HasMechanismTLSA reports whether the mechanism has a usable TLSA record:
// without one, HTTPS to the peer is not attempted.
func (p *Peer) HasMechanismTLSA(name string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	c := p.mechanismCrypto[name]
	return c != nil && len(c.TLSA.Records) > 0
}

// MechanismJWK returns the mechanism's discovered JWK data + algorithm
// (empty strings if none).
func (p *Peer) MechanismJWK(name string) (jwkData, keyAlgorithm string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if c := p.mechanismCrypto[name]; c != nil {
		return c.JWKData, c.KeyAlgorithm
	}
	return "", ""
}

// MechanismKeyRR returns the mechanism's discovered legacy KEY record, or nil.
func (p *Peer) MechanismKeyRR(name string) *dns.KEY {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if c := p.mechanismCrypto[name]; c != nil {
		return c.KeyRR
	}
	return nil
}

// SetMechanismLastHelloRecv records the time a Hello was last received
// on the named mechanism, and as the peer's LastHelloReceived. Creates
// the MechanismState entry on first call. Acquires p.mu for the duration
// of the write, so this is the safe replacement for direct map indexing
// of p.Mechanisms[name].
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
	p.LastHelloReceived = t
}

// SetMechanismLastBeatRecv records the time a Beat (or Ping treated as
// liveness) was last received on the named mechanism, and as the peer's
// LastBeatReceived. Same locking contract as SetMechanismLastHelloRecv.
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
	p.LastBeatReceived = t
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
// recordMechanismBeatSent on the transport's own Beat() success path.
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

// MechanismRawState returns the named mechanism's stored state WITHOUT
// liveness decay, plus a bool that is false if the mechanism is not
// present. Use this for anti-regression guards (e.g. "promote to KNOWN
// only if currently below KNOWN") where the decayed view would be wrong.
func (p *Peer) MechanismRawState(name string) (PeerState, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.Mechanisms == nil {
		return PeerState(0), false
	}
	m, ok := p.Mechanisms[name]
	if !ok || m == nil {
		return PeerState(0), false
	}
	return m.State, true
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

// SetState updates the peer's state with a reason.
func (p *Peer) SetState(state PeerState, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.State = state
	p.StateReason = reason
	p.StateChanged = time.Now()
}

// recordMessageSent records statistics for an outgoing message.
func (ms *MessageStats) recordMessageSent(msgType string) {
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

// recordMessageReceived records statistics for an incoming message.
func (ms *MessageStats) recordMessageReceived(msgType string) {
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

// SetLivenessInterval sets OUR local beat interval (seconds) for this peer:
// how often we beat it. The decay-on-read in EffectiveState() keys its
// DEGRADED/INTERRUPTED thresholds on this, so it MUST match the cadence we
// actually beat this peer at — otherwise a healthy peer beaten on a slow
// schedule (e.g. infra peers at 600s) decays to INTERRUPTED under the 30s
// default. A zero value leaves the 30s default in place.
func (p *Peer) SetLivenessInterval(seconds uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LivenessInterval = seconds
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

// SetAPIEndpoint records the URL of the peer's API transport.
func (p *Peer) SetAPIEndpoint(uri string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.APIEndpoint = uri
}

// GetAPIEndpoint returns the URL of the peer's API transport, "" when it
// has none.
func (p *Peer) GetAPIEndpoint() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.APIEndpoint
}

// SetDNSEndpoint records the dns:// URL of the peer's DNS transport.
func (p *Peer) SetDNSEndpoint(uri string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.DNSEndpoint = uri
}

// GetDNSEndpoint returns the dns:// URL of the peer's DNS transport, ""
// when it has none.
func (p *Peer) GetDNSEndpoint() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.DNSEndpoint
}

// SetPreferredTransport records the transport ("API" or "DNS") to try
// first for this peer.
func (p *Peer) SetPreferredTransport(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.PreferredTransport = name
}

// GetPreferredTransport returns the transport ("API" or "DNS") to try
// first for this peer, "" when none is set.
func (p *Peer) GetPreferredTransport() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.PreferredTransport
}

// setPreferredTransportIfUnset sets the preferred transport when none is
// set yet, in one step under p.mu.
func (p *Peer) setPreferredTransportIfUnset(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.PreferredTransport == "" {
		p.PreferredTransport = name
	}
}

// SetLastBeatReceived records the time of an inbound message from the
// peer that names no mechanism. A message on a known mechanism goes to
// SetMechanismLastBeatRecv, which stamps this time as well.
func (p *Peer) SetLastBeatReceived(t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastBeatReceived = t
}

// GetLastBeatReceived returns the time of the last inbound beat or other
// message that shows the peer reaches us.
func (p *Peer) GetLastBeatReceived() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.LastBeatReceived
}

// recordBeatSent records that a beat was sent.
func (p *Peer) recordBeatSent() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastBeatSent = time.Now()
	p.BeatSequence++
}

// recordMechanismBeatSent records a successfully-sent beat on the named
// mechanism ("API"/"DNS"): it bumps the per-mechanism BeatSequence and
// LastBeatSent and the top-level aggregate, and counts the send in Stats.
// Called by the transport's own Beat() success path so BeatSequence/Stats
// are maintained transport-internally (no MP write-back required).
func (p *Peer) recordMechanismBeatSent(name string) {
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
	p.Stats.recordMessageSent("beat")
}

// recordBeatReceived records that a beat was received.
func (p *Peer) recordBeatReceived() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastBeatReceived = time.Now()
	p.ConsecutiveFails = 0
}

// recordFailure records a communication failure.
func (p *Peer) recordFailure() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ConsecutiveFails++
}

// RecordMechanismFailure counts a failed outbound send on the named
// mechanism. ConsecutiveFails rises; MechanismEffectiveState then reads
// at least DEGRADED while fails remain, so a one-way pair shows in the
// gossip matrix. A recipient's Answered refusal is not a send failure
// (tdns-mp #236, tdns-transport #36).
func (p *Peer) RecordMechanismFailure(name string) {
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
	m.ConsecutiveFails++
}

// RecordMechanismSuccess clears the consecutive-failure count on the
// named mechanism after a successful send on it.
func (p *Peer) RecordMechanismSuccess(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if m := p.Mechanisms[name]; m != nil {
		m.ConsecutiveFails = 0
	}
}

// MechanismConsecutiveFails is the named mechanism's consecutive outbound
// send failures, or 0 when the mechanism is absent.
func (p *Peer) MechanismConsecutiveFails(name string) int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if m := p.Mechanisms[name]; m != nil {
		return m.ConsecutiveFails
	}
	return 0
}

// isHealthy returns true if the peer is in a healthy state.
func (p *Peer) isHealthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.State == PeerStateOperational || p.State == PeerStateDegraded
}

// PeerRegistry manages all known peers.
type PeerRegistry struct {
	mu    sync.RWMutex
	peers map[string]*Peer

	// OnRemove, when set, is called with each peer Remove takes out, after
	// the registry's lock is released (APITransport.ForgetPeer drops the
	// peer's HTTPS client).
	OnRemove func(*Peer)
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
	peer := r.peers[id]
	delete(r.peers, id)
	onRemove := r.OnRemove
	r.mu.Unlock()
	if peer != nil && onRemove != nil {
		onRemove(peer)
	}
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

// Count returns the number of peers in the registry.
func (r *PeerRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.peers)
}

// healthyCount returns the number of healthy peers.
func (r *PeerRegistry) healthyCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, peer := range r.peers {
		if peer.isHealthy() {
			count++
		}
	}
	return count
}
