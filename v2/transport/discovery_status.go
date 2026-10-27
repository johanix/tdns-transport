/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * What discovery found out about a peer's DNS data besides the data itself:
 * the DNSSEC verdict on each RRset it read, when that RRset expires from the
 * resolver's cache, and, when discovery gave nothing to use, why
 * (tdns-mp #260).
 *
 * The verdict is the state of the peer's chain, whatever the local setting
 * did with it: with require-dnssec-validation an answer that is not
 * validated is refused, and without it the answer is used. Either way the
 * peer's status says the chain is not secure, so an operator sees both a
 * peer that is NEEDED because its chain is broken and a peer that is
 * OPERATIONAL on data nobody could validate.
 */
package transport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/cache"
)

// ChainStatus is the DNSSEC verdict on discovery data. The order is the
// order of concern: a worse verdict is a larger value.
type ChainStatus uint8

const (
	ChainUnknown  ChainStatus = iota // nothing read yet, or no verdict given
	ChainSecure                      // validated
	ChainInsecure                    // not validated: unsigned, no trust anchor above it, or not judged
	ChainBogus                       // signed, and the signatures do not validate
)

var chainStatusNames = map[ChainStatus]string{
	ChainUnknown:  "unknown",
	ChainSecure:   "secure",
	ChainInsecure: "insecure",
	ChainBogus:    "bogus",
}

func (c ChainStatus) String() string {
	if s, ok := chainStatusNames[c]; ok {
		return s
	}
	return "unknown"
}

// chainOf is the verdict the resolver gave an answer or a denial. Records
// whose verdict is not set were not validated (validation was not attempted
// or ended in an error): insecure. A denial without a verdict says nothing
// about the chain: unknown.
func chainOf(resp *tdns.ImrResponse) ChainStatus {
	if resp == nil {
		return ChainUnknown
	}
	if resp.Validated {
		return ChainSecure
	}
	switch resp.ValidationState {
	case cache.ValidationStateSecure:
		return ChainSecure
	case cache.ValidationStateBogus:
		return ChainBogus
	case 0:
		if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
			return ChainUnknown
		}
		return ChainInsecure
	default: // none, insecure, indeterminate
		return ChainInsecure
	}
}

// DiscoveryFailure says why a discovery lookup gave nothing to use.
type DiscoveryFailure uint8

const (
	FailureNone         DiscoveryFailure = iota // records were found and used
	FailureNotValidated                         // refused: not DNSSEC-validated, and validation is required
	FailureNoRecords                            // the name or the records do not exist, or none is usable
	FailureUnreachable                          // no server for the name answered
	FailureQuery                                // the lookup failed in another way
)

var discoveryFailureNames = map[DiscoveryFailure]string{
	FailureNone:         "",
	FailureNotValidated: "not validated",
	FailureNoRecords:    "no records",
	FailureUnreachable:  "unreachable",
	FailureQuery:        "query failed",
}

func (f DiscoveryFailure) String() string { return discoveryFailureNames[f] }

// rank orders the failures by how much they tell the operator: a refusal
// for want of validation hides served, signed records and is the one most
// easily mistaken for something else, so it wins; "no records" is what
// every other failure would otherwise look like, so it loses.
func (f DiscoveryFailure) rank() int {
	switch f {
	case FailureNotValidated:
		return 4
	case FailureUnreachable:
		return 3
	case FailureQuery:
		return 2
	case FailureNoRecords:
		return 1
	}
	return 0
}

// DiscoveryLookup is one RRset that discovery read for a peer.
type DiscoveryLookup struct {
	Mechanism string           // "API" or "DNS": the mechanism the RRset is for
	Type      string           // URI, SVCB, TLSA, JWK, KEY
	Owner     string           // the name asked for
	Chain     ChainStatus      // the verdict on the answer or the denial; unknown when the lookup failed
	Expires   time.Time        // when the resolver's cache stops serving it; zero when not known
	Failure   DiscoveryFailure // FailureNone when records were found and used
	Detail    string           // the failure in words, or how a verdict that is not secure was taken
}

// String is the lookup as an operator reads it:
// "URI at _dns._tcp.agent.example.: answer insecure, DNSSEC validation required".
func (l DiscoveryLookup) String() string {
	s := l.Type + " at " + l.Owner
	if l.Detail != "" {
		s += ": " + l.Detail
	}
	return s
}

// DiscoveryError is a discovery that gave nothing to use, and why: the
// lookup behind the failure.
type DiscoveryError struct {
	Identity string
	Lookup   DiscoveryLookup
}

func (e *DiscoveryError) Error() string {
	return fmt.Sprintf("no contact endpoints found for %s: %s", e.Identity, e.Lookup)
}

// Failure is the kind of failure, for a caller that has only the error.
func (e *DiscoveryError) Failure() DiscoveryFailure { return e.Lookup.Failure }

// lookupError is a lookup that gave nothing to use; the lookup says why.
type lookupError struct {
	lookup DiscoveryLookup
}

func (e *lookupError) Error() string { return e.lookup.String() }

// lookupOf returns the lookup behind err, when err is a lookup's.
func lookupOf(err error) (DiscoveryLookup, bool) {
	var le *lookupError
	if errors.As(err, &le) {
		return le.lookup, true
	}
	return DiscoveryLookup{}, false
}

// failureOf classifies a lookup that failed: no server answered, or
// something else went wrong. The resolver has no sentinel for the first, so
// its messages are read: "Failed to resolve query ... using any nameserver
// address" (no nameserver address worked) and "no Answers found from any auth
// server" (none answered), and a lookup that ran out of time.
func failureOf(err error, msg string) DiscoveryFailure {
	if errors.Is(err, context.DeadlineExceeded) {
		return FailureUnreachable
	}
	text := msg
	if err != nil {
		text = err.Error() + " " + msg
	}
	for _, s := range []string{"using any nameserver address", "from any auth server", "no auth-server attempts", "i/o timeout", "deadline exceeded"} {
		if strings.Contains(text, s) {
			return FailureUnreachable
		}
	}
	return FailureQuery
}

// verdictDetail is the Detail of a lookup whose answer or denial was not
// validated: how it was taken.
func verdictDetail(what string, chain ChainStatus, required bool) string {
	if required {
		return fmt.Sprintf("%s %s, DNSSEC validation required", what, chain)
	}
	return fmt.Sprintf("%s %s, accepted as DNSSEC validation is not enforced", what, chain)
}

// DiscoveryStatus is what the last discovery of a peer found out about its
// DNS data.
type DiscoveryStatus struct {
	At      time.Time         // when discovery last ran; zero: never
	Expires time.Time         // the earliest expiry among Lookups; zero when none is known
	Failure DiscoveryFailure  // why the last discovery gave nothing to use; FailureNone if it did
	Reason  string            // that failure in words
	Lookups []DiscoveryLookup // the RRsets read, the TLSA as the checker last saw it
}

// Chain is the worst verdict on the peer's data.
func (s DiscoveryStatus) Chain() ChainStatus {
	return s.MechanismChain("")
}

// MechanismChain is the worst verdict on the data of one mechanism ("API",
// "DNS"); "" for all of them.
func (s DiscoveryStatus) MechanismChain(mechanism string) ChainStatus {
	worst := ChainUnknown
	for _, l := range s.Lookups {
		if (mechanism == "" || l.Mechanism == mechanism) && l.Chain > worst {
			worst = l.Chain
		}
	}
	return worst
}

// MechanismExpires is when the data of one mechanism ("API", "DNS") expires
// from the cache: the earliest expiry among its lookups. Zero when none is
// known. The peer is looked up again at Expires, the earliest of all.
func (s DiscoveryStatus) MechanismExpires(mechanism string) time.Time {
	var exp time.Time
	for _, l := range s.Lookups {
		if l.Mechanism == mechanism && !l.Expires.IsZero() && (exp.IsZero() || l.Expires.Before(exp)) {
			exp = l.Expires
		}
	}
	return exp
}

// saysNothing reports whether a lookup that failed so says nothing about the
// data it was for: it could not run. A refusal and a denial are answers.
func (f DiscoveryFailure) saysNothing() bool { return f == FailureUnreachable || f == FailureQuery }

// findLookup returns the lookup of the mechanism's RRset of that type.
func findLookup(lookups []DiscoveryLookup, mechanism, typ string) (DiscoveryLookup, bool) {
	for _, l := range lookups {
		if l.Mechanism == mechanism && l.Type == typ {
			return l, true
		}
	}
	return DiscoveryLookup{}, false
}

// MechanismReason says, for one mechanism ("" for all), what an operator
// needs to know about its data: the lookup that failed, the most telling
// failure first, and otherwise the lookup with the worst verdict when that
// is not secure. Empty when there is nothing to say.
func (s DiscoveryStatus) MechanismReason(mechanism string) string {
	var failed, weakest *DiscoveryLookup
	for i := range s.Lookups {
		l := &s.Lookups[i]
		if mechanism != "" && l.Mechanism != mechanism {
			continue
		}
		if l.Failure != FailureNone && (failed == nil || l.Failure.rank() > failed.Failure.rank()) {
			failed = l
		}
		if l.Chain > ChainSecure && (weakest == nil || l.Chain > weakest.Chain) {
			weakest = l
		}
	}
	switch {
	case failed != nil && failed.Failure != FailureNoRecords:
		return failed.String()
	case weakest != nil:
		return weakest.String()
	case failed != nil:
		return failed.String()
	}
	return ""
}

// summarize computes Expires from the lookups.
func (s *DiscoveryStatus) summarize() {
	s.Expires = time.Time{}
	for _, l := range s.Lookups {
		if !l.Expires.IsZero() && (s.Expires.IsZero() || l.Expires.Before(s.Expires)) {
			s.Expires = l.Expires
		}
	}
}

// copy returns s with its own Lookups.
func (s DiscoveryStatus) copy() DiscoveryStatus {
	s.Lookups = append([]DiscoveryLookup(nil), s.Lookups...)
	return s
}

// DiscoveryStatus returns what the last discovery of the peer found out
// about its DNS data. A peer that was never discovered returns the zero
// status.
func (p *Peer) DiscoveryStatus() DiscoveryStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.discovery.copy()
}

// setDiscoveryStatus records what a discovery of the peer found out. A lookup
// that could not run says nothing about the data it was for, which stays in
// use: it keeps the verdict and the expiry of the lookup of that RRset
// before it. When the whole discovery could not run, the lookups it did not
// get to are kept as they were too, so the marks of the data in use stay.
func (p *Peer) setDiscoveryStatus(s DiscoveryStatus) {
	s = s.copy()
	p.mu.Lock()
	defer p.mu.Unlock()
	old := p.discovery.Lookups
	for i := range s.Lookups {
		l := &s.Lookups[i]
		if !l.Failure.saysNothing() {
			continue
		}
		if o, ok := findLookup(old, l.Mechanism, l.Type); ok {
			l.Chain, l.Expires = o.Chain, o.Expires
		}
	}
	if s.Failure.saysNothing() {
		for _, o := range old {
			if _, ok := findLookup(s.Lookups, o.Mechanism, o.Type); !ok {
				s.Lookups = append(s.Lookups, o)
			}
		}
	}
	s.summarize()
	p.discovery = s
}

// noteLookup records a lookup made for the peer outside a discovery (the
// TLSA checker's): it replaces the lookup of the same RRset. A lookup that
// gave nothing to use leaves the time of the next refresh where it was: the
// expiry it carries is that of an answer that is not used, and a later one
// would put off the refresh that a refusal needs. A peer that discovery has
// not read is left as it is.
func (p *Peer) noteLookup(l DiscoveryLookup) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.discovery.At.IsZero() {
		return
	}
	lookups := append([]DiscoveryLookup(nil), p.discovery.Lookups...)
	replaced := false
	for i := range lookups {
		if lookups[i].Mechanism == l.Mechanism && lookups[i].Type == l.Type {
			if l.Failure != FailureNone {
				l.Expires = lookups[i].Expires
			}
			lookups[i] = l
			replaced = true
		}
	}
	if !replaced {
		if l.Failure != FailureNone {
			l.Expires = time.Time{}
		}
		lookups = append(lookups, l)
	}
	p.discovery.Lookups = lookups
	p.discovery.summarize()
}

// demoteMechanism makes the mechanism NEEDED for reason, with its contact
// information partial: what it was used with can be used no longer. The
// address and endpoint it held go, so that no send path selects it
// (SelectTransport, HasMechanism, APIUsable) until discovery finds data
// that validates: its slot, API's endpoint, DNS's display endpoint. The
// addresses the DNS carrier dials (CurrentAddress: the relocated one, then
// the discovered one) go with DNS, and with API only each where it is
// API's address: registration's fallback for a peer that offers no DNS, or
// a relocate to it. A relocate elsewhere is the peer's own, and a peer
// known from config or a hello keeps the address it was given. The other
// mechanism's are kept. It returns the state it had and whether it was past NEEDED; a
// mechanism that was not keeps its state and gets the reason. When no
// mechanism is left past NEEDED, the peer's own state follows, from any
// state: EffectiveState falls back to it then, and an ERROR left from a
// failed discovery before the peer was found would be shown in its place.
func (p *Peer) demoteMechanism(name, reason string) (PeerState, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Mechanisms == nil {
		p.Mechanisms = make(map[string]*MechanismState)
	}
	m := p.Mechanisms[name]
	if m == nil {
		m = &MechanismState{State: PeerStateNeeded, StateChanged: time.Now()}
		p.Mechanisms[name] = m
	}
	m.ContactInfo = "partial"
	dropped := m.Address
	m.Address = nil
	switch name {
	case MechanismAPI:
		p.APIEndpoint = ""
		// DiscoveryAddr holds the API's address only by registration's
		// fallback for a peer that offers no DNS, and goes with it. A
		// relocate is the peer's own word on where the DNS carrier dials,
		// and stays unless it is that address too. An address from DNS
		// discovery, from config or from a hello is the DNS carrier's own,
		// and stays.
		if dropped != nil {
			if p.DiscoveryAddr != nil && *p.DiscoveryAddr == *dropped {
				p.DiscoveryAddr = nil
			}
			if p.OperationalAddr != nil && *p.OperationalAddr == *dropped {
				p.OperationalAddr = nil
			}
		}
	case MechanismDNS:
		p.DNSEndpoint = ""
		p.DiscoveryAddr, p.OperationalAddr = nil, nil
	}
	was := m.State
	pastNeeded := func(s PeerState) bool { return s > PeerStateNeeded && s != PeerStateError }
	demoted := pastNeeded(was)
	if demoted {
		m.State, m.StateChanged = PeerStateNeeded, time.Now()
	}
	m.StateReason = reason
	for _, other := range p.Mechanisms {
		if other != nil && pastNeeded(other.State) {
			return was, demoted
		}
	}
	if p.State != PeerStateNeeded {
		p.State, p.StateReason, p.StateChanged = PeerStateNeeded, reason, time.Now()
	}
	return was, demoted
}
