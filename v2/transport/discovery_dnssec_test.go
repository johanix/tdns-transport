/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Discovery and the DNSSEC verdict on what it reads (tdns-mp #260), through a
 * real resolver whose cache holds the peer's records: the verdict and the
 * expiry of each RRset reach the peer's status, a refusal for want of
 * validation is told apart from missing records, and a peer whose data stops
 * validating goes back to NEEDED.
 */
package transport

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const dnssecPeer = "agent.example."

// cachedPeerImr is a resolver whose cache holds the API records of
// dnssecPeer, each with the verdict state and the TTL ttl: the URI, the SVCB
// with an address hint, and a usable TLSA. Nothing is asked of the network:
// every lookup is a cache hit.
func cachedPeerImr(t *testing.T, require bool, state cache.ValidationState, ttl uint32) *Imr {
	t.Helper()
	imr := &tdns.Imr{
		Cache:                   cache.NewRRsetCache(log.New(os.Stderr, "test ", log.LstdFlags), false, false),
		RequireDnssecValidation: require,
	}
	for _, s := range []string{
		"_https._tcp." + dnssecPeer + " IN URI 10 1 \"https://api.agent.example.:8443/api\"",
		"api." + dnssecPeer + " IN SVCB 1 . ipv4hint=192.0.2.10",
		"_8443._tcp.api." + dnssecPeer + " IN TLSA 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	} {
		cacheAnswer(t, imr, s, state, ttl)
	}
	return &Imr{Imr: imr}
}

// cacheAnswer stores the record s in imr's cache as an answer with the
// verdict state and the TTL ttl, replacing what is there.
func cacheAnswer(t *testing.T, imr *tdns.Imr, s string, state cache.ValidationState, ttl uint32) {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	rr.Header().Ttl = ttl
	h := rr.Header()
	imr.Cache.Set(h.Name, h.Rrtype, &cache.CachedRRset{
		Name: h.Name, RRtype: h.Rrtype,
		RRset:   &core.RRset{Name: h.Name, Class: dns.ClassINET, RRtype: h.Rrtype, RRs: []dns.RR{rr}},
		Context: cache.ContextAnswer, State: state, Transport: core.TransportDo53,
	})
}

// cacheDenial stores an NXDOMAIN for <name, qtype> with the verdict state.
func cacheDenial(t *testing.T, imr *tdns.Imr, name string, qtype uint16, state cache.ValidationState) {
	t.Helper()
	soa, err := dns.NewRR("example. 300 IN SOA ns.example. hostmaster.example. 1 3600 600 86400 300")
	if err != nil {
		t.Fatal(err)
	}
	imr.Cache.Set(name, qtype, &cache.CachedRRset{
		Name: name, RRtype: qtype, Rcode: uint8(dns.RcodeNameError),
		RRset:   &core.RRset{Name: "example.", Class: dns.ClassINET, RRtype: dns.TypeSOA, RRs: []dns.RR{soa}},
		Context: cache.ContextNXDOMAIN, State: state, Transport: core.TransportDo53,
	})
}

// apiManager is a manager that discovers over the API mechanism only, with
// imr, and already knows dnssecPeer (as the application's DiscoverPeer
// makes it known before discovery runs).
func apiManager(imr *Imr) (*TransportManager, *Peer) {
	tm := &TransportManager{PeerRegistry: NewPeerRegistry(), GetImr: func() *Imr { return imr }}
	tm.SetSupportedMechanisms([]string{"api"})
	return tm, tm.PeerRegistry.GetOrCreate(dnssecPeer)
}

func discoverWithin(t *testing.T, tm *TransportManager) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return tm.DiscoverAndRegisterPeer(ctx, dnssecPeer)
}

// A secure chain: the peer is usable, its status says secure, and it expires
// when the shortest-lived RRset does.
func TestDiscoverySecureChainReachesThePeer(t *testing.T) {
	imr := cachedPeerImr(t, true, cache.ValidationStateSecure, 600)
	cacheAnswer(t, imr.Imr, "api."+dnssecPeer+" IN SVCB 1 . ipv4hint=192.0.2.10", cache.ValidationStateSecure, 120)
	tm, peer := apiManager(imr)
	if err := discoverWithin(t, tm); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	if st, _ := peer.MechanismRawState("API"); st != PeerStateKnown {
		t.Fatalf("API state %v, want KNOWN", st)
	}
	s := peer.DiscoveryStatus()
	if s.At.IsZero() || s.Failure != FailureNone {
		t.Fatalf("status %+v: want a successful discovery", s)
	}
	if c := s.MechanismChain("API"); c != ChainSecure {
		t.Errorf("API chain %v, want secure", c)
	}
	if r := s.MechanismReason("API"); r != "" {
		t.Errorf("reason %q, want none for a secure chain", r)
	}
	if len(s.Lookups) != 3 {
		t.Errorf("%d lookups, want 3 (URI, SVCB, TLSA): %+v", len(s.Lookups), s.Lookups)
	}
	if d := time.Until(s.Expires); d < 110*time.Second || d > 125*time.Second {
		t.Errorf("expires in %v, want about 120s (the SVCB's TTL)", d)
	}
}

// The case of #260: validation required, records served but not validated.
// The peer stays NEEDED, and its status and the error say why, not that the
// records are missing.
func TestDiscoveryRefusedForWantOfValidationSaysSo(t *testing.T) {
	imr := cachedPeerImr(t, true, cache.ValidationStateInsecure, 600)
	tm, peer := apiManager(imr)
	err := discoverWithin(t, tm)
	var de *DiscoveryError
	if !errors.As(err, &de) {
		t.Fatalf("err %v: want a *DiscoveryError", err)
	}
	if de.Failure() != FailureNotValidated {
		t.Errorf("failure %v, want %v", de.Failure(), FailureNotValidated)
	}
	const want = "URI at _https._tcp.agent.example.: answer insecure, DNSSEC validation required"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not say %q", err, want)
	}
	if st, _ := peer.MechanismRawState("API"); st != PeerStateNeeded {
		t.Errorf("API state %v, want NEEDED", st)
	}
	s := peer.DiscoveryStatus()
	if s.Failure != FailureNotValidated || s.MechanismChain("API") != ChainInsecure {
		t.Errorf("status failure %v chain %v, want not validated / insecure", s.Failure, s.MechanismChain("API"))
	}
	if r := s.MechanismReason("API"); r != want {
		t.Errorf("reason %q, want %q", r, want)
	}
}

// Validation off: the same records are used, and the status says the chain
// is not secure, and that they were taken anyway.
func TestDiscoveryWithValidationOffMarksTheChain(t *testing.T) {
	for _, tc := range []struct {
		state cache.ValidationState
		want  ChainStatus
	}{
		{cache.ValidationStateInsecure, ChainInsecure},
		{cache.ValidationStateIndeterminate, ChainInsecure},
		{cache.ValidationStateBogus, ChainBogus},
	} {
		t.Run(tc.want.String()+"/"+cache.ValidationStateToString[tc.state], func(t *testing.T) {
			imr := cachedPeerImr(t, false, tc.state, 600)
			tm, peer := apiManager(imr)
			if err := discoverWithin(t, tm); err != nil {
				t.Fatalf("discovery: %v", err)
			}
			if st, _ := peer.MechanismRawState("API"); st != PeerStateKnown {
				t.Fatalf("API state %v, want KNOWN", st)
			}
			s := peer.DiscoveryStatus()
			if c := s.MechanismChain("API"); c != tc.want {
				t.Errorf("API chain %v, want %v", c, tc.want)
			}
			if r := s.MechanismReason("API"); !strings.Contains(r, "accepted as DNSSEC validation is off") {
				t.Errorf("reason %q: want it to say the data was taken with validation off", r)
			}
		})
	}
}

// A denial that was not validated is no proof the records are missing: with
// validation required it is refused, and says so.
func TestDiscoveryRefusesADenialThatIsNotValidated(t *testing.T) {
	imr := cachedPeerImr(t, true, cache.ValidationStateSecure, 600)
	cacheDenial(t, imr.Imr, "_https._tcp."+dnssecPeer, dns.TypeURI, cache.ValidationStateInsecure)
	tm, _ := apiManager(imr)
	err := discoverWithin(t, tm)
	var de *DiscoveryError
	if !errors.As(err, &de) || de.Failure() != FailureNotValidated {
		t.Fatalf("err %v: want a refusal for want of validation", err)
	}
	if !strings.Contains(err.Error(), "denial insecure, DNSSEC validation required") {
		t.Errorf("error %q does not name the denial", err)
	}

	// A validated denial is a plain "no records".
	cacheDenial(t, imr.Imr, "_https._tcp."+dnssecPeer, dns.TypeURI, cache.ValidationStateSecure)
	err = discoverWithin(t, tm)
	if !errors.As(err, &de) || de.Failure() != FailureNoRecords {
		t.Fatalf("err %v: want no records", err)
	}
}

// A peer in use whose data no longer validates, once it is looked up again,
// goes back to NEEDED, and the peer with it.
func TestAPeerWhoseChainBreaksGoesBackToNeeded(t *testing.T) {
	imr := cachedPeerImr(t, true, cache.ValidationStateSecure, 600)
	tm, peer := apiManager(imr)
	if err := discoverWithin(t, tm); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	peer.SetMechanismState("API", PeerStateOperational, "hello")
	peer.SetState(PeerStateOperational, "hello")

	// The chain breaks: the same records, no longer validated.
	cacheAnswer(t, imr.Imr, "api."+dnssecPeer+" IN SVCB 1 . ipv4hint=192.0.2.10", cache.ValidationStateInsecure, 600)
	if err := discoverWithin(t, tm); err != nil {
		t.Fatalf("second discovery: %v (the URI still validates, so it registers)", err)
	}
	if st, _ := peer.MechanismRawState("API"); st != PeerStateNeeded {
		t.Errorf("API state %v, want NEEDED", st)
	}
	if st := peer.EffectiveState(); st != PeerStateNeeded {
		t.Errorf("effective state %v, want NEEDED", st)
	}
	if ci := peer.MechanismContactInfo("API"); ci != "partial" {
		t.Errorf("contact info %q, want partial", ci)
	}
	if r := peer.DiscoveryStatus().MechanismReason("API"); !strings.Contains(r, "SVCB at api.agent.example.: answer insecure") {
		t.Errorf("reason %q: want the SVCB named", r)
	}

	// The URI too: nothing registers, and the peer stays NEEDED.
	cacheAnswer(t, imr.Imr, "_https._tcp."+dnssecPeer+" IN URI 10 1 \"https://api.agent.example.:8443/api\"", cache.ValidationStateBogus, 600)
	if err := discoverWithin(t, tm); err == nil {
		t.Fatal("discovery with a bogus URI: no error")
	}
	if c := peer.DiscoveryStatus().MechanismChain("API"); c != ChainBogus {
		t.Errorf("chain %v, want bogus", c)
	}
}

// The refresh loop looks a peer up again once its data has expired, and
// only then.
func TestRefreshLooksAPeerUpAgainWhenItsDataExpires(t *testing.T) {
	imr := cachedPeerImr(t, true, cache.ValidationStateSecure, 600)
	tm, peer := apiManager(imr)
	if err := discoverWithin(t, tm); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	ctx := context.Background()
	if n := tm.refreshExpiredDiscoveries(ctx, time.Now()); n != 0 {
		t.Fatalf("refreshed %d peers right after discovery, want 0", n)
	}
	first := peer.DiscoveryStatus()
	if n := tm.refreshExpiredDiscoveries(ctx, first.Expires.Add(time.Second)); n != 1 {
		t.Fatalf("refreshed %d peers after expiry, want 1", n)
	}
	if again := peer.DiscoveryStatus(); !again.At.After(first.At) {
		t.Errorf("status At %v, want later than %v", again.At, first.At)
	}

	// A peer never discovered is not the loop's.
	tm.PeerRegistry.GetOrCreate("other.example.")
	if n := tm.refreshExpiredDiscoveries(ctx, time.Now().Add(48*time.Hour)); n != 1 {
		t.Errorf("refreshed %d peers, want only the discovered one", n)
	}
}

func TestDiscoveryStatusDue(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name string
		s    DiscoveryStatus
		want bool
	}{
		{"never discovered", DiscoveryStatus{}, false},
		{"just discovered, expired", DiscoveryStatus{At: now.Add(-10 * time.Second), Expires: now.Add(-time.Second)}, false},
		{"expired", DiscoveryStatus{At: now.Add(-10 * time.Minute), Expires: now.Add(-time.Second)}, true},
		{"not expired", DiscoveryStatus{At: now.Add(-10 * time.Minute), Expires: now.Add(time.Minute)}, false},
		{"failed", DiscoveryStatus{At: now.Add(-2 * time.Minute), Expires: now.Add(time.Hour), Failure: FailureUnreachable}, true},
		{"expiry unknown, recent", DiscoveryStatus{At: now.Add(-10 * time.Minute)}, false},
		{"expiry unknown, old", DiscoveryStatus{At: now.Add(-2 * time.Hour)}, true},
	} {
		if got := tc.s.due(now); got != tc.want {
			t.Errorf("%s: due %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestChainOf(t *testing.T) {
	rrs := &core.RRset{RRs: []dns.RR{&dns.A{}}}
	for _, tc := range []struct {
		name string
		resp *tdns.ImrResponse
		want ChainStatus
	}{
		{"nil", nil, ChainUnknown},
		{"validated", &tdns.ImrResponse{Validated: true, RRset: rrs}, ChainSecure},
		{"secure", &tdns.ImrResponse{ValidationState: cache.ValidationStateSecure, RRset: rrs}, ChainSecure},
		{"insecure", &tdns.ImrResponse{ValidationState: cache.ValidationStateInsecure, RRset: rrs}, ChainInsecure},
		{"indeterminate", &tdns.ImrResponse{ValidationState: cache.ValidationStateIndeterminate, RRset: rrs}, ChainInsecure},
		{"none", &tdns.ImrResponse{ValidationState: cache.ValidationStateNone, RRset: rrs}, ChainInsecure},
		{"bogus", &tdns.ImrResponse{ValidationState: cache.ValidationStateBogus, RRset: rrs}, ChainBogus},
		{"records, no verdict", &tdns.ImrResponse{RRset: rrs}, ChainInsecure},
		{"denial, no verdict", &tdns.ImrResponse{Denial: cache.ContextNXDOMAIN}, ChainUnknown},
	} {
		if got := chainOf(tc.resp); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFailureOf(t *testing.T) {
	for _, tc := range []struct {
		err  error
		msg  string
		want DiscoveryFailure
	}{
		{context.DeadlineExceeded, "", FailureUnreachable},
		{nil, `Failed to resolve query "x.", URI, using any nameserver address`, FailureUnreachable},
		{errors.New("no Answers found from any auth server for x."), "", FailureUnreachable},
		{errors.New("max iterations reached, giving up"), "", FailureQuery},
		{nil, "Error finding the zone cut", FailureQuery},
	} {
		if got := failureOf(tc.err, tc.msg); got != tc.want {
			t.Errorf("failureOf(%v, %q) = %v, want %v", tc.err, tc.msg, got, tc.want)
		}
	}
}

// The reason names the failure that tells most, and a missing optional
// record only when there is nothing else to say.
func TestMechanismReasonPrefersTheTellingFailure(t *testing.T) {
	s := DiscoveryStatus{Lookups: []DiscoveryLookup{
		{Mechanism: "DNS", Type: "URI", Owner: "_dns._tcp.x.", Failure: FailureNoRecords, Detail: "no such name"},
		{Mechanism: "API", Type: "URI", Owner: "_https._tcp.x.", Chain: ChainInsecure, Detail: "answer insecure, accepted as DNSSEC validation is off"},
		{Mechanism: "API", Type: "SVCB", Owner: "api.x.", Chain: ChainBogus, Failure: FailureNotValidated, Detail: "answer bogus, DNSSEC validation required"},
	}}
	if r := s.MechanismReason("API"); r != "SVCB at api.x.: answer bogus, DNSSEC validation required" {
		t.Errorf("API reason %q", r)
	}
	if r := s.MechanismReason("DNS"); r != "URI at _dns._tcp.x.: no such name" {
		t.Errorf("DNS reason %q", r)
	}
	if c := s.Chain(); c != ChainBogus {
		t.Errorf("chain %v, want bogus", c)
	}
}

// A TLSA answer the checker reads replaces the peer's TLSA lookup, so the
// status follows the TLSA as it is now; a peer discovery has not read is
// left alone.
func TestNoteLookupReplacesTheTLSA(t *testing.T) {
	p := NewPeer("x.")
	p.noteLookup(DiscoveryLookup{Mechanism: "API", Type: "TLSA", Chain: ChainBogus})
	if p.DiscoveryStatus().Chain() != ChainUnknown {
		t.Fatal("a lookup was noted on a peer never discovered")
	}
	p.setDiscoveryStatus(DiscoveryStatus{At: time.Now(), Lookups: []DiscoveryLookup{
		{Mechanism: "API", Type: "URI", Chain: ChainSecure},
		{Mechanism: "API", Type: "TLSA", Chain: ChainSecure},
	}})
	p.noteLookup(DiscoveryLookup{Mechanism: "API", Type: "TLSA", Chain: ChainBogus})
	s := p.DiscoveryStatus()
	if len(s.Lookups) != 2 || s.Chain() != ChainBogus {
		t.Errorf("lookups %+v: want the TLSA replaced, bogus", s.Lookups)
	}
}

func TestDemoteMechanism(t *testing.T) {
	p := NewPeer("x.")
	p.SetMechanismState("API", PeerStateOperational, "hello")
	p.SetMechanismState("DNS", PeerStateOperational, "hello")
	p.SetState(PeerStateOperational, "hello")

	if was, demoted := p.demoteMechanism("API", "refused"); !demoted || was != PeerStateOperational {
		t.Fatalf("demote API: was %v demoted %v", was, demoted)
	}
	if p.GetState() != PeerStateOperational {
		t.Errorf("peer state %v: DNS is still in use, want it kept", p.GetState())
	}
	p.demoteMechanism("DNS", "refused")
	if p.GetState() != PeerStateNeeded {
		t.Errorf("peer state %v, want NEEDED with no mechanism in use", p.GetState())
	}
	if _, demoted := p.demoteMechanism("DNS", "refused again"); demoted {
		t.Error("a NEEDED mechanism was demoted again")
	}
}

// The TLSA checker's refusal, with validation required, takes the mechanism
// out of use as a discovery refusal does: NEEDED, the set it held dropped
// (so it is not usable), the reason on the status; and the refused answer
// does not put off the peer's refresh.
func TestTheCheckersRefusalTakesTheMechanismOutOfUse(t *testing.T) {
	cert := otherCert(t)
	p := withTLSA(NewPeer("b.example."), cert)
	p.SetAPIEndpoint("https://api.b.example.:443/api")
	p.SetMechanismState("API", PeerStateOperational, "hello")
	now := time.Now()
	p.setDiscoveryStatus(DiscoveryStatus{At: now, Lookups: []DiscoveryLookup{
		{Mechanism: "API", Type: "URI", Owner: "_https._tcp.b.example.", Chain: ChainSecure, Expires: now.Add(10 * time.Minute)},
		{Mechanism: "API", Type: "TLSA", Owner: "_443._tcp.api.b.example.", Chain: ChainSecure, Expires: now.Add(5 * time.Minute)},
	}})
	before := p.DiscoveryStatus().Expires
	if !p.APIUsable() {
		t.Fatal("the peer is not usable over the API before the refusal")
	}

	c := NewTLSAChecker(nil)
	c.source = &fakeTLSA{strict: true, answers: []fakeAnswer{{ans: tlsaAnswer{
		Records: []*dns.TLSA{tlsaFor(cert)}, Chain: ChainInsecure, Expires: now.Add(time.Hour)}}}}
	if _, err := c.Refresh(context.Background(), p, "API"); !errors.Is(err, ErrTLSALookup) {
		t.Fatalf("Refresh: %v, want ErrTLSALookup", err)
	}
	if st, _ := p.MechanismRawState("API"); st != PeerStateNeeded {
		t.Errorf("API state %v, want NEEDED", st)
	}
	if p.HasMechanismTLSA("API") || p.APIUsable() {
		t.Error("the refused TLSA's mechanism is still usable: the set held from before was kept")
	}
	s := p.DiscoveryStatus()
	if c := s.MechanismChain("API"); c != ChainInsecure {
		t.Errorf("API chain %v, want insecure", c)
	}
	if r := s.MechanismReason("API"); !strings.Contains(r, "TLSA at _443._tcp.api.b.example.: answer insecure, DNSSEC validation required") {
		t.Errorf("reason %q", r)
	}
	if !s.Expires.Equal(before) {
		t.Errorf("the peer's expiry moved from %v to %v: a refused answer put off the refresh", before, s.Expires)
	}

	// With validation off the same answer is used, and marked.
	q := withTLSA(NewPeer("c.example."), cert)
	q.SetMechanismState("API", PeerStateOperational, "hello")
	q.setDiscoveryStatus(DiscoveryStatus{At: now, Lookups: []DiscoveryLookup{{Mechanism: "API", Type: "TLSA", Chain: ChainSecure}}})
	c.source = &fakeTLSA{answers: []fakeAnswer{{ans: tlsaAnswer{Records: []*dns.TLSA{tlsaFor(cert)}, Chain: ChainInsecure}}}}
	if _, err := c.Refresh(context.Background(), q, "API"); err != nil {
		t.Fatalf("Refresh with validation off: %v", err)
	}
	if st, _ := q.MechanismRawState("API"); st != PeerStateOperational || !q.HasMechanismTLSA("API") {
		t.Errorf("with validation off: state %v, TLSA held %v: want it in use", st, q.HasMechanismTLSA("API"))
	}
	if c := q.DiscoveryStatus().MechanismChain("API"); c != ChainInsecure {
		t.Errorf("with validation off: chain %v, want insecure (marked)", c)
	}
}

// Discovery that refuses a TLSA drops the set held from before, as the
// checker does, and the mechanism goes back to NEEDED for that reason, not as
// a withdrawal.
func TestADiscoveryThatRefusesTheTLSADropsIt(t *testing.T) {
	imr := cachedPeerImr(t, true, cache.ValidationStateSecure, 600)
	tm, peer := apiManager(imr)
	if err := discoverWithin(t, tm); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	peer.SetMechanismState("API", PeerStateOperational, "hello")
	cacheAnswer(t, imr.Imr, "_8443._tcp.api."+dnssecPeer+" IN TLSA 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", cache.ValidationStateInsecure, 600)
	if err := discoverWithin(t, tm); err != nil {
		t.Fatalf("second discovery: %v", err)
	}
	if st, _ := peer.MechanismRawState("API"); st != PeerStateNeeded {
		t.Errorf("API state %v, want NEEDED", st)
	}
	if peer.HasMechanismTLSA("API") {
		t.Error("the TLSA set held from before was kept")
	}
	if r := peer.DiscoveryStatus().MechanismReason("API"); !strings.Contains(r, "TLSA at") || !strings.Contains(r, "DNSSEC validation required") {
		t.Errorf("reason %q: want the refused TLSA", r)
	}
}

// A lookup that cannot run says nothing about the data, which stays in use:
// the verdict and the expiry of the lookup before it stay, and when the
// whole discovery cannot run, the lookups it did not get to stay too.
func TestALookupThatCannotRunKeepsTheVerdict(t *testing.T) {
	p := NewPeer("b.example.")
	exp := time.Now().Add(-time.Minute)
	p.setDiscoveryStatus(DiscoveryStatus{At: time.Now().Add(-time.Hour), Lookups: []DiscoveryLookup{
		{Mechanism: "API", Type: "URI", Chain: ChainInsecure, Expires: exp},
		{Mechanism: "API", Type: "TLSA", Chain: ChainBogus, Expires: exp},
	}})
	p.setDiscoveryStatus(DiscoveryStatus{At: time.Now(), Failure: FailureUnreachable, Reason: "unreachable",
		Lookups: []DiscoveryLookup{{Mechanism: "API", Type: "URI", Failure: FailureUnreachable, Detail: "query failed: i/o timeout"}}})
	s := p.DiscoveryStatus()
	if len(s.Lookups) != 2 || s.MechanismChain("API") != ChainBogus {
		t.Fatalf("lookups %+v: want both kept, the chain still bogus", s.Lookups)
	}
	if u, _ := findLookup(s.Lookups, "API", "URI"); u.Chain != ChainInsecure || !u.Expires.Equal(exp) || u.Failure != FailureUnreachable {
		t.Errorf("the URI lookup %+v: want the failure, with the verdict and expiry from before", u)
	}
	if !s.due(time.Now().Add(2 * time.Minute)) {
		t.Error("a peer whose last discovery could not run is not asked for again")
	}

	// A refusal is an answer: it replaces what was there.
	p.setDiscoveryStatus(DiscoveryStatus{At: time.Now(), Failure: FailureNotValidated, Lookups: []DiscoveryLookup{
		{Mechanism: "API", Type: "URI", Chain: ChainInsecure, Failure: FailureNotValidated}}})
	if s := p.DiscoveryStatus(); len(s.Lookups) != 1 {
		t.Errorf("after a refusal: lookups %+v, want only the refusal", s.Lookups)
	}
}

func TestMechanismExpires(t *testing.T) {
	t1, t2 := time.Now().Add(time.Minute), time.Now().Add(time.Hour)
	s := DiscoveryStatus{Lookups: []DiscoveryLookup{
		{Mechanism: "API", Type: "URI", Expires: t2},
		{Mechanism: "API", Type: "TLSA", Expires: t1},
		{Mechanism: "DNS", Type: "URI", Expires: t2},
		{Mechanism: "DNS", Type: "JWK"},
	}}
	s.summarize()
	if !s.MechanismExpires("API").Equal(t1) || !s.MechanismExpires("DNS").Equal(t2) || !s.Expires.Equal(t1) {
		t.Errorf("API %v DNS %v peer %v: want %v %v %v", s.MechanismExpires("API"), s.MechanismExpires("DNS"), s.Expires, t1, t2, t1)
	}
	if !s.MechanismExpires("none").IsZero() {
		t.Error("a mechanism with no lookups has an expiry")
	}
}

// An ERROR left from a failed discovery before the peer was found does not
// stand in for it later: a successful discovery clears it, and when the
// peer's mechanisms are refused the peer is NEEDED, not ERROR (seen on the
// rig, run260b: the gossip cell read ERROR(-) where peer list read NEEDED(-)).
func TestAStaleErrorDoesNotStandInForThePeer(t *testing.T) {
	imr := cachedPeerImr(t, true, cache.ValidationStateSecure, 600)
	tm, peer := apiManager(imr)
	peer.SetState(PeerStateError, "an early discovery failed")
	if err := discoverWithin(t, tm); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	if st := peer.GetState(); st != PeerStateKnown {
		t.Errorf("after a successful discovery the peer's state is %v, want KNOWN", st)
	}
	peer.SetMechanismState("API", PeerStateOperational, "hello")
	peer.SetState(PeerStateError, "an early discovery failed, again")
	cacheAnswer(t, imr.Imr, "_https._tcp."+dnssecPeer+" IN URI 10 1 \"https://api.agent.example.:8443/api\"", cache.ValidationStateInsecure, 600)
	_ = discoverWithin(t, tm)
	if st := peer.EffectiveState(); st != PeerStateNeeded {
		t.Errorf("refused, the peer reads %v, want NEEDED", st)
	}
}
