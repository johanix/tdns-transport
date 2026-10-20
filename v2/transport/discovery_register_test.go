package transport

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// RegisterDiscoveredPeer with an API-only result (no DNS URI, no
// verification key) registers and promotes the peer: the key is a
// requirement of the DNS mechanism only.
func TestRegisterDiscoveredPeer_apiOnlyNeedsNoDNSKey(t *testing.T) {
	tm := &TransportManager{PeerRegistry: NewPeerRegistry()}
	err := tm.RegisterDiscoveredPeer(&DiscoveryResult{
		Identity:     "api.example.",
		APIUri:       "https://api.example.:8443/api/v1",
		APIAddresses: []string{"192.0.2.1"},
		TLSA:         TLSASet{Owner: "_8443._tcp.api.api.example.", Records: []*dns.TLSA{tlsaFor(otherCert(t))}, Validated: true},
	})
	if err != nil {
		t.Fatalf("RegisterDiscoveredPeer: %v", err)
	}
	peer, ok := tm.PeerRegistry.Get("api.example.")
	if !ok {
		t.Fatal("peer not registered")
	}
	if !peer.HasMechanism("API") || peer.PreferredMechanism() != "API" || peer.PreferredTransport != "API" {
		t.Fatalf("API mechanism not usable: has=%v pref=%q transport=%q", peer.HasMechanism("API"), peer.PreferredMechanism(), peer.PreferredTransport)
	}
	if st, _ := peer.MechanismRawState("API"); st != PeerStateKnown {
		t.Fatalf("API mechanism state = %v, want KNOWN", st)
	}
}

// A DNS result populates the DNS mechanism's address slot, so HasMechanism
// and PreferredMechanism see it; with both mechanisms resolved the API
// preference is kept and the DNS carrier's address is what CurrentAddress
// returns.
func TestRegisterDiscoveredPeer_dnsAddressAndPreference(t *testing.T) {
	tm := &TransportManager{PeerRegistry: NewPeerRegistry()}
	if err := tm.RegisterDiscoveredPeer(&DiscoveryResult{
		Identity:     "dns.example.",
		DNSUri:       "dns://dns.dns.example.:8154/",
		DNSAddresses: []string{"192.0.2.2"},
	}); err != nil {
		t.Fatalf("DNS-only: %v", err)
	}
	peer, _ := tm.PeerRegistry.Get("dns.example.")
	if !peer.HasMechanism("DNS") || peer.PreferredMechanism() != "DNS" || peer.PreferredTransport != "DNS" {
		t.Fatalf("DNS mechanism not usable: has=%v pref=%q transport=%q", peer.HasMechanism("DNS"), peer.PreferredMechanism(), peer.PreferredTransport)
	}
	if a := peer.CurrentAddress(); a == nil || a.Host != "192.0.2.2" || a.Port != 8154 {
		t.Fatalf("CurrentAddress = %+v, want 192.0.2.2:8154", a)
	}

	if err := tm.RegisterDiscoveredPeer(&DiscoveryResult{
		Identity:     "both.example.",
		APIUri:       "https://api.both.example.:8443/api/v1",
		APIAddresses: []string{"192.0.2.3"},
		DNSUri:       "dns://dns.both.example.:8154/",
		DNSAddresses: []string{"192.0.2.4"},
	}); err != nil {
		t.Fatalf("both: %v", err)
	}
	peer, _ = tm.PeerRegistry.Get("both.example.")
	if !peer.HasMechanism("API") || !peer.HasMechanism("DNS") {
		t.Fatalf("both mechanisms expected: api=%v dns=%v", peer.HasMechanism("API"), peer.HasMechanism("DNS"))
	}
	if peer.PreferredTransport != "API" || peer.PreferredMechanism() != "API" {
		t.Fatalf("API should stay preferred: transport=%q mechanism=%q", peer.PreferredTransport, peer.PreferredMechanism())
	}
	if a := peer.CurrentAddress(); a == nil || a.Host != "192.0.2.4" {
		t.Fatalf("CurrentAddress (the DNS carrier slot) = %+v, want the DNS address", a)
	}
}

// Two discoveries of one peer can finish at once (a hello and the retry
// loop both look it up), while beats arrive from it and sends to it pick
// a transport. Run under -race.
func TestTwoDiscoveriesOfOnePeerDoNotRaceItsTraffic(t *testing.T) {
	tm := &TransportManager{PeerRegistry: NewPeerRegistry()}
	result := &DiscoveryResult{
		Identity:     "both.example.",
		APIUri:       "https://api.both.example.:8443/api/v1",
		APIAddresses: []string{"192.0.2.3"},
		DNSUri:       "dns://dns.both.example.:8154/",
		DNSAddresses: []string{"192.0.2.4"},
	}
	peer := tm.PeerRegistry.GetOrCreate("both.example.")

	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if err := tm.RegisterDiscoveredPeer(result); err != nil {
				t.Errorf("RegisterDiscoveredPeer: %v", err)
			}
		})
	}
	for range 2 {
		wg.Go(func() {
			peer.SetMechanismLastBeatRecv("DNS", time.Now())
			peer.SetLastBeatReceived(time.Now())
		})
	}
	wg.Go(func() {
		tm.SelectTransport(peer)
		_, _ = apiURL(peer, "/beat")
		_ = peer.GetDNSEndpoint()
	})
	wg.Wait()

	if got := peer.GetPreferredTransport(); got != "API" {
		t.Errorf("preferred transport = %q, want API", got)
	}
	if got := peer.GetAPIEndpoint(); got != result.APIUri {
		t.Errorf("API endpoint = %q, want %q", got, result.APIUri)
	}
	if peer.GetLastBeatReceived().IsZero() {
		t.Error("no beat received time recorded")
	}
}

// An API endpoint without a usable TLSA is not usable: its mechanism stays
// NEEDED, so the retrier looks again, and a later discovery that finds one
// makes it KNOWN. A discovery whose TLSA lookup failed keeps the set held.
func TestRegisterDiscoveredPeer_apiWithoutTLSAIsNotUsable(t *testing.T) {
	tm := &TransportManager{PeerRegistry: NewPeerRegistry()}
	owner := "_8443._tcp.api.late.example."
	res := &DiscoveryResult{
		Identity:     "late.example.",
		APIUri:       "https://api.late.example.:8443/api/v1",
		APIAddresses: []string{"192.0.2.1"},
		TLSA:         TLSASet{Owner: owner, Validated: true},
		Partial:      true,
	}
	if err := tm.RegisterDiscoveredPeer(res); err != nil {
		t.Fatalf("RegisterDiscoveredPeer: %v", err)
	}
	peer, _ := tm.PeerRegistry.Get("late.example.")
	if st, _ := peer.MechanismRawState("API"); st != PeerStateNeeded || peer.APIUsable() {
		t.Fatalf("API with no TLSA: state %v, usable %v; want NEEDED and not usable", st, peer.APIUsable())
	}
	if !peer.mechanismNeedsDiscovery() {
		t.Error("a peer with API NEEDED does not need discovery")
	}

	res.TLSA.Records = []*dns.TLSA{tlsaFor(otherCert(t))}
	res.Partial = false
	if err := tm.RegisterDiscoveredPeer(res); err != nil {
		t.Fatalf("RegisterDiscoveredPeer: %v", err)
	}
	if st, _ := peer.MechanismRawState("API"); st != PeerStateKnown || !peer.APIUsable() {
		t.Fatalf("API with a TLSA published: state %v, usable %v; want KNOWN and usable", st, peer.APIUsable())
	}

	if err := tm.RegisterDiscoveredPeer(&DiscoveryResult{
		Identity:     "late.example.",
		APIUri:       "https://api.late.example.:8443/api/v1",
		APIAddresses: []string{"192.0.2.1"},
		TLSA:         TLSASet{Owner: owner},
		TLSAFailed:   true,
		Partial:      true,
	}); err != nil {
		t.Fatalf("RegisterDiscoveredPeer: %v", err)
	}
	if !peer.APIUsable() {
		t.Error("a failed TLSA lookup on re-discovery dropped the set held")
	}

	// A re-discovery that finds the TLSA gone puts an established
	// mechanism back to NEEDED, so the retrier looks again.
	peer.SetMechanismState("API", PeerStateOperational, "test")
	if err := tm.RegisterDiscoveredPeer(&DiscoveryResult{
		Identity:     "late.example.",
		APIUri:       "https://api.late.example.:8443/api/v1",
		APIAddresses: []string{"192.0.2.1"},
		TLSA:         TLSASet{Owner: owner, Validated: true},
		Partial:      true,
	}); err != nil {
		t.Fatalf("RegisterDiscoveredPeer: %v", err)
	}
	if st, _ := peer.MechanismRawState("API"); st != PeerStateNeeded || peer.APIUsable() || !peer.mechanismNeedsDiscovery() {
		t.Errorf("after the TLSA went: state %v, usable %v; want NEEDED, not usable, up for discovery", st, peer.APIUsable())
	}
}

// A peer known on one mechanism is looked up again while another still
// needs discovery, and stays usable when that look fails: the resolver is
// asked (and has nothing), and the known peer comes back without an error.
func TestDiscoverPeerLooksAgainWhileAMechanismIsNeeded(t *testing.T) {
	asked := 0
	tm := &TransportManager{PeerRegistry: NewPeerRegistry(), GetImr: func() *Imr { asked++; return nil }}
	peer := tm.PeerRegistry.GetOrCreate("half.example.")
	peer.SetState(PeerStateKnown, "test")
	peer.SetMechanismState("DNS", PeerStateOperational, "test")
	if got, err := tm.DiscoverPeer(context.Background(), "half.example."); err != nil || got != peer || asked != 0 {
		t.Fatalf("a peer known on its only mechanism: %v %v, resolver asked %d times, want none", got, err, asked)
	}
	peer.SetMechanismContactInfo("API", "partial")
	peer.SetMechanismState("API", PeerStateNeeded, "no TLSA yet")
	got, err := tm.DiscoverPeer(context.Background(), "half.example.")
	if asked == 0 {
		t.Error("a peer with a mechanism NEEDED was not looked up again")
	}
	if err != nil || got != peer {
		t.Errorf("a known peer whose re-discovery failed: %v %v, want the peer as it was", got, err)
	}
	tm.GetImr = nil
	if got, err := tm.DiscoverPeer(context.Background(), "half.example."); err != nil || got != peer {
		t.Errorf("a known peer with no resolver to look again: %v %v, want the peer as it was", got, err)
	}
	if _, err := tm.DiscoverPeer(context.Background(), "unknown.example."); err == nil {
		t.Error("an unknown peer with no resolver: no error")
	}
}
