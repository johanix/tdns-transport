package transport

import "testing"

// RegisterDiscoveredPeer with an API-only result (no DNS URI, no
// verification key) registers and promotes the peer: the key is a
// requirement of the DNS mechanism only.
func TestRegisterDiscoveredPeer_apiOnlyNeedsNoDNSKey(t *testing.T) {
	tm := &TransportManager{PeerRegistry: NewPeerRegistry()}
	err := tm.RegisterDiscoveredPeer(&DiscoveryResult{
		Identity:     "api.example.",
		APIUri:       "https://api.example.:8443/api/v1",
		APIAddresses: []string{"192.0.2.1"},
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
