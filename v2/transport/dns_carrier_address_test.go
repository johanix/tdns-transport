/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The DNS carrier dials only a DNS address (docs/2026-10-27-dns-carrier-address.md):
 * the slots it dials hold only udp or tcp addresses, their setters refuse any
 * other, and a peer that offers only the API is Addressable without one.
 */
package transport

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// setDNSCarrier sets the address the DNS carrier dials, which a test passes
// as a DNS address.
func setDNSCarrier(t *testing.T, p *Peer, addr *Address) {
	t.Helper()
	if err := p.SetDNSCarrierAddress(addr); err != nil {
		t.Fatalf("SetDNSCarrierAddress: %v", err)
	}
}

// setOperational sets a relocate's address, which a test passes as a DNS
// address.
func setOperational(t *testing.T, p *Peer, addr *Address) {
	t.Helper()
	if err := p.SetOperationalAddress(addr); err != nil {
		t.Fatalf("SetOperationalAddress: %v", err)
	}
}

// onlyDNSAddresses fails t when a slot the DNS carrier dials holds an
// address it does not dial.
func onlyDNSAddresses(t *testing.T, p *Peer, when string) {
	t.Helper()
	p.mu.RLock()
	carrier, relocated := p.DNSCarrierAddr, p.OperationalAddr
	p.mu.RUnlock()
	if err := checkDNSCarrierAddress(carrier); err != nil {
		t.Errorf("%s: DNSCarrierAddr: %v", when, err)
	}
	if err := checkDNSCarrierAddress(relocated); err != nil {
		t.Errorf("%s: OperationalAddr: %v", when, err)
	}
}

// apiOnlyPeerFound is a manager with both carriers that has found
// dnssecPeer, which offers only the API, by a secure discovery: its API is
// usable and in use.
func apiOnlyPeerFound(t *testing.T) (*TransportManager, *Peer, *Imr) {
	t.Helper()
	imr := cachedPeerImr(t, true, cache.ValidationStateSecure, 600)
	tm, peer := apiManager(imr)
	tm.APITransport, tm.DNSTransport = &APITransport{}, &DNSTransport{}
	if err := discoverWithin(t, tm); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	peer.SetMechanismState("API", PeerStateOperational, "hello")
	if !peer.APIUsable() || !peer.Addressable() {
		t.Fatal("after a secure discovery the API mechanism is not usable")
	}
	if a := peer.DNSCarrierAddress(); a != nil {
		t.Fatalf("DNSCarrierAddress %+v for a peer that offers only the API", a)
	}
	return tm, peer, imr
}

// refreshDiscovery runs the refresh that is due once peer's discovery
// expires.
func refreshDiscovery(t *testing.T, tm *TransportManager, peer *Peer) {
	t.Helper()
	expired := peer.DiscoveryStatus().Expires.Add(time.Second)
	if n := tm.refreshExpiredDiscoveries(context.Background(), expired); n != 1 {
		t.Fatalf("refreshed %d peers after expiry, want 1", n)
	}
}

// selectsNothing fails t when SelectTransport chooses a transport for peer,
// by default or with DNS preferred.
func selectsNothing(t *testing.T, tm *TransportManager, peer *Peer) {
	t.Helper()
	for _, pref := range []string{"API", "DNS"} {
		peer.SetPreferredTransport(pref)
		if tr := tm.SelectTransport(peer); tr != nil {
			t.Errorf("%s preferred: SelectTransport chose %s, want nothing", pref, tr.Name())
		}
	}
}

// A validated denial of the TLSA makes an API-only peer's API NEEDED. Nothing
// is left to send to: in particular the DNS carrier is not chosen to dial the
// HTTPS address.
func TestTLSAWithdrawnFromAnAPIOnlyPeerSelectsNothing(t *testing.T) {
	tm, peer, imr := apiOnlyPeerFound(t)

	cacheDenial(t, imr.Imr, "_8443._tcp.api."+dnssecPeer, dns.TypeTLSA, cache.ValidationStateSecure)
	refreshDiscovery(t, tm, peer)
	if st, _ := peer.MechanismRawState("API"); st != PeerStateNeeded {
		t.Errorf("API state %v after the withdrawal, want NEEDED", st)
	}
	if peer.APIUsable() {
		t.Fatal("the API is usable with its TLSA withdrawn")
	}
	if a := peer.DNSCarrierAddress(); a != nil {
		t.Errorf("DNSCarrierAddress %+v: the API's address is there for the DNS carrier", a)
	}
	if peer.Addressable() {
		t.Error("the peer is Addressable with nothing to send to")
	}
	selectsNothing(t, tm, peer)
	onlyDNSAddresses(t, peer, "after the withdrawal")
}

// The API moves to another endpoint, with no TLSA for it yet. Its slot
// takes the new address; the DNS carrier is given neither the old address
// nor the new one.
func TestAMovedAPIAddressIsNotDialledByTheDNSCarrier(t *testing.T) {
	tm, peer, imr := apiOnlyPeerFound(t)
	old := *peer.MechanismAddress("API")

	cacheAnswer(t, imr.Imr, "_https._tcp."+dnssecPeer+" IN URI 10 1 \"https://api.agent.example.:9443/api\"", cache.ValidationStateSecure, 600)
	cacheAnswer(t, imr.Imr, "api."+dnssecPeer+" IN SVCB 1 . ipv4hint=192.0.2.11", cache.ValidationStateSecure, 600)
	cacheDenial(t, imr.Imr, "_9443._tcp.api."+dnssecPeer, dns.TypeTLSA, cache.ValidationStateSecure)
	refreshDiscovery(t, tm, peer)
	if a := peer.MechanismAddress("API"); a == nil || a.Host != "192.0.2.11" || a.Port != 9443 {
		t.Fatalf("API address %+v after the move, want 192.0.2.11:9443", a)
	}
	if peer.APIUsable() {
		t.Fatal("the API is usable at the new endpoint with no TLSA for it")
	}
	if a := peer.DNSCarrierAddress(); a != nil {
		t.Errorf("DNSCarrierAddress %+v, want none: the old API address was %+v", a, old)
	}
	if peer.Addressable() {
		t.Error("the peer is Addressable with nothing to send to")
	}
	selectsNothing(t, tm, peer)
	onlyDNSAddresses(t, peer, "after the move")
}

// The setters of the slots the DNS carrier dials take a udp or tcp address
// without a path, and nil. Any other is refused with an error, and the slot
// keeps what it had.
func TestTheDNSCarrierSettersRefuseANonDNSAddress(t *testing.T) {
	setters := map[string]func(*Peer, *Address) error{
		"SetDNSCarrierAddress":  (*Peer).SetDNSCarrierAddress,
		"SetOperationalAddress": (*Peer).SetOperationalAddress,
	}
	slot := map[string]func(*Peer) *Address{
		"SetDNSCarrierAddress":  func(p *Peer) *Address { return p.DNSCarrierAddr },
		"SetOperationalAddress": func(p *Peer) *Address { return p.OperationalAddr },
	}
	for _, tc := range []struct {
		name  string
		addr  *Address
		taken bool
	}{
		{"https with a path", &Address{Host: "192.0.2.10", Port: 8443, Transport: "https", Path: "/api"}, false},
		{"https", &Address{Host: "192.0.2.10", Port: 8443, Transport: "https"}, false},
		{"tcp with a path", &Address{Host: "192.0.2.10", Port: 53, Transport: "tcp", Path: "/api"}, false},
		{"no transport", &Address{Host: "192.0.2.10", Port: 53}, false},
		{"udp", &Address{Host: "192.0.2.30", Port: 53, Transport: "udp"}, true},
		{"tcp", &Address{Host: "192.0.2.30", Port: 53, Transport: "tcp"}, true},
		{"nil", nil, true},
	} {
		for name, set := range setters {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				peer := NewPeer(dnssecPeer)
				held := &Address{Host: "192.0.2.20", Port: 53, Transport: "udp"}
				if err := set(peer, held); err != nil {
					t.Fatalf("a udp address: %v", err)
				}
				err := set(peer, tc.addr)
				got := slot[name](peer)
				if tc.taken {
					if err != nil || got != tc.addr {
						t.Errorf("%v, slot %+v: want it taken", err, got)
					}
					return
				}
				if err == nil {
					t.Error("taken, want an error")
				}
				if got != held {
					t.Errorf("slot %+v, want the address it held, %+v", got, held)
				}
			})
		}
	}
}

// Registration writes only DNS addresses to the slot the DNS carrier dials,
// whatever the API and DNS legs found or were refused, and when a later
// discovery withdraws the API's TLSA or moves the API.
func TestRegistrationPutsOnlyDNSAddressesWhereTheDNSCarrierDials(t *testing.T) {
	tlsaRR, err := dns.NewRR("_8443._tcp.api." + dnssecPeer + " 600 IN TLSA 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	owner := "_8443._tcp.api." + dnssecPeer
	tlsa := TLSASet{Owner: owner, Records: []*dns.TLSA{tlsaRR.(*dns.TLSA)}, Validated: true}
	api := func(r DiscoveryResult) DiscoveryResult {
		r.Identity = dnssecPeer
		r.APIUri = "https://api.agent.example.:8443/api"
		r.APIAddresses = []string{"192.0.2.10"}
		return r
	}
	withDNS := func(r DiscoveryResult) DiscoveryResult {
		r.DNSUri = "dns://dns.agent.example.:53"
		r.DNSAddresses = []string{"192.0.2.20"}
		return r
	}
	refused := func(mech, typ, owner string) []DiscoveryLookup {
		return []DiscoveryLookup{{Mechanism: mech, Type: typ, Owner: owner, Chain: ChainInsecure,
			Failure: FailureNotValidated, Detail: "answer insecure, DNSSEC validation required"}}
	}
	usable := api(DiscoveryResult{TLSA: tlsa})
	for _, tc := range []struct {
		name    string
		results []DiscoveryResult
	}{
		{"API only, usable", []DiscoveryResult{usable}},
		{"API only, no TLSA", []DiscoveryResult{api(DiscoveryResult{})}},
		{"API and DNS", []DiscoveryResult{withDNS(usable)}},
		{"API usable, DNS key refused", []DiscoveryResult{withDNS(api(DiscoveryResult{TLSA: tlsa, Lookups: refused("DNS", "JWK", dnssecPeer)}))}},
		{"API usable, DNS URI refused", []DiscoveryResult{api(DiscoveryResult{TLSA: tlsa, Lookups: refused("DNS", "URI", "_dns._tcp."+dnssecPeer)})}},
		{"API refused, DNS found", []DiscoveryResult{withDNS(api(DiscoveryResult{TLSA: tlsa, Lookups: refused("API", "URI", "_https._tcp."+dnssecPeer)}))}},
		{"API usable, then its TLSA withdrawn", []DiscoveryResult{usable, api(DiscoveryResult{TLSA: TLSASet{Owner: owner, Validated: true}})}},
		{"API usable, then moved with no TLSA", []DiscoveryResult{usable, {
			Identity: dnssecPeer, APIUri: "https://api.agent.example.:9443/api", APIAddresses: []string{"192.0.2.11"},
			TLSA: TLSASet{Owner: "_9443._tcp.api." + dnssecPeer}, TLSAFailed: true,
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tm := &TransportManager{PeerRegistry: NewPeerRegistry(), APITransport: &APITransport{}, DNSTransport: &DNSTransport{}}
			peer := tm.PeerRegistry.GetOrCreate(dnssecPeer)
			for i := range tc.results {
				r := tc.results[i]
				if err := tm.RegisterDiscoveredPeer(&r); err != nil {
					t.Logf("registration %d: %v", i+1, err)
				}
				onlyDNSAddresses(t, peer, fmt.Sprintf("registration %d", i+1))
				if r.DNSUri == "" {
					if a := peer.DNSCarrierAddress(); a != nil {
						t.Errorf("registration %d: DNSCarrierAddress %+v for a peer that offers no DNS", i+1, a)
					}
				}
			}
		})
	}
}

// Addressable: somewhere to send, by either carrier.
func TestAddressable(t *testing.T) {
	tlsaRR, err := dns.NewRR("_8443._tcp.api." + dnssecPeer + " 600 IN TLSA 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		set  func(*Peer)
		want bool
	}{
		{"a DNS address only", func(p *Peer) {
			setDNSCarrier(t, p, &Address{Host: "192.0.2.20", Port: 53, Transport: "udp"})
		}, true},
		{"a relocate only", func(p *Peer) {
			setOperational(t, p, &Address{Host: "198.51.100.20", Port: 53, Transport: "udp"})
		}, true},
		{"a usable API only", func(p *Peer) {
			p.SetAPIEndpoint("https://api.agent.example.:8443/api")
			p.SetMechanismTLSA("API", TLSASet{Owner: "_8443._tcp.api." + dnssecPeer, Records: []*dns.TLSA{tlsaRR.(*dns.TLSA)}, Validated: true})
		}, true},
		{"an API with no TLSA only", func(p *Peer) {
			p.SetAPIEndpoint("https://api.agent.example.:8443/api")
		}, false},
		{"nothing", func(*Peer) {}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := NewPeer(dnssecPeer)
			tc.set(peer)
			if got := peer.Addressable(); got != tc.want {
				t.Errorf("Addressable() = %v, want %v", got, tc.want)
			}
		})
	}
}
