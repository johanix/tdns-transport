package transport

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestAddressHostPort(t *testing.T) {
	for _, tc := range []struct {
		addr Address
		want string
	}{
		{Address{Host: "192.0.2.1", Port: 53}, "192.0.2.1:53"},
		{Address{Host: "::1", Port: 8055}, "[::1]:8055"},
		{Address{Host: "2001:db8::53", Port: 853}, "[2001:db8::53]:853"},
		{Address{Host: "ns.example.", Port: 5353}, "ns.example.:5353"},
	} {
		if got := tc.addr.HostPort(); got != tc.want {
			t.Errorf("%+v.HostPort() = %q, want %q", tc.addr, got, tc.want)
		}
	}
	a := Address{Host: "::1", Port: 8085, Transport: "https", Path: "/api/v1"}
	if got, want := a.String(), "https://[::1]:8085/api/v1"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// A ping to a peer at an IPv6 address reaches the peer's receive pipeline
// and comes back confirmed.
func TestDNSPingToIPv6Peer(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	const zone = "control.example."
	receiver := NewChunkNotifyHandler(zone, "b.example.", nil)
	receiver.ParseApp = func(distributionID string, payload []byte, sourceAddr string) (*IncomingMessage, error) {
		var p PingPost
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		return &IncomingMessage{TypeToken: p.MessageType, SenderID: p.MyIdentity, DistributionID: distributionID,
			Payload: payload, SourceAddr: sourceAddr}, nil
	}
	receiver.Router = NewDNSMessageRouter()
	if err := InitializeRouter(receiver.Router, &RouterConfig{}); err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		_ = receiver.RouteViaRouter(context.Background(), r.Question[0].Name, r, w)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	sender := NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: zone, ChunkMode: "edns0", Timeout: 2 * time.Second})
	peer := NewPeer("b.example.")
	peer.SetDiscoveryAddress(&Address{Host: "::1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := sender.Ping(ctx, peer, &PingRequest{SenderID: "a.example.", Nonce: "n-6", Timestamp: time.Now()})
	if err != nil {
		t.Fatalf("Ping to [::1]: %v", err)
	}
	if !resp.OK || resp.Nonce != "n-6" || resp.ResponderID != "b.example." {
		t.Fatalf("ping confirm: %+v", resp)
	}
}
