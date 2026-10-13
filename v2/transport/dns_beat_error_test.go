package transport

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dnsPeerAnswering starts a server that answers every message with rcode and
// returns a peer whose DNS mechanism points at it.
func dnsPeerAnswering(t *testing.T, rcode int) *Peer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})
	peer := NewPeer("b.example.")
	peer.SetDiscoveryAddress(&Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp"})
	return peer
}

// A beat that the peer answers with REFUSED is an error to the caller, and
// the error says the rcode, as it does for a hello. It used to come back as
// a beat that was not acknowledged, with no error: the same as a beat that
// the peer answered and did not confirm.
func TestADNSBeatThatIsRefusedIsAnError(t *testing.T) {
	peer := dnsPeerAnswering(t, dns.RcodeRefused)
	sender := NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example.", ChunkMode: "edns0", Timeout: 2 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, helloErr := sender.Hello(ctx, peer, &HelloRequest{SenderID: "a.example.", Timestamp: time.Now()})
	resp, beatErr := sender.Beat(ctx, peer, &BeatRequest{SenderID: "a.example.", Timestamp: time.Now(), Sequence: 7})
	if beatErr == nil {
		t.Fatalf("Beat to a peer that answers REFUSED returned no error, and the response %+v", resp)
	}
	if resp != nil {
		t.Errorf("Beat returned the response %+v with its error, want none", resp)
	}
	var te *TransportError
	if !errors.As(beatErr, &te) {
		t.Fatalf("Beat's error is a %T, want a *TransportError: %v", beatErr, beatErr)
	}
	if te.Err == nil || !strings.Contains(te.Err.Error(), dns.RcodeToString[dns.RcodeRefused]) {
		t.Errorf("Beat's error does not say the rcode: %v", beatErr)
	}

	// The same answer to a hello gives the same cause.
	var hte *TransportError
	if !errors.As(helloErr, &hte) || hte.Err == nil {
		t.Fatalf("Hello's error is a %T, want a *TransportError with a cause: %v", helloErr, helloErr)
	}
	if hte.Err.Error() != te.Err.Error() {
		t.Errorf("a refused beat says %q and a refused hello says %q, want the same", te.Err, hte.Err)
	}
}

// A beat to a peer that does not answer is an error too, and not the one of
// a refused beat.
func TestADNSBeatThatGetsNoAnswerIsAnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close() // nothing listens there now

	peer := NewPeer("b.example.")
	peer.SetDiscoveryAddress(&Address{Host: "127.0.0.1", Port: port, Transport: "tcp"})
	sender := NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example.", ChunkMode: "edns0", Timeout: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, beatErr := sender.Beat(ctx, peer, &BeatRequest{SenderID: "a.example.", Timestamp: time.Now()})
	if beatErr == nil {
		t.Fatalf("Beat to a port where nothing listens returned no error, and the response %+v", resp)
	}
	if strings.Contains(beatErr.Error(), dns.RcodeToString[dns.RcodeRefused]) {
		t.Errorf("Beat's error says REFUSED for a peer that did not answer: %v", beatErr)
	}
}
