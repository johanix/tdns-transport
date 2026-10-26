package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// sendTransport is a Transport whose Ping and SendApp fail with err (or
// succeed when err is nil) and count their calls.
type sendTransport struct {
	name  string
	err   error
	calls int
}

func (f *sendTransport) Ping(ctx context.Context, peer *Peer, req *PingRequest) (*PingResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &PingResponse{ResponderID: peer.ID, Nonce: req.Nonce, OK: true}, nil
}
func (f *sendTransport) SendApp(context.Context, *Peer, *AppMessage) (*AppResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &AppResponse{Status: ConfirmSuccess}, nil
}
func (f *sendTransport) Hello(context.Context, *Peer, *HelloRequest) (*HelloResponse, error) {
	return nil, errors.New("not used")
}
func (f *sendTransport) Beat(context.Context, *Peer, *BeatRequest) (*BeatResponse, error) {
	return nil, errors.New("not used")
}
func (f *sendTransport) Confirm(context.Context, *Peer, *ConfirmRequest) error { return nil }
func (f *sendTransport) Name() string                                          { return f.name }

// TestSendBothFailCarriesBoth is the peer ping to an IPv6 address: the DNS
// primary fails retryably, the API fallback fails too, and the error must
// still say why DNS failed.
func TestSendBothFailCarriesBoth(t *testing.T) {
	peer := NewPeer("peer.example.")
	errDial := errors.New("dial tcp: address ::1:8055: too many colons in address")
	errNoEndpoint := errors.New("peer peer.example. has no API endpoint configured")
	dnsErr := NewTransportError("DNS", "Ping", peer.ID, fmt.Errorf("NOTIFY exchange failed: %w", errDial), true)
	apiErr := NewTransportError("API", "Ping", peer.ID, errNoEndpoint, false)
	dns := &sendTransport{name: "DNS", err: dnsErr}
	api := &sendTransport{name: "API", err: apiErr}

	_, err := sendWith(context.Background(), peer, &PingRequest{}, dns, api)
	if err == nil {
		t.Fatal("both transports failed but no error was returned")
	}
	if dns.calls != 1 || api.calls != 1 {
		t.Errorf("calls: DNS %d, API %d; want 1 each", dns.calls, api.calls)
	}
	for _, want := range []error{dnsErr, errDial, apiErr, errNoEndpoint} {
		if !errors.Is(err, want) {
			t.Errorf("errors.Is(err, %q) is false; err: %v", want, err)
		}
	}
	var te *TransportError
	if !errors.As(err, &te) || te != dnsErr {
		t.Errorf("errors.As found %v, want the primary's *TransportError", te)
	}
	for _, want := range []string{"DNS: " + dnsErr.Error(), "API: " + apiErr.Error()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// refuseTransport's SendApp returns a ConfirmFailed AppResponse with no
// error: what a peer answers when it refuses an RFI (or sync/update).
type refuseTransport struct {
	sendTransport
	status ConfirmStatus
	msg    string
}

func (f *refuseTransport) SendApp(context.Context, *Peer, *AppMessage) (*AppResponse, error) {
	f.calls++
	st := f.status
	if st == 0 {
		st = ConfirmFailed
	}
	return &AppResponse{Status: st, Message: f.msg}, nil
}

// A recipient's refusal of a sync-family verb must not fall back: the
// message was delivered and judged; the other mechanism would refuse
// again (tdns-transport #36).
func TestSendRefusalDoesNotFallBack(t *testing.T) {
	ctx := context.Background()
	peer := NewPeer("peer.example.")
	primary := &refuseTransport{sendTransport: sendTransport{name: "API"}, msg: "not authorized"}
	fallback := &sendTransport{name: "DNS"}

	resp, err := sendWith(ctx, peer, &AppMessage{TypeToken: "rfi"}, primary, fallback)
	if fallback.calls != 0 {
		t.Fatalf("fallback was called %d times; a refusal must not fall back", fallback.calls)
	}
	if primary.calls != 1 {
		t.Fatalf("primary calls %d, want 1", primary.calls)
	}
	var te *TransportError
	if !errors.As(err, &te) || !te.Retryable || !te.Answered {
		t.Fatalf("err %v: want a retryable Answered *TransportError", err)
	}
	if ar, ok := resp.(*AppResponse); !ok || ar.Status != ConfirmFailed {
		t.Fatalf("resp %+v, want the ConfirmFailed AppResponse", resp)
	}
	if !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("error %q does not carry the refusal", err)
	}

	// A dial-style retryable failure still falls back.
	dialErr := NewTransportError("API", "rfi", peer.ID, errors.New("connection refused"), true)
	dnsOK := &sendTransport{name: "DNS"}
	apiFail := &sendTransport{name: "API", err: dialErr}
	resp, err = sendWith(ctx, peer, &AppMessage{TypeToken: "rfi"}, apiFail, dnsOK)
	if err != nil || dnsOK.calls != 1 {
		t.Fatalf("dial failure should fall back: resp %+v err %v fallback calls %d", resp, err, dnsOK.calls)
	}
}

// A /msg that does not take a verb answers that it is not accepted there
// (tdns-mp's main takes sync, update, rfi and confirm; config and audit
// come with tdns-mp #238). Nothing judged the message, so Send carries it
// over DNS, for every sync-family verb. A message the endpoint took and
// judged does not fall back: the refusal comes back, Answered
// (tdns-transport #36).
func TestSendVerbNotAcceptedFallsBack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rcv := newMsgReceiver(t)
	dnsRcv := newDNSChunkReceiver(t)
	dnsRcv.setConfirm(true)
	tm := &TransportManager{
		APITransport: apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, rcv.srv),
		DNSTransport: NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example.", Timeout: 2 * time.Second}),
	}
	peer := apiPeer(rcv.srv)
	peer.SetDiscoveryAddress(dnsRcv.addr)
	peer.SetMechanismAddress("DNS", dnsRcv.addr)

	posts, notifies := 0, 0
	for _, verb := range []string{"sync", "update", "rfi", "config", "audit"} {
		rcv.refuseWith(fmt.Sprintf("message type %q is not accepted on /api/v1/msg", verb))
		resp, err := tm.Send(ctx, peer, &AppMessage{TypeToken: verb, Payload: []byte(`{}`)})
		posts++
		notifies++
		if err != nil {
			t.Fatalf("%s not accepted on /msg: %v, want it sent over DNS", verb, err)
		}
		if ar, ok := resp.(*AppResponse); !ok || ar.Status != ConfirmSuccess {
			t.Errorf("%s not accepted on /msg: resp %+v, want DNS's ConfirmSuccess", verb, resp)
		}
		if api, dns := len(rcv.captured()), len(dnsRcv.received()); api != posts || dns != notifies {
			t.Fatalf("%s not accepted on /msg: %d POSTs, %d NOTIFYs; want %d and %d", verb, api, dns, posts, notifies)
		}
	}

	// A config the endpoint took and judged stays there.
	rcv.refuseWith("not authorized")
	resp, err := tm.Send(ctx, peer, &AppMessage{TypeToken: "config", Payload: []byte(`{}`)})
	posts++
	var te *TransportError
	if err == nil || !errors.As(err, &te) || !te.Retryable || !te.Answered {
		t.Fatalf("a judged config: %v, want a retryable, Answered *TransportError", err)
	}
	if !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("error %q does not carry the refusal", err)
	}
	if ar, ok := resp.(*AppResponse); !ok || ar.Status != ConfirmFailed {
		t.Errorf("a judged config: resp %+v, want the ConfirmFailed AppResponse", resp)
	}
	if api, dns := len(rcv.captured()), len(dnsRcv.received()); api != posts || dns != notifies {
		t.Fatalf("a judged config: %d POSTs, %d NOTIFYs; want %d and %d", api, dns, posts, notifies)
	}
}

// TestSendFallbackOutcomes covers the other ways out of primary-then-fallback.
func TestSendFallbackOutcomes(t *testing.T) {
	ctx := context.Background()
	peer := NewPeer("peer.example.")
	retryable := NewTransportError("DNS", "Ping", peer.ID, errors.New("NOTIFY exchange failed: timeout"), true)

	// A non-retryable primary error is returned as is; the fallback is not tried.
	final := NewTransportError("DNS", "Ping", peer.ID, errors.New("no address available"), false)
	dns, api := &sendTransport{name: "DNS", err: final}, &sendTransport{name: "API"}
	if _, err := sendWith(ctx, peer, &PingRequest{}, dns, api); err != final || api.calls != 0 {
		t.Errorf("non-retryable primary: err %v, fallback calls %d", err, api.calls)
	}

	// A retryable primary error with no fallback transport is kept.
	dns = &sendTransport{name: "DNS", err: retryable}
	if _, err := sendWith(ctx, peer, &PingRequest{}, dns, nil); !errors.Is(err, retryable) ||
		!strings.Contains(err.Error(), "DNS: "+retryable.Error()) {
		t.Errorf("no fallback: %v", err)
	}

	// A fallback that succeeds is the result.
	dns, api = &sendTransport{name: "DNS", err: retryable}, &sendTransport{name: "API"}
	resp, err := sendWith(ctx, peer, &AppMessage{TypeToken: "sync"}, dns, api)
	if ar, ok := resp.(*AppResponse); err != nil || !ok || ar.Status != ConfirmSuccess || api.calls != 1 {
		t.Errorf("fallback success: resp %+v, err %v, fallback calls %d", resp, err, api.calls)
	}

	// An unsupported request type reaches no transport.
	dns, api = &sendTransport{name: "DNS"}, &sendTransport{name: "API"}
	if _, err := sendWith(ctx, peer, &HelloRequest{}, dns, api); err == nil || dns.calls+api.calls != 0 {
		t.Errorf("unsupported type: err %v, calls %d", err, dns.calls+api.calls)
	}
}

// TestSendDNSOnlyVerbHasNoAPIFallback runs Send over the real transports
// against a peer that refuses every connection. A verb only DNS carries
// fails over DNS alone; a sync-family verb still tries both mechanisms.
func TestSendDNSOnlyVerbHasNoAPIFallback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing listens on port: every dial is refused

	tm := &TransportManager{
		APITransport: NewAPITransport(&APITransportConfig{LocalID: "me.example.", DefaultTimeout: 2 * time.Second}),
		DNSTransport: NewDNSTransport(&DNSTransportConfig{LocalID: "me.example.", ControlZone: "control.example.", Timeout: 2 * time.Second}),
	}
	peer := NewPeer("peer.example.")
	peer.APIEndpoint = fmt.Sprintf("https://127.0.0.1:%d", port)
	withTLSA(peer, otherCert(t)) // nothing is ever presented to check it against
	addr := &Address{Host: "127.0.0.1", Port: uint16(port), Transport: "tcp"}
	peer.SetDiscoveryAddress(addr)
	peer.SetMechanismAddress("DNS", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// SelectTransport picks API; Send routes the DNS-only verb to DNS and
	// gives it no fallback.
	_, err = tm.Send(ctx, peer, &AppMessage{TypeToken: "keystate", Payload: []byte(`{}`)})
	if err == nil || !strings.Contains(err.Error(), "(DNS: ") || strings.Contains(err.Error(), "API: ") {
		t.Errorf("DNS-only verb: %v", err)
	}

	// A sync-family verb keeps its fallback: API first, then DNS.
	_, err = tm.Send(ctx, peer, &AppMessage{TypeToken: "sync", Payload: []byte(`{}`)})
	if err == nil || !strings.Contains(err.Error(), "(API: ") || !strings.Contains(err.Error(), "; DNS: ") {
		t.Errorf("sync-family verb: %v", err)
	}
}

// TestSendNoUsableTransport: when SelectTransport finds nothing, Send tries
// nothing and says why, instead of reporting failures that never happened.
func TestSendNoUsableTransport(t *testing.T) {
	peer := NewPeer("peer.example.")

	tm := &TransportManager{APITransport: NewAPITransport(&APITransportConfig{LocalID: "me.example."})}
	_, err := tm.Send(context.Background(), peer, &PingRequest{})
	if err == nil || !strings.Contains(err.Error(), "no usable transport for peer peer.example. (API: peer has no endpoint; DNS: not enabled)") {
		t.Errorf("API enabled, peer without endpoint: %v", err)
	}

	_, err = (&TransportManager{}).Send(context.Background(), peer, &PingRequest{})
	if err == nil || !strings.Contains(err.Error(), "(API: not enabled; DNS: not enabled)") {
		t.Errorf("no transports enabled: %v", err)
	}
}
