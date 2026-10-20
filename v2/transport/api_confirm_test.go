/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Confirmations over the HTTPS mechanism: the confirm payload a DNS
 * confirmation carries goes to /msg, a receiver that refuses it is a
 * retryable failure, and the manager sends a confirmation over DNS when
 * the API's fails.
 */

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// testConfirmRequest is a confirmation with every field the payload
// carries set: the confirmer a.example. tells b.example. what became of
// its SYNC.
func testConfirmRequest() *ConfirmRequest {
	return &ConfirmRequest{
		SenderID:       "a.example.",
		Zone:           "z.example.",
		DistributionID: "d-1",
		Nonce:          "n-1",
		Status:         ConfirmPartial,
		Message:        "one of two applied",
		AppliedRecords: []string{"z.example.\t3600\tIN\tNS\tns1.b.example."},
		RemovedRecords: []string{"z.example.\t3600\tIN\tNS\tns0.b.example."},
		RejectedItems:  []RejectedItemDTO{{Record: "z.example.\t3600\tIN\tNS\tns2.b.example.", Reason: "not authorized"}},
		IgnoredRecords: []string{"z.example.\t3600\tIN\tNS\tns3.b.example."},
		Truncated:      true,
		Timestamp:      time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

// msgReceiver is a TLS receiver of /msg that records what it was posted,
// under a lock, and takes it or, with refuse set, refuses it.
type msgReceiver struct {
	mu     sync.Mutex
	posts  []apiCapture
	refuse bool
	srv    *httptest.Server
}

func newMsgReceiver(t *testing.T) *msgReceiver {
	t.Helper()
	rcv := &msgReceiver{}
	rcv.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r.Body); err != nil {
			t.Errorf("read body: %v", err)
		}
		rcv.mu.Lock()
		rcv.posts = append(rcv.posts, apiCapture{path: r.URL.Path, body: buf.Bytes()})
		refuse := rcv.refuse
		rcv.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if refuse {
			// What a receiver from before this change answers: /msg takes
			// the sync family only.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"AgentId": "b.example.", "Status": "error",
				"Error": true, "ErrorMsg": `message type "confirm" is not accepted on /api/v1/msg`})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"AgentId": "b.example.", "Status": "ok", "Msg": "received", "Error": false})
	}))
	t.Cleanup(rcv.srv.Close)
	return rcv
}

func (rcv *msgReceiver) setRefuse(refuse bool) {
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	rcv.refuse = refuse
}

func (rcv *msgReceiver) captured() []apiCapture {
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	return append([]apiCapture(nil), rcv.posts...)
}

// dnsChunkReceiver is a DNS server that records the CHUNK payload of every
// NOTIFY it gets and answers NOERROR.
type dnsChunkReceiver struct {
	mu       sync.Mutex
	payloads [][]byte
	addr     *Address
}

func newDNSChunkReceiver(t *testing.T) *dnsChunkReceiver {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rcv := &dnsChunkReceiver{addr: &Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp"}}
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if opt := r.IsEdns0(); opt != nil && r.Opcode == dns.OpcodeNotify {
			for _, o := range opt.Option {
				local, ok := o.(*dns.EDNS0_LOCAL)
				if !ok || local.Code != edns0.EDNS0_CHUNK_OPTION_CODE {
					continue
				}
				chunk, err := edns0.ParseChunkOption(local)
				if err != nil {
					t.Errorf("unparseable CHUNK option: %v", err)
					continue
				}
				rcv.mu.Lock()
				rcv.payloads = append(rcv.payloads, chunk.Data)
				rcv.mu.Unlock()
			}
		}
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})
	return rcv
}

func (rcv *dnsChunkReceiver) received() [][]byte {
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	return append([][]byte(nil), rcv.payloads...)
}

func confirmGolden(t *testing.T) []byte {
	t.Helper()
	golden, err := os.ReadFile("testdata/golden-wire/confirm.json")
	if err != nil {
		t.Fatal(err)
	}
	return golden
}

// A confirmation over HTTPS is the DNS confirmation's payload, byte for
// byte, posted to /msg; the receiver routes it to the same handler.
func TestAPIConfirmPostsTheDNSConfirmPayload(t *testing.T) {
	golden := confirmGolden(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The DNS mechanism's NOTIFY carries the golden bytes.
	dnsRcv := newDNSChunkReceiver(t)
	dnsPeer := NewPeer("b.example.")
	dnsPeer.SetDiscoveryAddress(dnsRcv.addr)
	dt := NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example.", Timeout: 2 * time.Second})
	if err := dt.Confirm(ctx, dnsPeer, testConfirmRequest()); err != nil {
		t.Fatalf("DNS Confirm: %v", err)
	}
	if got := dnsRcv.received(); len(got) != 1 || !bytes.Equal(got[0], golden) {
		t.Fatalf("DNS confirm payload:\n got  %q\n want %s", got, golden)
	}

	// The HTTPS mechanism posts the same bytes to /msg.
	rcv := newMsgReceiver(t)
	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, rcv.srv)
	peer := apiPeer(rcv.srv.URL)
	if err := tr.Confirm(ctx, peer, testConfirmRequest()); err != nil {
		t.Fatalf("API Confirm: %v", err)
	}
	posts := rcv.captured()
	if len(posts) != 1 || posts[0].path != "/api/v1/msg" {
		t.Fatalf("posted %+v, want one POST to /api/v1/msg", posts)
	}
	if !bytes.Equal(posts[0].body, golden) {
		t.Errorf("API confirm body differs from the DNS confirm payload:\n got  %s\n want %s", posts[0].body, golden)
	}
	if _, sent, _ := peer.Stats.GetStats(); sent != 1 {
		t.Errorf("the peer's stats count %d messages sent, want 1", sent)
	}
}

// A receiver that refuses the confirmation, or does not answer it, is a
// retryable failure: the manager may then send it over DNS.
func TestAPIConfirmRefusalIsRetryable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rcv := newMsgReceiver(t)
	rcv.setRefuse(true)
	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, rcv.srv)
	err := tr.Confirm(ctx, apiPeer(rcv.srv.URL), testConfirmRequest())
	var te *TransportError
	if err == nil || !errors.As(err, &te) || !te.Retryable {
		t.Fatalf("a refused confirmation: %v, want a retryable *TransportError", err)
	}

	failing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}))
	defer failing.Close()
	ft := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, failing)
	err = ft.Confirm(ctx, apiPeer(failing.URL), testConfirmRequest())
	if err == nil || !errors.As(err, &te) || !te.Retryable {
		t.Fatalf("a confirmation answered HTTP 503: %v, want a retryable *TransportError", err)
	}

	// Failures that would not keep DNS from it are retryable too: an
	// endpoint that is not https, and a reply that is not JSON.
	plain := NewPeer("b.example.")
	plain.APIEndpoint = "http://127.0.0.1:1/api/v1"
	if err := tr.Confirm(ctx, plain, testConfirmRequest()); err == nil || !errors.As(err, &te) || !te.Retryable {
		t.Fatalf("a confirmation to an http endpoint: %v, want a retryable *TransportError", err)
	}
	page := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>maintenance</html>"))
	}))
	defer page.Close()
	pt := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, page)
	if err := pt.Confirm(ctx, apiPeer(page.URL), testConfirmRequest()); err == nil || !errors.As(err, &te) || !te.Retryable {
		t.Fatalf("a confirmation answered with a page: %v, want a retryable *TransportError", err)
	}

	if err := tr.Confirm(ctx, NewPeer("nowhere.example."), testConfirmRequest()); err == nil {
		t.Fatal("a confirmation to a peer without an API endpoint must fail")
	}
}

// The manager sends a confirmation over the API when the peer offers it,
// over DNS when the API's fails (a receiver from before this change
// refuses it), and over DNS first when the peer prefers DNS.
func TestManagerConfirmPrefersAPIFallsBackToDNS(t *testing.T) {
	golden := confirmGolden(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rcv := newMsgReceiver(t)
	dnsRcv := newDNSChunkReceiver(t)
	tm := &TransportManager{
		APITransport: apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, rcv.srv),
		DNSTransport: NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example.", Timeout: 2 * time.Second}),
	}
	peer := apiPeer(rcv.srv.URL)
	peer.SetDiscoveryAddress(dnsRcv.addr)
	peer.SetMechanismAddress("DNS", dnsRcv.addr)

	// The API takes it; DNS is not tried.
	if err := tm.Confirm(ctx, peer, testConfirmRequest()); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if api, dns := len(rcv.captured()), len(dnsRcv.received()); api != 1 || dns != 0 {
		t.Fatalf("API accepted: %d POSTs, %d NOTIFYs; want 1 and 0", api, dns)
	}

	// The receiver refuses it over HTTPS; the NOTIFY carries it.
	rcv.setRefuse(true)
	if err := tm.Confirm(ctx, peer, testConfirmRequest()); err != nil {
		t.Fatalf("Confirm with the API refusing: %v", err)
	}
	notifies := dnsRcv.received()
	if api := len(rcv.captured()); api != 2 || len(notifies) != 1 {
		t.Fatalf("API refused: %d POSTs, %d NOTIFYs; want 2 and 1", api, len(notifies))
	}
	if !bytes.Equal(notifies[0], golden) {
		t.Errorf("the fallback NOTIFY carried %s, want %s", notifies[0], golden)
	}

	// A peer that prefers DNS gets the NOTIFY first.
	rcv.setRefuse(false)
	peer.SetPreferredTransport("DNS")
	if err := tm.Confirm(ctx, peer, testConfirmRequest()); err != nil {
		t.Fatalf("Confirm to a peer that prefers DNS: %v", err)
	}
	if api, dns := len(rcv.captured()), len(dnsRcv.received()); api != 2 || dns != 2 {
		t.Fatalf("DNS preferred: %d POSTs, %d NOTIFYs; want 2 and 2", api, dns)
	}

	if err := tm.Confirm(ctx, peer, nil); err == nil {
		t.Error("an empty confirmation must fail")
	}
}

// A peer whose HTTPS endpoint hangs leaves the DNS fallback time: the API
// try gets half of the caller's time, not all of it, though its own
// timeout is longer.
func TestManagerConfirmHangingAPILeavesDNSTime(t *testing.T) {
	release := make(chan struct{})
	hanging := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(hanging.Close)
	t.Cleanup(func() { close(release) })
	dnsRcv := newDNSChunkReceiver(t)
	tm := &TransportManager{
		APITransport: apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 10 * time.Second}, hanging),
		DNSTransport: NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example.", Timeout: 2 * time.Second}),
	}
	peer := apiPeer(hanging.URL)
	peer.SetDiscoveryAddress(dnsRcv.addr)
	peer.SetMechanismAddress("DNS", dnsRcv.addr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tm.Confirm(ctx, peer, testConfirmRequest()); err != nil {
		t.Fatalf("Confirm with the API hanging: %v", err)
	}
	if got := dnsRcv.received(); len(got) != 1 {
		t.Fatalf("%d NOTIFYs, want the fallback's one", len(got))
	}
}

// A peer that DNS alone reaches keeps all the caller's time for the NOTIFY:
// with no endpoint for the API there is no fallback to leave time for.
func TestManagerConfirmDNSOnlyPeerKeepsAllItsTime(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(1500 * time.Millisecond) // more than half the caller's time
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})
	tm := &TransportManager{
		APITransport: NewAPITransport(&APITransportConfig{LocalID: "a.example."}),
		DNSTransport: NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example.", Timeout: 3 * time.Second}),
	}
	peer := NewPeer("b.example.")
	peer.SetDiscoveryAddress(&Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp"})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tm.Confirm(ctx, peer, testConfirmRequest()); err != nil {
		t.Fatalf("Confirm to a peer only DNS reaches: %v", err)
	}
}
