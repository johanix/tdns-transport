/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Confirmations over the HTTPS mechanism: the confirm payload a DNS
 * confirmation carries goes to /msg, a receiver that refuses it is a
 * retryable failure, and the manager sends a confirmation over DNS when
 * the API's fails, but not when the receiver took it and judged it.
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
	"strings"
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

// notAcceptedConfirm is what a receiver from before confirmations went
// over HTTPS answers one: its /msg takes the sync family only.
const notAcceptedConfirm = `message type "confirm" is not accepted on /api/v1/msg`

// msgReceiver is a TLS receiver of /msg that records what it was posted,
// under a lock, and takes it or, with a refusal set, refuses it with that
// message, as tdns-mp's /msg does: HTTP 200, Error set.
type msgReceiver struct {
	mu      sync.Mutex
	posts   []apiCapture
	refusal string
	srv     *httptest.Server
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
		refusal := rcv.refusal
		rcv.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if refusal != "" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"AgentId": "b.example.", "Status": "error",
				"Error": true, "ErrorMsg": refusal})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"AgentId": "b.example.", "Status": "ok", "Msg": "received", "Error": false})
	}))
	t.Cleanup(rcv.srv.Close)
	return rcv
}

// setRefuse makes the receiver answer as one from before confirmations
// went over HTTPS (refuse), or take what it is posted.
func (rcv *msgReceiver) setRefuse(refuse bool) {
	if refuse {
		rcv.refuseWith(notAcceptedConfirm)
		return
	}
	rcv.refuseWith("")
}

// refuseWith makes the receiver refuse what it is posted with msg; ""
// makes it take it.
func (rcv *msgReceiver) refuseWith(msg string) {
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	rcv.refusal = msg
}

func (rcv *msgReceiver) captured() []apiCapture {
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	return append([]apiCapture(nil), rcv.posts...)
}

// dnsChunkReceiver is a DNS server that records the CHUNK payload of every
// NOTIFY it gets and answers NOERROR; with confirm set, the answer carries
// an "ok" confirmation in a CHUNK option, as a receiver's answer to an
// application message does.
type dnsChunkReceiver struct {
	mu       sync.Mutex
	payloads [][]byte
	confirm  bool
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
		rcv.mu.Lock()
		confirm := rcv.confirm
		rcv.mu.Unlock()
		if confirm {
			m.SetEdns0(dns.DefaultMsgSize, false)
			opt := m.IsEdns0()
			opt.Option = append(opt.Option, edns0.CreateChunkOption(EnvelopeNone, nil, []byte(`{"type":"confirm","status":"ok","message":"received"}`)))
		}
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

func (rcv *dnsChunkReceiver) setConfirm(confirm bool) {
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	rcv.confirm = confirm
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
	peer := apiPeer(rcv.srv)
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
// retryable failure. Only a refusal from a receiver that took the
// confirmation and judged it is Answered: the manager sends the others
// over DNS, and not that one.
func TestAPIConfirmRefusalIsRetryable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rcv := newMsgReceiver(t)
	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, rcv.srv)
	var te *TransportError

	// A /msg that does not take confirmations did not judge this one: DNS
	// may carry it.
	rcv.setRefuse(true)
	err := tr.Confirm(ctx, apiPeer(rcv.srv), testConfirmRequest())
	if err == nil || !errors.As(err, &te) || !te.Retryable || te.Answered {
		t.Fatalf("a confirmation /msg does not take: %v, want a retryable *TransportError, not Answered", err)
	}

	// A /msg that took it and refused it has judged it: Answered, with the
	// receiver's reason.
	for _, judged := range []string{
		"not authorized",
		`sender "a.example." is not the client certificate's identity`,
	} {
		rcv.refuseWith(judged)
		err := tr.Confirm(ctx, apiPeer(rcv.srv), testConfirmRequest())
		if err == nil || !errors.As(err, &te) || !te.Retryable || !te.Answered {
			t.Fatalf("a confirmation refused with %q: %v, want a retryable, Answered *TransportError", judged, err)
		}
		if !strings.Contains(err.Error(), judged) {
			t.Errorf("error %q does not carry the refusal %q", err, judged)
		}
	}

	failing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}))
	defer failing.Close()
	ft := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, failing)
	err = ft.Confirm(ctx, apiPeer(failing), testConfirmRequest())
	if err == nil || !errors.As(err, &te) || !te.Retryable || te.Answered {
		t.Fatalf("a confirmation answered HTTP 503: %v, want a retryable *TransportError, not Answered", err)
	}

	// Failures that would not keep DNS from it are retryable too: an
	// endpoint that is not https, and a reply that is not JSON.
	plain := NewPeer("b.example.")
	plain.APIEndpoint = "http://127.0.0.1:1/api/v1"
	if err := tr.Confirm(ctx, plain, testConfirmRequest()); err == nil || !errors.As(err, &te) || !te.Retryable || te.Answered {
		t.Fatalf("a confirmation to an http endpoint: %v, want a retryable *TransportError, not Answered", err)
	}
	page := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>maintenance</html>"))
	}))
	defer page.Close()
	pt := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, page)
	if err := pt.Confirm(ctx, apiPeer(page), testConfirmRequest()); err == nil || !errors.As(err, &te) || !te.Retryable || te.Answered {
		t.Fatalf("a confirmation answered with a page: %v, want a retryable *TransportError, not Answered", err)
	}

	if err := tr.Confirm(ctx, NewPeer("nowhere.example."), testConfirmRequest()); err == nil {
		t.Fatal("a confirmation to a peer without an API endpoint must fail")
	}
}

// A confirmation the receiver took over HTTPS and judged is not sent again
// over DNS: the receiver would refuse it again (tdns-transport #36). The
// refusal comes back, Answered.
func TestManagerJudgedConfirmDoesNotFallBack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rcv := newMsgReceiver(t)
	dnsRcv := newDNSChunkReceiver(t)
	tm := &TransportManager{
		APITransport: apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, rcv.srv),
		DNSTransport: NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example.", Timeout: 2 * time.Second}),
	}
	peer := apiPeer(rcv.srv)
	peer.SetDiscoveryAddress(dnsRcv.addr)
	peer.SetMechanismAddress("DNS", dnsRcv.addr)

	for i, judged := range []string{
		"not authorized",
		`sender "a.example." is not the client certificate's identity`,
	} {
		rcv.refuseWith(judged)
		err := tm.Confirm(ctx, peer, testConfirmRequest())
		var te *TransportError
		if err == nil || !errors.As(err, &te) || !te.Answered {
			t.Fatalf("a confirmation refused with %q: %v, want an Answered *TransportError", judged, err)
		}
		if !strings.Contains(err.Error(), judged) {
			t.Errorf("error %q does not carry the refusal %q", err, judged)
		}
		if api, dns := len(rcv.captured()), len(dnsRcv.received()); api != i+1 || dns != 0 {
			t.Fatalf("refused with %q: %d POSTs, %d NOTIFYs; want %d and 0", judged, api, dns, i+1)
		}
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
	peer := apiPeer(rcv.srv)
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
	peer := apiPeer(hanging)
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
