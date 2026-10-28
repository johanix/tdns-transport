package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sendOnRig is a manager with both transports and b.example., whom the API
// reaches at rcv (SelectTransport picks it) and DNS at dnsRcv, which
// confirms what it is sent.
func sendOnRig(t *testing.T) (*TransportManager, *msgReceiver, *dnsChunkReceiver, *Peer) {
	t.Helper()
	rcv := newMsgReceiver(t)
	dnsRcv := newDNSChunkReceiver(t)
	dnsRcv.setConfirm(true)
	tm := &TransportManager{
		APITransport: apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, rcv.srv),
		DNSTransport: NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example.", Timeout: 2 * time.Second}),
	}
	peer := apiPeer(rcv.srv)
	setDNSCarrier(t, peer, dnsRcv.addr)
	peer.SetMechanismAddress("DNS", dnsRcv.addr)
	return tm, rcv, dnsRcv, peer
}

func configAnswer() *AppMessage {
	return &AppMessage{TypeToken: "config", Payload: []byte(`{}`)}
}

// sent fails t unless rcv has had posts POSTs and dnsRcv notifies NOTIFYs.
func sent(t *testing.T, what string, rcv *msgReceiver, dnsRcv *dnsChunkReceiver, posts, notifies int) {
	t.Helper()
	if api, dns := len(rcv.captured()), len(dnsRcv.received()); api != posts || dns != notifies {
		t.Fatalf("%s: %d POSTs, %d NOTIFYs; want %d and %d", what, api, dns, posts, notifies)
	}
}

// An answer goes back on the mechanism its request came on, whatever
// SelectTransport would pick; with the mechanism not known, or not
// reaching the peer, the first choice is SelectTransport's.
func TestSendOnAnswersOnTheRequestsMechanism(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tm, rcv, dnsRcv, peer := sendOnRig(t)
	if got := tm.SelectTransport(peer); got != Transport(tm.APITransport) {
		t.Fatalf("SelectTransport picked %v, want the API", got)
	}

	_, out, err := tm.SendOn(ctx, peer, MechanismDNS, configAnswer())
	if err != nil || out != (SendOutcome{First: "DNS", Carrier: "DNS"}) {
		t.Fatalf("a request over DNS: outcome %+v, err %v; want DNS first and carrying", out, err)
	}
	sent(t, "a request over DNS", rcv, dnsRcv, 0, 1)

	_, out, err = tm.SendOn(ctx, peer, MechanismAPI, configAnswer())
	if err != nil || out != (SendOutcome{First: "API", Carrier: "API"}) {
		t.Fatalf("a request over HTTPS: outcome %+v, err %v; want the API first and carrying", out, err)
	}
	sent(t, "a request over HTTPS", rcv, dnsRcv, 1, 1)

	_, out, err = tm.SendOn(ctx, peer, "", configAnswer())
	if err != nil || out != (SendOutcome{First: "API", Carrier: "API"}) {
		t.Fatalf("the mechanism not known: outcome %+v, err %v; want SelectTransport's API", out, err)
	}
	sent(t, "the mechanism not known", rcv, dnsRcv, 2, 1)

	// DNS has no address for this peer: the answer goes over the API.
	noDNS := apiPeer(rcv.srv)
	_, out, err = tm.SendOn(ctx, noDNS, MechanismDNS, configAnswer())
	if err != nil || out != (SendOutcome{First: "API", Carrier: "API"}) {
		t.Fatalf("DNS not reaching the peer: outcome %+v, err %v; want the API first and carrying", out, err)
	}
	sent(t, "DNS not reaching the peer", rcv, dnsRcv, 3, 1)
	if n := noDNS.MechanismConsecutiveFails(MechanismDNS); n != 0 {
		t.Errorf("DNS, not tried, has %d failures counted, want 0", n)
	}
}

// A /msg that does not take the verb has judged nothing: the answer, or the
// confirmation, goes over DNS. The API delivered it, so no failure is
// counted against it (tdns-mp #270's S1).
func TestSendOnVerbNotAcceptedFallsBack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tm, rcv, dnsRcv, peer := sendOnRig(t)

	posts, notifies := 0, 0
	for _, verb := range []string{"config", "audit"} {
		rcv.refuseWith(`message type "` + verb + `" is not accepted on /api/v1/msg`)
		resp, out, err := tm.SendOn(ctx, peer, MechanismAPI, &AppMessage{TypeToken: verb, Payload: []byte(`{}`)})
		posts++
		notifies++
		if err != nil {
			t.Fatalf("%s not accepted on /msg: %v, want it sent over DNS", verb, err)
		}
		if ar, ok := resp.(*AppResponse); !ok || ar.Status != ConfirmSuccess {
			t.Errorf("%s not accepted on /msg: resp %+v, want DNS's ConfirmSuccess", verb, resp)
		}
		var te *TransportError
		if out.First != "API" || out.Carrier != "DNS" || !errors.As(out.FirstErr, &te) || !te.NotAccepted {
			t.Errorf("%s not accepted on /msg: outcome %+v, want the API first, NotAccepted, and DNS carrying", verb, out)
		}
		sent(t, verb+" not accepted on /msg", rcv, dnsRcv, posts, notifies)
	}

	rcv.setRefuse(true)
	_, out, err := tm.SendOn(ctx, peer, MechanismAPI, testConfirmRequest())
	posts++
	notifies++
	if err != nil || out.Carrier != "DNS" {
		t.Fatalf("confirm not accepted on /msg: outcome %+v, err %v; want it sent over DNS", out, err)
	}
	sent(t, "confirm not accepted on /msg", rcv, dnsRcv, posts, notifies)

	if n := peer.MechanismConsecutiveFails(MechanismAPI); n != 0 {
		t.Errorf("the API has %d failures counted, want 0: it delivered every message", n)
	}
}

// A refusal the peer judged stays on the first mechanism: it is returned,
// Answered, DNS is not tried, and the count is neither raised nor cleared.
func TestSendOnJudgedRefusalStays(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tm, rcv, dnsRcv, peer := sendOnRig(t)
	peer.RecordMechanismFailure(MechanismAPI)

	rcv.refuseWith("not authorized")
	for i, req := range []interface{}{configAnswer(), testConfirmRequest()} {
		resp, out, err := tm.SendOn(ctx, peer, MechanismAPI, req)
		var te *TransportError
		if err == nil || !errors.As(err, &te) || !te.Answered {
			t.Fatalf("%T refused: %v, want an Answered *TransportError", req, err)
		}
		if out.First != "API" || out.Carrier != "" || out.Refuser != "API" || !transportErrorAnswered(out.FirstErr) {
			t.Errorf("%T refused: outcome %+v, want the API first and refusing, Answered, and nothing carrying", req, out)
		}
		if _, isApp := req.(*AppMessage); isApp {
			if ar, ok := resp.(*AppResponse); !ok || ar.Status != ConfirmFailed || ar.Message != "not authorized" {
				t.Errorf("config refused: resp %+v, want the ConfirmFailed AppResponse", resp)
			}
		}
		sent(t, "refused", rcv, dnsRcv, i+1, 0)
	}
	if n := peer.MechanismConsecutiveFails(MechanismAPI); n != 1 {
		t.Errorf("the API has %d failures counted, want the 1 from before", n)
	}
}

// A first choice that fails to deliver, and a fallback whose recipient
// refuses the message: the outcome names the fallback as the refuser, the
// fallback's ConfirmFailed response comes back, and only the first's
// failure is counted.
func TestSendOnRefusalOnTheFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tm, rcv, dnsRcv, peer := sendOnRig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := &Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp"}
	ln.Close() // nothing listens there: every NOTIFY is refused
	setDNSCarrier(t, peer, dead)
	peer.SetMechanismAddress("DNS", dead)
	rcv.refuseWith("not authorized")

	resp, out, err := tm.SendOn(ctx, peer, MechanismDNS, configAnswer())
	if err == nil {
		t.Fatal("a refused answer came back without an error")
	}
	if out.First != "DNS" || out.FirstErr == nil || out.Carrier != "" || out.Refuser != "API" {
		t.Fatalf("DNS failing, the API refusing: outcome %+v, want DNS failing and the API refusing", out)
	}
	if ar, ok := resp.(*AppResponse); !ok || ar.Status != ConfirmFailed || ar.Message != "not authorized" {
		t.Errorf("resp %+v, want the API's ConfirmFailed response", resp)
	}
	sent(t, "DNS failing, the API refusing", rcv, dnsRcv, 1, 0)
	if d, a := peer.MechanismConsecutiveFails(MechanismDNS), peer.MechanismConsecutiveFails(MechanismAPI); d != 1 || a != 0 {
		t.Errorf("counts: DNS %d, API %d; want 1 and 0", d, a)
	}
}

// A failure to deliver on the first choice is counted against it and the
// other mechanism carries the message; the mechanism that carries it, first
// or other, has its count cleared (tdns-mp #236).
func TestSendOnCountsAFailureToDeliver(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tm, rcv, dnsRcv, peer := sendOnRig(t)
	peer.RecordMechanismFailure(MechanismAPI)
	peer.RecordMechanismFailure(MechanismAPI)
	peer.RecordMechanismFailure(MechanismDNS)

	if _, _, err := tm.SendOn(ctx, peer, MechanismAPI, configAnswer()); err != nil {
		t.Fatalf("SendOn: %v", err)
	}
	if n := peer.MechanismConsecutiveFails(MechanismAPI); n != 0 {
		t.Fatalf("after the API carried the answer: %d failures counted, want 0", n)
	}

	rcv.srv.Close() // the API now refuses every connection
	_, out, err := tm.SendOn(ctx, peer, MechanismAPI, configAnswer())
	if err != nil || out.First != "API" || out.Carrier != "DNS" || out.FirstErr == nil {
		t.Fatalf("the API refusing connections: outcome %+v, err %v; want the API failing and DNS carrying", out, err)
	}
	sent(t, "the API refusing connections", rcv, dnsRcv, 1, 1)
	if n := peer.MechanismConsecutiveFails(MechanismAPI); n != 1 {
		t.Errorf("the API has %d failures counted, want 1", n)
	}
	if n := peer.MechanismConsecutiveFails(MechanismDNS); n != 0 {
		t.Errorf("DNS, the fallback that carried it, has %d failures counted, want its 1 cleared", n)
	}
}

// A mechanism that does not reach the peer is no fallback: an API endpoint
// with no TLSA to check the peer's certificate against is not tried when
// DNS fails, and DNS's failure is counted.
func TestSendOnNoFallbackThatDoesNotReach(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tm, rcv, dnsRcv, peer := sendOnRig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := &Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp"}
	ln.Close() // nothing listens there: every NOTIFY is refused
	setDNSCarrier(t, peer, dead)
	peer.SetMechanismAddress("DNS", dead)
	peer.SetMechanismTLSA("API", TLSASet{})

	_, out, err := tm.SendOn(ctx, peer, MechanismDNS, testConfirmRequest())
	if err == nil || out.First != "DNS" || out.Carrier != "" || strings.Contains(err.Error(), "API: ") {
		t.Fatalf("DNS refused, the API with no TLSA: outcome %+v, err %v; want DNS failing and the API not tried", out, err)
	}
	sent(t, "DNS refused, the API with no TLSA", rcv, dnsRcv, 0, 0)
	if n := peer.MechanismConsecutiveFails(MechanismDNS); n != 1 {
		t.Errorf("DNS has %d failures counted, want 1", n)
	}
}

// An answer is sent once: a first choice that hangs gets half the caller's
// time, and the other mechanism the rest.
func TestSendOnHangingFirstChoiceLeavesTheOtherTime(t *testing.T) {
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
	dnsRcv.setConfirm(true)
	tm := &TransportManager{
		APITransport: apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 10 * time.Second}, hanging),
		DNSTransport: NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example.", Timeout: 2 * time.Second}),
	}
	peer := apiPeer(hanging)
	setDNSCarrier(t, peer, dnsRcv.addr)
	peer.SetMechanismAddress("DNS", dnsRcv.addr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, out, err := tm.SendOn(ctx, peer, MechanismAPI, configAnswer())
	if err != nil || out.Carrier != "DNS" {
		t.Fatalf("the API hanging: outcome %+v, err %v; want DNS carrying", out, err)
	}
	if got := dnsRcv.received(); len(got) != 1 {
		t.Fatalf("%d NOTIFYs, want the fallback's one", len(got))
	}
	if n := peer.MechanismConsecutiveFails(MechanismAPI); n != 1 {
		t.Errorf("the API has %d failures counted, want 1", n)
	}
}

// Only a failure to deliver is counted: not a judged refusal, not a verb
// the mechanism does not carry, and not an error that would hit the other
// mechanism too.
func TestUndelivered(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"a plain error", errors.New("boom"), true},
		{"retryable", NewTransportError("API", "config", "b.example.", errors.New("connection refused"), true), true},
		{"non-retryable", NewTransportError("DNS", "config", "b.example.", errors.New("no address available"), false), false},
		{"answered", NewAnsweredTransportError("API", "config", "b.example.", errors.New("not authorized")), false},
		{"not accepted", NewNotAcceptedTransportError("API", "config", "b.example.", errors.New("not accepted")), false},
	} {
		if got := undelivered(tc.err); got != tc.want {
			t.Errorf("undelivered(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
