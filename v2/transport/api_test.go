/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The HTTPS mechanism against a receiver in the sync API's dialect
 * (cleanup plan step 5): the bodies it posts are the DNS wire structs, byte
 * for byte, an application message goes verbatim to /msg, and the
 * receiver's reply object maps onto the transport's responses.
 */

package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

type apiCapture struct {
	path string
	body []byte
}

// A receiver that records what it was posted and answers in the sync
// API's dialect.
func apiReceiver(t *testing.T, captured *[]apiCapture, reply func(path string, body []byte) interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		*captured = append(*captured, apiCapture{path: r.URL.Path, body: body})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply(r.URL.Path, body))
	}))
}

// apiClient is an APITransport that trusts the given test servers' certificates.
func apiClient(cfg *APITransportConfig, servers ...*httptest.Server) *APITransport {
	pool := x509.NewCertPool()
	for _, srv := range servers {
		pool.AddCert(srv.Certificate())
	}
	cfg.TLSConfig = &tls.Config{RootCAs: pool}
	return NewAPITransport(cfg)
}

func apiPeer(url string) *Peer {
	p := NewPeer("b.example.")
	p.APIEndpoint = url + "/api/v1"
	return p
}

func TestAPIOwnVerbsPostTheWireStructs(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	var captured []apiCapture
	srv := apiReceiver(t, &captured, func(path string, body []byte) interface{} {
		switch path {
		case "/api/v1/hello":
			return map[string]interface{}{"Status": "ok", "MyIdentity": "b.example.", "YourIdentity": "a.example.", "Time": at, "Msg": "hi", "Error": false, "ErrorMsg": ""}
		case "/api/v1/beat":
			return map[string]interface{}{"Status": "ok", "MyIdentity": "b.example.", "Msg": "Hi there!", "Error": false}
		case "/api/v1/sync/ping":
			return map[string]interface{}{"Status": "ok", "MyIdentity": "b.example.", "Nonce": "n-1", "Error": false}
		}
		return map[string]interface{}{"Error": true, "ErrorMsg": "unexpected path " + path}
	})
	defer srv.Close()

	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 5 * time.Second}, srv)
	peer := apiPeer(srv.URL)
	ctx := context.Background()

	hello, err := tr.Hello(ctx, peer, &HelloRequest{SenderID: "a.example.", SharedZones: []string{"z.example.", "ignored.example."}, Timestamp: at})
	if err != nil || !hello.Accepted || hello.ResponderID != "b.example." {
		t.Fatalf("Hello: %+v %v", hello, err)
	}
	beat, err := tr.Beat(ctx, peer, &BeatRequest{SenderID: "a.example.", Timestamp: at, Zones: []string{"z1.example.", "z2.example."},
		Gossip: json.RawMessage(`[{"group_hash":"abc"}]`)})
	if err != nil || !beat.Ack {
		t.Fatalf("Beat: %+v %v", beat, err)
	}
	ping, err := tr.Ping(ctx, peer, &PingRequest{SenderID: "a.example.", Nonce: "n-1", Timestamp: at})
	if err != nil || !ping.OK {
		t.Fatalf("Ping: %+v %v", ping, err)
	}

	// The bodies are the DNS wire, byte for byte (testdata/golden-wire).
	want := map[string]string{"/api/v1/hello": "hello", "/api/v1/beat": "beat", "/api/v1/sync/ping": "ping"}
	if len(captured) != 3 {
		t.Fatalf("captured %d posts, want 3", len(captured))
	}
	for _, c := range captured {
		golden, err := os.ReadFile("testdata/golden-wire/" + want[c.path] + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(c.body, golden) {
			t.Errorf("%s body differs from the DNS wire:\n got  %s\n want %s", c.path, c.body, golden)
		}
	}
}

func TestAPIRejectionsAndNonce(t *testing.T) {
	var captured []apiCapture
	srv := apiReceiver(t, &captured, func(path string, body []byte) interface{} {
		switch path {
		case "/api/v1/hello":
			return map[string]interface{}{"MyIdentity": "b.example.", "Error": true, "ErrorMsg": "not a participant"}
		case "/api/v1/sync/ping":
			return map[string]interface{}{"Status": "ok", "Nonce": "other", "Error": false}
		}
		return map[string]interface{}{"Error": true}
	})
	defer srv.Close()
	tr := apiClient(&APITransportConfig{LocalID: "a.example."}, srv)
	peer := apiPeer(srv.URL)

	hello, err := tr.Hello(context.Background(), peer, &HelloRequest{SenderID: "a.example."})
	if err != nil || hello.Accepted || hello.RejectReason != "not a participant" {
		t.Fatalf("rejected hello: %+v %v", hello, err)
	}
	ping, err := tr.Ping(context.Background(), peer, &PingRequest{SenderID: "a.example.", Nonce: "n-1"})
	if err != nil || ping.OK {
		t.Fatalf("ping with the wrong nonce must not be OK: %+v %v", ping, err)
	}
	if _, err := tr.Hello(context.Background(), NewPeer("nowhere.example."), &HelloRequest{SenderID: "a.example."}); err == nil {
		t.Fatal("a peer without an API endpoint must fail")
	}
	if err := tr.Confirm(context.Background(), peer, &ConfirmRequest{}); err == nil {
		t.Fatal("Confirm over HTTPS must fail: there is no receiver")
	}
}

func TestAPISendAppPostsThePayloadVerbatim(t *testing.T) {
	var captured []apiCapture
	srv := apiReceiver(t, &captured, func(path string, body []byte) interface{} {
		return map[string]interface{}{"Status": "ok", "AgentId": "b.example.", "Msg": "received", "Error": false}
	})
	defer srv.Close()
	tr := apiClient(&APITransportConfig{LocalID: "a.example."}, srv)
	peer := apiPeer(srv.URL)

	payload := json.RawMessage(`{"MessageType":"rfi","OriginatorID":"a.example.","YourIdentity":"b.example.","Zone":"z.example.","RfiType":"CONFIG"}`)
	resp, err := tr.SendApp(context.Background(), peer, &AppMessage{Scope: "z.example.", TypeToken: "rfi", Payload: payload})
	if err != nil || resp.Status != ConfirmSuccess || resp.ResponderID != "b.example." || resp.Message != "received" {
		t.Fatalf("SendApp: %+v %v", resp, err)
	}
	if len(captured) != 1 || captured[0].path != "/api/v1/msg" || !bytes.Equal(captured[0].body, payload) {
		t.Fatalf("posted %+v, want the payload verbatim on /msg", captured)
	}
	if resp.DistributionID == "" {
		t.Error("SendApp must return a distribution id")
	}

	// A verb outside the sync family is refused before any request, retryably.
	_, err = tr.SendApp(context.Background(), peer, &AppMessage{TypeToken: "keystate", Payload: payload})
	var te *TransportError
	if err == nil || !errorsAs(err, &te) || !te.Retryable {
		t.Fatalf("keystate over HTTPS: %v", err)
	}
	if len(captured) != 1 {
		t.Fatal("a refused verb must not be posted")
	}
}

func errorsAs(err error, target **TransportError) bool {
	for err != nil {
		if te, ok := err.(*TransportError); ok {
			*target = te
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// Only https endpoints are posted to, and a redirect is not followed.
func TestAPIRefusesPlainHTTPAndRedirects(t *testing.T) {
	posted := 0
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { posted++ }))
	defer plain.Close()
	tr := NewAPITransport(&APITransportConfig{LocalID: "a.example."})
	if _, err := tr.Hello(context.Background(), apiPeer(plain.URL), &HelloRequest{SenderID: "a.example."}); err == nil {
		t.Fatal("an http endpoint must be refused")
	}
	if posted != 0 {
		t.Fatal("nothing may be posted to an http endpoint")
	}

	followed := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed++ }))
	defer target.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	rt := apiClient(&APITransportConfig{LocalID: "a.example."}, redirector, target)
	if _, err := rt.Hello(context.Background(), apiPeer(redirector.URL), &HelloRequest{SenderID: "a.example."}); err == nil {
		t.Fatal("a redirect must be refused")
	}
	if followed != 0 {
		t.Fatal("the redirect was followed")
	}
}

// A reply object without Status "ok" is not an acceptance.
func TestAPIEmptyReplyIsNotAccepted(t *testing.T) {
	var captured []apiCapture
	srv := apiReceiver(t, &captured, func(path string, body []byte) interface{} { return map[string]interface{}{} })
	defer srv.Close()
	tr := apiClient(&APITransportConfig{LocalID: "a.example."}, srv)
	hello, err := tr.Hello(context.Background(), apiPeer(srv.URL), &HelloRequest{SenderID: "a.example."})
	if err != nil || hello.Accepted {
		t.Fatalf("empty reply accepted: %+v %v", hello, err)
	}
	beat, err := tr.Beat(context.Background(), apiPeer(srv.URL), &BeatRequest{SenderID: "a.example."})
	if err != nil || beat.Ack {
		t.Fatalf("empty reply acked a beat: %+v %v", beat, err)
	}
}
