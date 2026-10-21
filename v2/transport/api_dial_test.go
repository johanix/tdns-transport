/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The HTTPS mechanism dials the API address discovery found for a peer,
 * not what the endpoint's host name resolves to: a host need not have a
 * system resolver. The name stays in the URL and TLS uses it.
 */

package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// namedServer is a TLS receiver whose certificate names only name (an
// .invalid name, which no resolver answers). It counts the requests it
// serves and the connections that close.
type namedServer struct {
	srv    *httptest.Server
	served atomic.Int32
	opened atomic.Int32
	closed atomic.Int32
}

func newNamedServer(t *testing.T, name string) *namedServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ns := &namedServer{}
	ns.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ns.served.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Status":"ok","MyIdentity":"b.example.","Error":false}`))
	}))
	ns.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	ns.srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			ns.opened.Add(1)
		case http.StateClosed:
			ns.closed.Add(1)
		}
	}
	ns.srv.StartTLS()
	t.Cleanup(ns.srv.Close)
	return ns
}

func (ns *namedServer) address() *Address {
	tcp := ns.srv.Listener.Addr().(*net.TCPAddr)
	return &Address{Host: tcp.IP.String(), Port: uint16(tcp.Port), Transport: "https"}
}

// discoveredPeer is b.example. as discovery registers it: an endpoint with
// a host name and the address discovery found for it.
func discoveredPeer(name string, port uint16, addr *Address, certs ...*x509.Certificate) *Peer {
	p := NewPeer("b.example.")
	p.APIEndpoint = "https://" + net.JoinHostPort(name, strconv.Itoa(int(port))) + "/api/v1"
	p.SetMechanismAddress("API", addr)
	return withTLSA(p, certs...)
}

// A peer whose endpoint name no resolver answers is reached at the address
// discovery found. Before this change the request failed on the name's
// lookup.
func TestAPIDialsTheDiscoveredAddress(t *testing.T) {
	const name = "api.b.invalid"
	ns := newNamedServer(t, name)
	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, ns.srv)
	peer := discoveredPeer(name, ns.address().Port, ns.address(), ns.srv.Certificate())
	ctx := context.Background()

	hello, err := tr.Hello(ctx, peer, &HelloRequest{SenderID: "a.example."})
	if err != nil || !hello.Accepted {
		t.Fatalf("Hello to %s at %s: %+v %v", name, ns.address().HostPort(), hello, err)
	}
	if ping, err := tr.Ping(ctx, peer, &PingRequest{SenderID: "a.example."}); err != nil || ping == nil {
		t.Fatalf("Ping: %+v %v", ping, err)
	}
	if n := ns.served.Load(); n != 2 {
		t.Errorf("the server served %d requests, want 2", n)
	}
}

// TLS still checks the endpoint's name: an address whose server holds a
// certificate for another name is refused.
func TestAPIKeepsTheNameForTLS(t *testing.T) {
	ns := newNamedServer(t, "api.other.invalid")
	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, ns.srv)
	peer := discoveredPeer("api.b.invalid", ns.address().Port, ns.address(), ns.srv.Certificate())
	_, err := tr.Hello(context.Background(), peer, &HelloRequest{SenderID: "a.example."})
	var mismatch x509.HostnameError
	if !errors.As(err, &mismatch) {
		t.Fatalf("a certificate for another name: %v, want a host name mismatch", err)
	}
	if n := ns.served.Load(); n != 0 {
		t.Errorf("the server served %d requests, want none", n)
	}
}

// When discovery finds a new address, the next request goes there, not
// over a kept-alive connection to the old one, and the idle connection to
// the old one is closed.
func TestAPIDialsTheNewAddressAfterRediscovery(t *testing.T) {
	const name = "api.b.invalid"
	old, fresh := newNamedServer(t, name), newNamedServer(t, name)
	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, old.srv, fresh.srv)
	peer := discoveredPeer(name, old.address().Port, old.address(), old.srv.Certificate(), fresh.srv.Certificate())
	ctx := context.Background()

	if _, err := tr.Hello(ctx, peer, &HelloRequest{SenderID: "a.example."}); err != nil {
		t.Fatalf("Hello at the old address: %v", err)
	}
	// Rediscovery: the same name, a new address. The URL's port is the old
	// server's; the address is what is dialed.
	peer.SetMechanismAddress("API", fresh.address())
	if _, err := tr.Hello(ctx, peer, &HelloRequest{SenderID: "a.example."}); err != nil {
		t.Fatalf("Hello at the new address: %v", err)
	}
	if o, f := old.served.Load(), fresh.served.Load(); o != 1 || f != 1 {
		t.Fatalf("the old address served %d requests and the new one %d, want 1 and 1", o, f)
	}
	deadline := time.Now().Add(2 * time.Second)
	for old.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if old.closed.Load() == 0 {
		t.Error("the idle connection to the old address is still open")
	}
}

// When the peer's TLSA set changes, its idle connections, checked under the
// old set, are closed: the next request is checked against the new one.
func TestAPIClosesIdleConnectionsWhenTheTLSAChanges(t *testing.T) {
	const name = "api.b.invalid"
	ns := newNamedServer(t, name)
	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, ns.srv)
	peer := discoveredPeer(name, ns.address().Port, ns.address(), ns.srv.Certificate())
	if _, err := tr.Hello(context.Background(), peer, &HelloRequest{SenderID: "a.example."}); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	withTLSA(peer, ns.srv.Certificate(), otherCertFor(t)) // a rollover adds a record
	if _, err := tr.Hello(context.Background(), peer, &HelloRequest{SenderID: "a.example."}); err != nil {
		t.Fatalf("Hello after the TLSA changed: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for ns.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ns.closed.Load() == 0 {
		t.Error("the idle connection checked under the old TLSA set is still open")
	}
}

func otherCertFor(t *testing.T) *x509.Certificate { return otherCert(t) }
