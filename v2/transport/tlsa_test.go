/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The HTTPS client checks the receiver's certificate against the receiver's
 * TLSA RRset: any record may match; no TLSA, no dial; a mismatch is refused
 * before any request; the set is looked up at each check, an unvalidated
 * answer refused unless validation is off, a denial empties it, a failed
 * lookup keeps it, and a mismatch is looked at once more past the cache.
 */

package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// tlsaFor is the 3 1 1 TLSA record that matches cert.
func tlsaFor(cert *x509.Certificate) *dns.TLSA {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return &dns.TLSA{Hdr: dns.RR_Header{Rrtype: dns.TypeTLSA, Class: dns.ClassINET},
		Usage: 3, Selector: 1, MatchingType: 1, Certificate: hex.EncodeToString(sum[:])}
}

// withTLSA gives p a validated TLSA set at its API TLSA name, one record
// per certificate, as discovery would store it.
func withTLSA(p *Peer, certs ...*x509.Certificate) *Peer {
	set := TLSASet{Owner: "_443._tcp.api." + p.ID, Validated: true}
	for _, c := range certs {
		set.Records = append(set.Records, tlsaFor(c))
	}
	p.SetMechanismTLSA("API", set)
	return p
}

// otherCert is a self-signed certificate with a key of its own.
func otherCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "other.invalid"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// fakeTLSA answers TLSA lookups in the order given; the last answer repeats.
type fakeTLSA struct {
	mu      sync.Mutex
	strict  bool
	answers []fakeAnswer
	fresh   []bool // the fresh flag of each lookup
}

type fakeAnswer struct {
	ans tlsaAnswer
	err error
}

func (f *fakeTLSA) lookupTLSA(_ context.Context, _ string, fresh bool) (tlsaAnswer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fresh = append(f.fresh, fresh)
	a := f.answers[0]
	if len(f.answers) > 1 {
		f.answers = f.answers[1:]
	}
	return a.ans, a.err
}

func (f *fakeTLSA) requireValidation() bool { return f.strict }

func (f *fakeTLSA) lookups() []bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]bool(nil), f.fresh...)
}

func okReply(string, []byte) interface{} {
	return map[string]interface{}{"Status": "ok", "MyIdentity": "b.example.", "Error": false}
}

// The TLSA is checked when the client also verifies by CA, as this one
// does: a certificate the CA accepts but no TLSA record names is refused,
// retryably, and the receiver sees no request.
func TestTLSAMismatchIsRefusedBeforeAnyRequest(t *testing.T) {
	var captured []apiCapture
	srv := apiReceiver(t, &captured, okReply)
	defer srv.Close()
	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, srv)
	peer := NewPeer("b.example.")
	peer.APIEndpoint = srv.URL + "/api/v1"
	withTLSA(peer, otherCert(t))

	_, err := tr.Hello(context.Background(), peer, &HelloRequest{SenderID: "a.example."})
	if !errors.Is(err, ErrTLSAMismatch) {
		t.Fatalf("a certificate no TLSA record names: %v, want ErrTLSAMismatch", err)
	}
	var te *TransportError
	if !errors.As(err, &te) || !te.Retryable {
		t.Errorf("the refusal is not a retryable *TransportError: %v", err)
	}
	if !strings.Contains(err.Error(), spkiSHA256Hex(srv.Certificate())) {
		t.Errorf("the error does not name the SPKI presented: %v", err)
	}
	if len(captured) != 0 {
		t.Errorf("the receiver got %d requests, want none", len(captured))
	}
}

// A certificate passes when it matches any record of the set: during a
// rollover the old and the new TLSA are published together.
func TestTLSAMatchesAnyRecordOfTheSet(t *testing.T) {
	var captured []apiCapture
	srv := apiReceiver(t, &captured, okReply)
	defer srv.Close()
	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, srv)
	peer := NewPeer("b.example.")
	peer.APIEndpoint = srv.URL + "/api/v1"
	withTLSA(peer, otherCert(t), srv.Certificate())

	if hello, err := tr.Hello(context.Background(), peer, &HelloRequest{SenderID: "a.example."}); err != nil || !hello.Accepted {
		t.Fatalf("a certificate matching the second record: %+v %v", hello, err)
	}
}

// With no TLSA the peer is not dialed, and the manager picks DNS.
func TestNoTLSAIsNotDialed(t *testing.T) {
	const name = "api.b.invalid"
	ns := newNamedServer(t, name)
	srv := ns.srv
	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, srv)
	peer := discoveredPeer(name, ns.address().Port, ns.address())

	_, err := tr.Hello(context.Background(), peer, &HelloRequest{SenderID: "a.example."})
	if !errors.Is(err, ErrNoTLSA) {
		t.Fatalf("a peer with no TLSA: %v, want ErrNoTLSA", err)
	}
	var te *TransportError
	if !errors.As(err, &te) || !te.Retryable {
		t.Errorf("the refusal is not a retryable *TransportError: %v", err)
	}
	if n := ns.opened.Load(); n != 0 {
		t.Errorf("%d connections opened to a peer with no TLSA, want none", n)
	}

	dnsT := NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example."})
	tm := &TransportManager{APITransport: tr, DNSTransport: dnsT}
	peer.SetDiscoveryAddress(&Address{Host: "127.0.0.1", Port: 53, Transport: "tcp"})
	if got := tm.SelectTransport(peer); got != Transport(dnsT) {
		t.Errorf("SelectTransport picked %v for a peer with no TLSA, want DNS", got)
	}
	withTLSA(peer, srv.Certificate())
	if got := tm.SelectTransport(peer); got != Transport(tr) {
		t.Errorf("SelectTransport picked %v for a peer with a TLSA, want API", got)
	}
}

// Where the check cannot be installed, nothing is sent: a proxy's address
// is not the peer's, so the client refuses rather than send unchecked.
func TestTLSACheckThatCannotBeInstalledRefuses(t *testing.T) {
	var captured []apiCapture
	srv := apiReceiver(t, &captured, okReply)
	defer srv.Close()
	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, srv)
	tr.HTTPClient.Transport.(*http.Transport).Proxy = http.ProxyFromEnvironment
	_, err := tr.Hello(context.Background(), apiPeer(srv), &HelloRequest{SenderID: "a.example."})
	if err == nil || !strings.Contains(err.Error(), "cannot check") {
		t.Fatalf("a client with a proxy: %v, want a refusal", err)
	}
	if len(captured) != 0 {
		t.Errorf("the receiver got %d requests, want none", len(captured))
	}
}

// An answer that DNSSEC has not validated is refused when validation is
// required, and accepted (with a warning) when it is not.
func TestTLSAUnvalidatedRefusedUnlessValidationIsOff(t *testing.T) {
	var captured []apiCapture
	srv := apiReceiver(t, &captured, okReply)
	defer srv.Close()
	unvalidated := fakeAnswer{ans: tlsaAnswer{Records: []*dns.TLSA{tlsaFor(srv.Certificate())}}}

	for _, strict := range []bool{true, false} {
		tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, srv)
		tr.TLSA.source = &fakeTLSA{strict: strict, answers: []fakeAnswer{unvalidated}}
		_, err := tr.Hello(context.Background(), apiPeer(srv), &HelloRequest{SenderID: "a.example."})
		if strict && !errors.Is(err, ErrTLSALookup) {
			t.Errorf("an unvalidated TLSA with validation required: %v, want ErrTLSALookup", err)
		}
		if !strict && err != nil {
			t.Errorf("an unvalidated TLSA with validation off: %v, want it accepted", err)
		}
	}
}

// A validated denial empties the set: the peer is not dialed again, and its
// API mechanism needs discovery. A failed lookup changes nothing.
func TestTLSADenialEmptiesTheSetAndAFailedLookupKeepsIt(t *testing.T) {
	var captured []apiCapture
	srv := apiReceiver(t, &captured, okReply)
	defer srv.Close()

	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, srv)
	tr.TLSA.source = &fakeTLSA{answers: []fakeAnswer{{err: errors.New("SERVFAIL")}}}
	peer := apiPeer(srv)
	peer.SetMechanismState("API", PeerStateOperational, "test")
	_, err := tr.Hello(context.Background(), peer, &HelloRequest{SenderID: "a.example."})
	if !errors.Is(err, ErrTLSALookup) {
		t.Fatalf("a failed lookup: %v, want ErrTLSALookup", err)
	}
	if !peer.HasMechanismTLSA("API") {
		t.Fatal("a failed lookup emptied the set")
	}

	tr.TLSA.source = &fakeTLSA{answers: []fakeAnswer{{ans: tlsaAnswer{Denied: true, Validated: true}}}}
	if _, err := tr.Hello(context.Background(), peer, &HelloRequest{SenderID: "a.example."}); !errors.Is(err, ErrNoTLSA) {
		t.Fatalf("a validated denial: %v, want ErrNoTLSA", err)
	}
	if peer.HasMechanismTLSA("API") {
		t.Error("a validated denial left the set")
	}
	if st, _ := peer.MechanismRawState("API"); st != PeerStateNeeded || !peer.mechanismNeedsDiscovery() {
		t.Errorf("after the withdrawal the API mechanism is %v, want NEEDED and up for discovery", st)
	}
	if _, err := tr.Hello(context.Background(), peer, &HelloRequest{SenderID: "a.example."}); !errors.Is(err, ErrNoTLSA) {
		t.Errorf("after the withdrawal: %v, want ErrNoTLSA without a dial", err)
	}
	if len(captured) != 0 {
		t.Errorf("the receiver got %d requests, want none", len(captured))
	}
}

// A mismatch is looked at once more past the cache, which may hold the set
// from before a rotation, and not again within the recheck interval.
func TestTLSAMismatchLooksAgainPastTheCache(t *testing.T) {
	var captured []apiCapture
	srv := apiReceiver(t, &captured, okReply)
	defer srv.Close()
	old := tlsaAnswer{Records: []*dns.TLSA{tlsaFor(otherCert(t))}, Validated: true}
	rotated := tlsaAnswer{Records: []*dns.TLSA{tlsaFor(srv.Certificate())}, Validated: true}

	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, srv)
	src := &fakeTLSA{answers: []fakeAnswer{{ans: old}, {ans: rotated}}}
	tr.TLSA.source = src
	peer := apiPeer(srv)
	if _, err := tr.Hello(context.Background(), peer, &HelloRequest{SenderID: "a.example."}); err != nil {
		t.Fatalf("the rotated certificate after a look past the cache: %v", err)
	}
	if got := src.lookups(); len(got) != 2 || got[0] || !got[1] {
		t.Errorf("lookups (fresh?) %v, want a cached one and then a fresh one", got)
	}

	// The next mismatch within the interval is not looked at again.
	tr2 := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, srv)
	src2 := &fakeTLSA{answers: []fakeAnswer{{ans: old}}}
	tr2.TLSA.source = src2
	for i := 0; i < 2; i++ {
		if _, err := tr2.Hello(context.Background(), apiPeer(srv), &HelloRequest{SenderID: "a.example."}); !errors.Is(err, ErrTLSAMismatch) {
			t.Fatalf("a certificate the set does not name: %v, want ErrTLSAMismatch", err)
		}
	}
	if got := src2.lookups(); len(got) != 3 || got[0] || !got[1] || got[2] {
		t.Errorf("lookups (fresh?) %v, want one fresh look in the interval", got)
	}
}

// Without a certificate there is nothing to check.
func TestTLSACheckWithoutACertificate(t *testing.T) {
	c := NewTLSAChecker(nil)
	if err := c.Check(context.Background(), withTLSA(NewPeer("b.example."), otherCert(t)), "API", nil); !errors.Is(err, ErrTLSAMismatch) {
		t.Errorf("no certificate: %v, want ErrTLSAMismatch", err)
	}
}

// A peer's client goes with the peer.
func TestAPIForgetsARemovedPeer(t *testing.T) {
	var captured []apiCapture
	srv := apiReceiver(t, &captured, okReply)
	defer srv.Close()
	tr := apiClient(&APITransportConfig{LocalID: "a.example.", DefaultTimeout: 2 * time.Second}, srv)
	reg := NewPeerRegistry()
	reg.OnRemove = tr.ForgetPeer
	peer := apiPeer(srv)
	if err := reg.Add(peer); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Hello(context.Background(), peer, &HelloRequest{SenderID: "a.example."}); err != nil {
		t.Fatal(err)
	}
	tr.mu.Lock()
	n := len(tr.clients)
	tr.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d clients after one peer's request, want 1", n)
	}
	reg.Remove(peer.ID)
	tr.mu.Lock()
	n = len(tr.clients)
	tr.mu.Unlock()
	if n != 0 {
		t.Errorf("%d clients after the peer was removed, want none", n)
	}
}
