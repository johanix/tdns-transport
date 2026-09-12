/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The cross-decrypt gate for the payload crypto seam (cleanup plan, step 7).
 *
 * What is on the wire is base64.StdEncoding(JWS(JWE(payload))). JWE is
 * randomised, so fresh ciphertext can never be compared byte for byte;
 * instead: a ciphertext captured from the pre-step-7 path with the
 * checked-in test keys must decrypt through the current path, a fresh
 * ciphertext from the current path must decrypt through the pre-step-7
 * algorithm (re-implemented here from the backend primitives, which did
 * not change), and the produced bytes must have the wire's structure.
 */

package transport

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose"
)

const seamPlaintext = `{"MessageType":"ping","MyIdentity":"a.example.","nonce":"n-1"}`

func seamKeys(t *testing.T) (crypto.Backend, crypto.PrivateKey, crypto.PublicKey, crypto.PrivateKey, crypto.PublicKey) {
	t.Helper()
	backend, err := crypto.GetBackend("jose")
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/crypto/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	aPriv, err := backend.ParsePrivateKey(read("a.priv.json"))
	if err != nil {
		t.Fatal(err)
	}
	aPub, err := backend.ParsePublicKey(read("a.pub.json"))
	if err != nil {
		t.Fatal(err)
	}
	bPriv, err := backend.ParsePrivateKey(read("b.priv.json"))
	if err != nil {
		t.Fatal(err)
	}
	bPub, err := backend.ParsePublicKey(read("b.pub.json"))
	if err != nil {
		t.Fatal(err)
	}
	return backend, aPriv, aPub, bPriv, bPub
}

// seamSender is a's PayloadCrypto with b as the peer; seamReceiver is b's
// with a as the peer.
func seamPair(t *testing.T) (*SecurePayloadWrapper, *SecurePayloadWrapper) {
	t.Helper()
	backend, aPriv, aPub, bPriv, bPub := seamKeys(t)
	a, _ := NewPayloadCrypto(&PayloadCryptoConfig{Backend: backend, Enabled: true})
	a.SetLocalKeys(aPriv, aPub)
	a.AddPeerKey("b.example.", bPub)
	a.AddPeerVerificationKey("b.example.", bPub)
	b, _ := NewPayloadCrypto(&PayloadCryptoConfig{Backend: backend, Enabled: true})
	b.SetLocalKeys(bPriv, bPub)
	b.AddPeerKey("a.example.", aPub)
	b.AddPeerVerificationKey("a.example.", aPub)
	return NewSecurePayloadWrapper(a), NewSecurePayloadWrapper(b)
}

// legacyDecrypt is the receive algorithm as it was before step 7, from the
// backend primitives: standard base64, split the JWS compact serialization,
// base64url-decode its payload (the JWE), verify the JWS over it with the
// sender's key, decrypt the JWE with the recipient's key.
func legacyDecrypt(t *testing.T, backend crypto.Backend, recipient crypto.PrivateKey, sender crypto.PublicKey, wire []byte) []byte {
	t.Helper()
	jws, err := base64.StdEncoding.DecodeString(string(wire))
	if err != nil {
		t.Fatalf("legacy: outer base64: %v", err)
	}
	parts := bytes.Split(jws, []byte("."))
	if len(parts) != 3 {
		t.Fatalf("legacy: JWS has %d parts, want 3", len(parts))
	}
	jwe, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		t.Fatalf("legacy: JWS payload: %v", err)
	}
	ok, err := backend.Verify(sender, jwe, jws)
	if err != nil || !ok {
		t.Fatalf("legacy: verify: ok=%v err=%v", ok, err)
	}
	plain, err := backend.DecryptMultiRecipient(recipient, jwe)
	if err != nil {
		t.Fatalf("legacy: decrypt: %v", err)
	}
	return plain
}

// assertWireStructure checks the shape of one wire payload: standard base64
// outside, a three-part JWS whose protected header says ES256, and inside
// its payload a five-part JWE compact serialization whose protected header
// says ECDH-ES and A256GCM and carries the metadata the wrapper adds.
func assertWireStructure(t *testing.T, wire []byte, peerID string) {
	t.Helper()
	jws, err := base64.StdEncoding.DecodeString(string(wire))
	if err != nil {
		t.Fatalf("outer layer is not standard base64: %v", err)
	}
	parts := strings.Split(string(jws), ".")
	if len(parts) != 3 {
		t.Fatalf("JWS has %d parts, want 3", len(parts))
	}
	var jwsHeader map[string]interface{}
	if hb, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil || json.Unmarshal(hb, &jwsHeader) != nil {
		t.Fatalf("JWS protected header: %v", err)
	}
	if jwsHeader["alg"] != "ES256" {
		t.Errorf("JWS alg = %v, want ES256", jwsHeader["alg"])
	}
	jwe, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("JWS payload: %v", err)
	}
	jweParts := strings.Split(string(jwe), ".")
	if len(jweParts) != 5 {
		t.Fatalf("JWE has %d parts, want 5 (compact serialization)", len(jweParts))
	}
	var jweHeader map[string]interface{}
	if hb, err := base64.RawURLEncoding.DecodeString(jweParts[0]); err != nil || json.Unmarshal(hb, &jweHeader) != nil {
		t.Fatalf("JWE protected header: %v", err)
	}
	if jweHeader["alg"] != "ECDH-ES" || jweHeader["enc"] != "A256GCM" {
		t.Errorf("JWE alg/enc = %v/%v, want ECDH-ES/A256GCM", jweHeader["alg"], jweHeader["enc"])
	}
	if jweHeader["typ"] != "tdns-distribution" || jweHeader["crypto_backend"] != "jose" {
		t.Errorf("JWE typ/crypto_backend = %v/%v", jweHeader["typ"], jweHeader["crypto_backend"])
	}
	if jweHeader["peer_id"] != peerID {
		t.Errorf("JWE peer_id = %v, want %s", jweHeader["peer_id"], peerID)
	}
	if _, ok := jweHeader["timestamp"].(string); !ok {
		t.Errorf("JWE timestamp missing: %v", jweHeader)
	}
}

// A ciphertext captured before step 7 decrypts through the current path.
func TestCryptoSeam_CapturedDecrypts(t *testing.T) {
	_, receiver := seamPair(t)
	wire, err := os.ReadFile("testdata/crypto/a-to-b.wire")
	if err != nil {
		t.Fatal(err)
	}
	assertWireStructure(t, wire, "b.example.")
	plain, err := receiver.UnwrapIncomingFromPeerEnvelope(wire, "a.example.", EnvelopeJOSE)
	if err != nil {
		t.Fatalf("captured ciphertext through the current path: %v", err)
	}
	if string(plain) != seamPlaintext {
		t.Fatalf("plaintext %q", plain)
	}
}

// A fresh ciphertext from the current path decrypts through the pre-step-7
// algorithm, and has the wire's structure.
func TestCryptoSeam_FreshDecryptsLegacy(t *testing.T) {
	backend, aPriv, aPub, bPriv, bPub := seamKeys(t)
	_ = aPriv
	_ = bPub
	sender, receiver := seamPair(t)
	wire, err := sender.WrapOutgoing("b.example.", []byte(seamPlaintext))
	if err != nil {
		t.Fatal(err)
	}
	assertWireStructure(t, wire, "b.example.")
	if got := legacyDecrypt(t, backend, bPriv, aPub, wire); string(got) != seamPlaintext {
		t.Fatalf("legacy algorithm: plaintext %q", got)
	}
	// and through the current path, for good measure
	plain, err := receiver.UnwrapIncomingFromPeerEnvelope(wire, "a.example.", EnvelopeJOSE)
	if err != nil || string(plain) != seamPlaintext {
		t.Fatalf("current path: %q %v", plain, err)
	}
	// the wrong sender's key must not verify
	if _, err := receiver.UnwrapIncomingFromPeerEnvelope(wire, "b.example.", EnvelopeJOSE); err == nil {
		t.Fatal("verified with the wrong peer's key")
	}
}
