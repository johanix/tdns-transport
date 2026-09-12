/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Backend registry and interface tests, against the JOSE backend (the one
 * in production; a COSE backend is the planned second).
 */

package crypto_test

import (
	"bytes"
	"sort"
	"testing"

	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose" // Register JOSE backend
)

func TestJOSERegistered(t *testing.T) {
	if !crypto.IsBackendRegistered("jose") {
		t.Fatal("JOSE backend not registered")
	}
	backends := crypto.ListBackends()
	if !sort.StringsAreSorted(backends) {
		t.Errorf("ListBackends not sorted: %v", backends)
	}
	found := false
	for _, name := range backends {
		if name == "jose" {
			found = true
		}
	}
	if !found {
		t.Errorf("jose missing from %v", backends)
	}
}

func TestGetBackend(t *testing.T) {
	backend, err := crypto.GetBackend("jose")
	if err != nil || backend == nil || backend.Name() != "jose" {
		t.Fatalf("GetBackend(jose): %v %v", backend, err)
	}
	if backend.Envelope() != crypto.EnvelopeJOSE {
		t.Errorf("Envelope() = %v, want %v", backend.Envelope(), crypto.EnvelopeJOSE)
	}
	if _, err := crypto.GetBackend("unknown"); err == nil {
		t.Error("GetBackend(unknown): expected an error")
	}
	if crypto.IsBackendRegistered("unknown") {
		t.Error("IsBackendRegistered(unknown) = true")
	}
}

func TestRegisterDuplicate(t *testing.T) {
	backend, _ := crypto.GetBackend("jose")
	if err := crypto.RegisterBackend(backend); err == nil {
		t.Error("registering jose twice did not fail")
	}
}

// The interface round trip: keys serialize and parse, the public half
// derives from the private, and EncryptAndSign is undone by DecryptAndVerify.
func TestBackendRoundTrip(t *testing.T) {
	backend, _ := crypto.GetBackend("jose")
	senderPriv, senderPub, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	recipientPriv, recipientPub, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if senderPriv.Backend() != "jose" || senderPub.Backend() != "jose" {
		t.Errorf("key backend names: %s %s", senderPriv.Backend(), senderPub.Backend())
	}

	privBytes, err := backend.SerializePrivateKey(recipientPriv)
	if err != nil {
		t.Fatal(err)
	}
	parsedPriv, err := backend.ParsePrivateKey(privBytes)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := backend.SerializePublicKey(recipientPub)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := backend.PublicFromPrivate(parsedPriv)
	if err != nil {
		t.Fatal(err)
	}
	derivedBytes, err := backend.SerializePublicKey(derived)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubBytes, derivedBytes) {
		t.Errorf("PublicFromPrivate differs from the generated public key:\n %s\n %s", pubBytes, derivedBytes)
	}

	plaintext := []byte(`{"MessageType":"ping","nonce":"n-1"}`)
	envelope, err := backend.EncryptAndSign([]crypto.PublicKey{recipientPub}, plaintext, senderPriv,
		map[string]interface{}{"peer_id": "b.example."})
	if err != nil {
		t.Fatal(err)
	}
	got, err := backend.DecryptAndVerify(parsedPriv, senderPub, envelope)
	if err != nil {
		t.Fatalf("DecryptAndVerify: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext %q", got)
	}
	// the wrong verification key fails
	if _, err := backend.DecryptAndVerify(parsedPriv, recipientPub, envelope); err == nil {
		t.Error("verified with the wrong key")
	}
	// the wrong private key fails
	if _, err := backend.DecryptAndVerify(senderPriv, senderPub, envelope); err == nil {
		t.Error("decrypted with the wrong key")
	}
}
