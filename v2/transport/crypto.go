/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Payload crypto for the DNS transport: the local key pair, the peers'
 * keys, and the wire form of an encrypted payload.
 *
 * The wire form is base64.StdEncoding(envelope), where the envelope is
 * what the crypto backend's EncryptAndSign produces (JWS(JWE(payload)) for
 * JOSE) and the outer standard-base64 layer is the transport's own. The
 * envelope label the backend reports rides in the CHUNK Format byte
 * (envelope.go). Nothing here parses an envelope: that is the backend's
 * job, and crypto_seam_test.go is the gate that keeps the bytes the same.
 */

package transport

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/johanix/tdns-transport/v2/crypto"
	"github.com/miekg/dns"
)

// ErrNoVerificationKey is returned when a peer's verification key is not available.
// Use errors.Is(err, ErrNoVerificationKey) instead of string matching on error messages.
var ErrNoVerificationKey = errors.New("no verification key")

// ErrPlaintextRefused is returned for an unwrapped payload while payload
// crypto is enabled: nothing proves who sent it, whatever identity it claims.
var ErrPlaintextRefused = errors.New("plaintext payload refused: payload crypto is enabled")

// PayloadCrypto handles encryption and signing of DNS transport payloads.
// It wraps a crypto.Backend to provide a simple interface for the DNS transport.
type PayloadCrypto struct {
	// Backend is the cryptographic backend (JOSE today)
	Backend crypto.Backend

	// LocalPrivateKey is our private key for decryption and signing
	LocalPrivateKey crypto.PrivateKey

	// LocalPublicKey is our public key (for key exchange)
	LocalPublicKey crypto.PublicKey

	// SigningKey is the key used for signing (may be same as LocalPrivateKey for JOSE)
	SigningKey crypto.PrivateKey

	// VerificationKey is our public key for signature verification
	VerificationKey crypto.PublicKey

	// PeerKeys maps peer IDs to their public keys for encryption
	PeerKeys map[string]crypto.PublicKey

	// PeerVerificationKeys maps peer IDs to their verification keys for signature verification
	PeerVerificationKeys map[string]crypto.PublicKey

	// Enabled indicates if encryption is enabled
	Enabled bool
}

// PayloadCryptoConfig holds configuration for creating a PayloadCrypto instance.
type PayloadCryptoConfig struct {
	Backend      crypto.Backend
	Enabled      bool
	AutoGenerate bool // If true, generate keypair if not provided
}

// NewPayloadCrypto creates a new PayloadCrypto instance.
func NewPayloadCrypto(cfg *PayloadCryptoConfig) (*PayloadCrypto, error) {
	if cfg.Backend == nil && cfg.Enabled {
		return nil, fmt.Errorf("crypto backend is required when encryption is enabled")
	}

	pc := &PayloadCrypto{
		Backend:              cfg.Backend,
		Enabled:              cfg.Enabled,
		PeerKeys:             make(map[string]crypto.PublicKey),
		PeerVerificationKeys: make(map[string]crypto.PublicKey),
	}

	// Generate keypair if enabled and requested
	if cfg.Enabled && cfg.AutoGenerate && cfg.Backend != nil {
		privKey, pubKey, err := cfg.Backend.GenerateKeypair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate keypair: %w", err)
		}
		pc.LocalPrivateKey = privKey
		pc.LocalPublicKey = pubKey
		pc.SigningKey = privKey
		pc.VerificationKey = pubKey
	}

	return pc, nil
}

// SetLocalKeys sets the local private and public keys.
func (pc *PayloadCrypto) SetLocalKeys(privKey crypto.PrivateKey, pubKey crypto.PublicKey) {
	pc.LocalPrivateKey = privKey
	pc.LocalPublicKey = pubKey
	pc.SigningKey = privKey
	pc.VerificationKey = pubKey
}

// AddPeerKey adds a peer's public key for encryption.
// Normalizes peerID to FQDN for consistent lookup.
func (pc *PayloadCrypto) AddPeerKey(peerID string, pubKey crypto.PublicKey) {
	pc.PeerKeys[dns.Fqdn(peerID)] = pubKey
}

// AddPeerVerificationKey adds a peer's public key for signature verification.
// Normalizes peerID to FQDN for consistent lookup.
func (pc *PayloadCrypto) AddPeerVerificationKey(peerID string, pubKey crypto.PublicKey) {
	pc.PeerVerificationKeys[dns.Fqdn(peerID)] = pubKey
}

// getPeerKey retrieves a peer's public key for encryption.
func (pc *PayloadCrypto) getPeerKey(peerID string) (crypto.PublicKey, bool) {
	key, exists := pc.PeerKeys[dns.Fqdn(peerID)]
	return key, exists
}

// getPeerVerificationKey retrieves a peer's public key for signature verification.
func (pc *PayloadCrypto) getPeerVerificationKey(peerID string) (crypto.PublicKey, bool) {
	key, exists := pc.PeerVerificationKeys[dns.Fqdn(peerID)]
	return key, exists
}

// peerVerificationKeyIDs returns the list of peer IDs we have verification keys for (for try-decrypt on incoming).
func (pc *PayloadCrypto) peerVerificationKeyIDs() []string {
	ids := make([]string, 0, len(pc.PeerVerificationKeys))
	for id := range pc.PeerVerificationKeys {
		ids = append(ids, id)
	}
	return ids
}

// Envelope returns the label of what encryptAndSignPayload produces: the
// backend's envelope, which is what the CHUNK Format byte carries for an
// encrypted payload.
func (pc *PayloadCrypto) Envelope() uint8 {
	return uint8(pc.Backend.Envelope())
}

// encryptAndSignPayload produces the wire form of a payload for a peer:
// the backend's envelope (for JOSE, JWS(JWE(payload))) under an outer
// standard-base64 layer. The outer layer is part of the wire and stays
// whatever the backend; a receiver strips it before it asks the backend.
// If encryption is disabled, returns the original payload as-is.
func (pc *PayloadCrypto) encryptAndSignPayload(peerID string, payload []byte, metadata map[string]interface{}) ([]byte, error) {
	if !pc.Enabled {
		return payload, nil
	}

	peerKey, exists := pc.PeerKeys[dns.Fqdn(peerID)]
	if !exists {
		return nil, fmt.Errorf("no encryption key for peer %s", peerID)
	}

	if pc.SigningKey == nil {
		return nil, fmt.Errorf("no signing key configured")
	}

	// Add default metadata if not provided
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	if _, exists := metadata["timestamp"]; !exists {
		metadata["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	}

	envelope, err := pc.Backend.EncryptAndSign([]crypto.PublicKey{peerKey}, payload, pc.SigningKey, metadata)
	if err != nil {
		return nil, fmt.Errorf("encrypt and sign: %w", err)
	}

	return []byte(base64.StdEncoding.EncodeToString(envelope)), nil
}

// decryptAndVerifyPayload is the inverse of encryptAndSignPayload for a
// payload from the named peer: strips the outer standard-base64 layer,
// then has the backend verify with the peer's key and decrypt with ours.
// If encryption is disabled, returns the original payload as-is.
func (pc *PayloadCrypto) decryptAndVerifyPayload(peerID string, encodedPayload []byte) ([]byte, error) {
	if !pc.Enabled {
		return encodedPayload, nil
	}

	if pc.LocalPrivateKey == nil {
		return nil, fmt.Errorf("no private key configured for decryption")
	}

	verifyKey, exists := pc.PeerVerificationKeys[dns.Fqdn(peerID)]
	if !exists {
		return nil, fmt.Errorf("%w: peer %s", ErrNoVerificationKey, peerID)
	}

	envelope, err := base64.StdEncoding.DecodeString(string(encodedPayload))
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	plaintext, err := pc.Backend.DecryptAndVerify(pc.LocalPrivateKey, verifyKey, envelope)
	if err != nil {
		return nil, fmt.Errorf("verify and decrypt from peer %s: %w", peerID, err)
	}

	return plaintext, nil
}

// isPayloadEncrypted checks if a payload appears to be encrypted (base64-encoded).
// This is a heuristic check - encrypted payloads won't start with '{' after decode attempt.
// Legacy: the receive path reads the envelope label instead (see
// envelope.go); this sniff remains for payloads that carry no label.
func isPayloadEncrypted(payload []byte) bool {
	// Try to parse as JSON first - if it works, it's not encrypted
	var test interface{}
	if err := json.Unmarshal(payload, &test); err == nil {
		return false
	}

	// Check if it looks like base64
	if len(payload) == 0 {
		return false
	}

	// Try to decode as base64 - if successful and result isn't JSON, it's encrypted
	decoded, err := base64.StdEncoding.DecodeString(string(payload))
	if err != nil {
		return false
	}

	// If decoded bytes don't look like JSON, assume encrypted
	return len(decoded) > 0 && decoded[0] != '{'
}

// SecurePayloadWrapper wraps the payload crypto operations for use with DNS transport.
type SecurePayloadWrapper struct {
	crypto *PayloadCrypto
}

// NewSecurePayloadWrapper creates a new wrapper for secure payload handling.
func NewSecurePayloadWrapper(crypto *PayloadCrypto) *SecurePayloadWrapper {
	return &SecurePayloadWrapper{crypto: crypto}
}

// wrapOutgoing prepares an outgoing payload for a specific peer.
// If encryption is enabled, returns encrypted and signed payload.
// Otherwise returns the original payload.
func (w *SecurePayloadWrapper) wrapOutgoing(peerID string, payload []byte) ([]byte, error) {
	if w.crypto == nil || !w.crypto.Enabled {
		return payload, nil
	}

	metadata := map[string]interface{}{
		"peer_id":   peerID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	encrypted, err := w.crypto.encryptAndSignPayload(peerID, payload, metadata)
	if err != nil {
		lgCrypto().Error("encryption failed", "peer", peerID, "err", err)
		return nil, err
	}

	return encrypted, nil
}

// unwrapIncoming processes an incoming payload from a specific peer.
// If encryption is enabled, verifies and decrypts the payload.
// Otherwise returns the original payload.
func (w *SecurePayloadWrapper) unwrapIncoming(peerID string, payload []byte) ([]byte, error) {
	if w.crypto == nil || !w.crypto.Enabled {
		return payload, nil
	}

	// Check if payload is encrypted
	if !isPayloadEncrypted(payload) {
		lgCrypto().Warn("received unencrypted payload when encryption is enabled, rejecting", "peer", peerID)
		return nil, fmt.Errorf("received unencrypted payload from peer %s when encryption is mandatory", peerID)
	}

	decrypted, err := w.crypto.decryptAndVerifyPayload(peerID, payload)
	if err != nil {
		lgCrypto().Error("decryption failed", "peer", peerID, "err", err)
		return nil, err
	}

	return decrypted, nil
}

// unwrapIncomingFromPeerEnvelope is unwrapIncomingFromPeer driven by the
// payload's envelope label instead of a byte-sniff. EnvelopeNone passes the
// payload through when payload crypto is off and is refused when it is on;
// EnvelopeJOSE requires payload crypto and the named peer's verification
// key, and decrypts with that key only; EnvelopeUnknown sniffs the bytes of
// a payload that arrived without a label, and refuses plaintext the same
// way.
func (w *SecurePayloadWrapper) unwrapIncomingFromPeerEnvelope(payload []byte, requiredPeerID string, envelope uint8) ([]byte, error) {
	switch envelope {
	case EnvelopeUnknown:
		return w.unwrapIncomingFromPeer(payload, requiredPeerID)
	case EnvelopeNone:
		if w.IsEnabled() {
			return nil, fmt.Errorf("%w: from %s", ErrPlaintextRefused, requiredPeerID)
		}
		return payload, nil
	case EnvelopeJOSE:
		if w.crypto == nil || !w.crypto.Enabled {
			return nil, fmt.Errorf("payload from %s is JOSE-wrapped but payload crypto is not enabled", requiredPeerID)
		}
		if _, exists := w.crypto.PeerVerificationKeys[dns.Fqdn(requiredPeerID)]; !exists {
			return nil, fmt.Errorf("%w: peer %s", ErrNoVerificationKey, requiredPeerID)
		}
		decrypted, err := w.crypto.decryptAndVerifyPayload(requiredPeerID, payload)
		if err != nil {
			return nil, fmt.Errorf("decryption failed for required peer %s: %w", requiredPeerID, err)
		}
		return decrypted, nil
	}
	return nil, checkEnvelope(envelope)
}

// IsEnabled returns true if encryption is enabled.
func (w *SecurePayloadWrapper) IsEnabled() bool {
	return w.crypto != nil && w.crypto.Enabled
}

// Envelope returns the label of what wrapOutgoing produces; EnvelopeNone
// when encryption is not enabled.
func (w *SecurePayloadWrapper) Envelope() uint8 {
	if !w.IsEnabled() {
		return EnvelopeNone
	}
	return w.crypto.Envelope()
}

// GetCrypto returns the underlying PayloadCrypto instance.
// This allows access to methods like AddPeerKey for dynamic peer registration.
func (w *SecurePayloadWrapper) GetCrypto() *PayloadCrypto {
	return w.crypto
}

// unwrapIncomingFromPeer decrypts an incoming payload using ONLY the specified peer's verification key.
// This is the secure version that prevents DoS attacks via QNAME forgery.
//
// Use this function when:
// - You've already performed authorization checks (IsPeerAuthorized)
// - The peerID comes from a trusted source (e.g., QNAME after authorization)
// - You want to prevent attackers from forcing crypto operations with all peer keys
//
// If decryption fails with the specified peer's key, this function returns an error immediately
// without trying other peers. This prevents DoS amplification where an attacker forges a QNAME
// to be an authorized peer's identity.
//
// Parameters:
//   - payload: The encrypted payload (base64-encoded JWS wrapping JWE)
//   - requiredPeerID: The identity of the peer that MUST have signed this payload
//
// Returns:
//   - decrypted: The decrypted plaintext payload
//   - error: Non-nil if decryption fails or peer not found
func (w *SecurePayloadWrapper) unwrapIncomingFromPeer(payload []byte, requiredPeerID string) ([]byte, error) {
	if w.crypto == nil || !w.crypto.Enabled {
		return payload, nil
	}
	if !isPayloadEncrypted(payload) {
		return nil, fmt.Errorf("%w: from %s", ErrPlaintextRefused, requiredPeerID)
	}

	// Verify we have the peer's key
	_, exists := w.crypto.PeerVerificationKeys[dns.Fqdn(requiredPeerID)]
	if !exists {
		return nil, fmt.Errorf("%w: peer %s", ErrNoVerificationKey, requiredPeerID)
	}

	// Attempt decryption with ONLY the required peer's key
	decrypted, err := w.crypto.decryptAndVerifyPayload(requiredPeerID, payload)
	if err != nil {
		return nil, fmt.Errorf("decryption failed for required peer %s: %w", requiredPeerID, err)
	}

	return decrypted, nil
}
