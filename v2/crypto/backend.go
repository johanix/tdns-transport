/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Crypto backend abstraction layer for the tdns transport.
 *
 * A backend owns one envelope: how a payload is encrypted for a peer and
 * signed by the sender, and how the result is serialized. The transport's
 * PayloadCrypto is written against this interface only; the JOSE backend
 * is the one in production, and a COSE backend (with HPKE as its recipient
 * algorithm) is the planned second.
 */

package crypto

// Backend defines the interface that all cryptographic backends must implement.
type Backend interface {
	// Name returns the backend identifier (e.g., "jose")
	Name() string

	// Envelope returns the label the backend's EncryptAndSign output
	// carries on the wire.
	Envelope() Envelope

	// GenerateKeypair generates a new key pair suitable for this backend
	GenerateKeypair() (PrivateKey, PublicKey, error)

	// ParsePublicKey deserializes a public key from bytes
	// The format is backend-specific (JWK JSON for JOSE)
	ParsePublicKey(data []byte) (PublicKey, error)

	// ParsePrivateKey deserializes a private key from bytes
	// The format is backend-specific
	ParsePrivateKey(data []byte) (PrivateKey, error)

	// SerializePublicKey serializes a public key to bytes
	// The format is backend-specific
	SerializePublicKey(key PublicKey) ([]byte, error)

	// SerializePrivateKey serializes a private key to bytes
	// The format is backend-specific
	SerializePrivateKey(key PrivateKey) ([]byte, error)

	// Encrypt encrypts plaintext for the specified recipient public key
	// Returns ciphertext in backend-specific format (may include ephemeral key, etc.)
	Encrypt(recipientPubKey PublicKey, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext using the private key
	// Expects ciphertext in backend-specific format
	Decrypt(privateKey PrivateKey, ciphertext []byte) ([]byte, error)

	// GetEphemeralKey extracts the ephemeral public key from ciphertext
	// Returns the ephemeral public key bytes, or nil/empty if the backend
	// embeds the ephemeral key within the ciphertext format (e.g., JWE header)
	// This allows the encryption layer to be truly backend-agnostic
	GetEphemeralKey(ciphertext []byte) ([]byte, error)

	// EncryptMultiRecipient encrypts plaintext for multiple recipients.
	// Returns JWE-formatted ciphertext (JSON Serialization) containing:
	// - Single encrypted payload (CEK-encrypted with AES-256-GCM)
	// - Multiple recipient entries, each with encrypted CEK
	// - Protected headers with metadata (distribution_id, timestamp, etc.)
	//
	// A backend without native multi-recipient support may encrypt for
	// each recipient separately inside its envelope.
	//
	// The metadata map should contain JWE protected header fields:
	//   - "distribution_id": string - Distribution identifier
	//   - "content_type": string - Content type (e.g., "key_operations")
	//   - "timestamp": string - ISO8601 timestamp for replay protection
	//   - "distribution_ttl": string - TTL for replay protection
	//   - "sender": string - Sender identity
	//   - Other custom fields as needed
	EncryptMultiRecipient(recipients []PublicKey, plaintext []byte, metadata map[string]interface{}) ([]byte, error)

	// DecryptMultiRecipient decrypts JWE-formatted multi-recipient ciphertext.
	// Finds the recipient entry matching the provided private key and decrypts.
	// Returns plaintext and metadata from protected headers.
	//
	// This method handles both:
	// - JWE JSON Serialization (standard multi-recipient format)
	// - JWE Compact Serialization (single-recipient, for backward compatibility)
	DecryptMultiRecipient(privKey PrivateKey, ciphertext []byte) ([]byte, error)

	// Sign signs data using the private key and returns the backend's
	// signed structure (for JOSE: ES256, JWS compact serialization with
	// base64url(data) as the payload).
	Sign(privKey PrivateKey, data []byte) ([]byte, error)

	// Verify verifies a JWS signature using the public key.
	// Returns true if signature is valid, false otherwise.
	// The signature algorithm is detected from the JWS protected header.
	Verify(pubKey PublicKey, data []byte, signature []byte) (bool, error)

	// PublicKeyFromStdlib wraps a stdlib crypto.PublicKey in a backend-specific wrapper.
	// This allows converting discovered keys (from JWK records, etc.) to backend-specific types.
	// The stdlib key type must be compatible with the backend (e.g., ECDSA for JOSE).
	PublicKeyFromStdlib(stdlibKey interface{}) (PublicKey, error)

	// PublicFromPrivate returns the public half of a private key.
	PublicFromPrivate(priv PrivateKey) (PublicKey, error)

	// EncryptAndSign produces the backend's envelope for the recipients:
	// the plaintext encrypted for them and signed by signingKey, with the
	// metadata in the envelope's protected header. This is what the
	// transport puts on the wire (behind its outer standard-base64 layer).
	EncryptAndSign(recipients []PublicKey, plaintext []byte, signingKey PrivateKey, metadata map[string]interface{}) ([]byte, error)

	// DecryptAndVerify is the inverse of EncryptAndSign: it verifies the
	// envelope's signature with verifyKey and decrypts with privKey, in
	// that order, and returns the plaintext.
	DecryptAndVerify(privKey PrivateKey, verifyKey PublicKey, ciphertext []byte) ([]byte, error)
}

// PrivateKey represents a private key (backend-specific implementation)
type PrivateKey interface {
	// Backend returns the name of the backend this key belongs to
	Backend() string
}

// PublicKey represents a public key (backend-specific implementation)
type PublicKey interface {
	// Backend returns the name of the backend this key belongs to
	Backend() string
}
