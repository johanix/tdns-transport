/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Common types and errors for crypto abstraction layer
 */

package crypto

import (
	"errors"
	"fmt"
)

// Common errors
var (
	// ErrUnsupportedBackend indicates the requested backend is not registered
	ErrUnsupportedBackend = errors.New("unsupported crypto backend")

	// ErrInvalidKey indicates a key is malformed or invalid
	ErrInvalidKey = errors.New("invalid key")

	// ErrEncryptionFailed indicates encryption operation failed
	ErrEncryptionFailed = errors.New("encryption failed")

	// ErrDecryptionFailed indicates decryption operation failed
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrBackendMismatch indicates a key from one backend was used with another
	ErrBackendMismatch = errors.New("crypto backend mismatch")
)

// BackendError wraps backend-specific errors with context
type BackendError struct {
	Backend string
	Op      string // Operation that failed (e.g., "encrypt", "decrypt", "parse_key")
	Err     error
}

func (e *BackendError) Error() string {
	return fmt.Sprintf("%s backend %s: %v", e.Backend, e.Op, e.Err)
}

func (e *BackendError) Unwrap() error {
	return e.Err
}

// NewBackendError creates a new BackendError
func NewBackendError(backend, op string, err error) error {
	return &BackendError{
		Backend: backend,
		Op:      op,
		Err:     err,
	}
}

// Envelope is the label a backend's EncryptAndSign output carries on the
// wire: it tells a receiver how the bytes are wrapped and which backend
// opens them. The values are the CHUNK Format codes the transport already
// carried (JSON = 1 is a plain payload, not a backend's envelope); the
// transport asserts that they agree with tdns core's constants.
type Envelope uint8

const (
	// EnvelopeJOSE: JWS over JWE (RFC 7515 over RFC 7516).
	EnvelopeJOSE Envelope = 2
	// EnvelopeCOSE: a CBOR envelope (RFC 9052); reserved, no backend yet.
	EnvelopeCOSE Envelope = 3
)
