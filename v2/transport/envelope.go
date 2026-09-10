/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The payload envelope label (C5): where it rides and what it means.
 */

package transport

import (
	"fmt"

	core "github.com/johanix/tdns/v2/core"
)

// Envelope labels. The label says how the bytes of a CHUNK payload are
// wrapped, and therefore what the receiver must do before it can read them.
// It rides in the Format byte of the CHUNK EDNS0 option (in-channel NOTIFY)
// and of CHUNK records served in query mode: the transport-owned slot that
// every message already carries and that is read before reassembly and
// before any cryptography. The values are the historical Format codes, so
// the label costs no wire change and every sender to date already emits
// it. It replaces the byte-sniff (IsPayloadEncrypted) as the receiver's
// source of truth; the sniff survives only as the fallback for a payload
// that reached the receiver without a label (EnvelopeUnknown: the legacy
// query-mode fetch through the application's FetchChunkQuery callback).
const (
	// EnvelopeUnknown: no label was available. The receiver falls back to
	// sniffing the bytes. Never sent.
	EnvelopeUnknown uint8 = 0
	// EnvelopeNone: plain JSON, nothing to unwrap.
	EnvelopeNone uint8 = core.FormatJSON
	// EnvelopeJOSE: JWS over JWE, the sender's key signs and the receiver's
	// key decrypts.
	EnvelopeJOSE uint8 = core.FormatJWT
	// EnvelopeCOSE is reserved for a CBOR envelope; a receiver answers
	// FORMERR to it until it is implemented.
	EnvelopeCOSE uint8 = 3
)

// EnvelopeString names an envelope label for logs.
func EnvelopeString(e uint8) string {
	switch e {
	case EnvelopeUnknown:
		return "unlabelled"
	case EnvelopeNone:
		return "none"
	case EnvelopeJOSE:
		return "jose"
	case EnvelopeCOSE:
		return "cose"
	}
	return fmt.Sprintf("envelope(%d)", e)
}

// checkEnvelope reports whether a receiver can process a payload carrying
// this label: it must be known and implemented. EnvelopeUnknown passes so
// the legacy fallback can run.
func checkEnvelope(e uint8) error {
	switch e {
	case EnvelopeUnknown, EnvelopeNone, EnvelopeJOSE:
		return nil
	case EnvelopeCOSE:
		return fmt.Errorf("envelope %s is not implemented", EnvelopeString(e))
	}
	return fmt.Errorf("unknown envelope label %d", e)
}

// payloadEnvelope is the label of the payload currently in ctx.ChunkPayload,
// for code that must decide whether the payload is JOSE-wrapped: the label
// when the receive path recorded one, the byte-sniff otherwise.
func (ctx *MessageContext) payloadIsJOSE() bool {
	if ctx.ChunkEnvelope != EnvelopeUnknown {
		return ctx.ChunkEnvelope == EnvelopeJOSE
	}
	return IsPayloadEncrypted(ctx.ChunkPayload)
}
