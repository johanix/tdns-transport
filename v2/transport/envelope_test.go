package transport

import (
	"strings"
	"testing"
)

func TestCheckEnvelope(t *testing.T) {
	for _, e := range []uint8{EnvelopeUnknown, EnvelopeNone, EnvelopeJOSE} {
		if err := checkEnvelope(e); err != nil {
			t.Errorf("%s: %v", EnvelopeString(e), err)
		}
	}
	if err := checkEnvelope(EnvelopeCOSE); err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("cose: %v", err)
	}
	if err := checkEnvelope(9); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Errorf("9: %v", err)
	}
}

// The label, not the bytes, decides: plain JSON labelled none passes
// through untouched even with crypto disabled; a JOSE label without crypto
// is an error; an unlabelled payload falls back to the sniff.
func TestUnwrapIncomingFromPeerEnvelope_noCrypto(t *testing.T) {
	w := NewSecurePayloadWrapper(nil)
	plain := []byte(`{"MessageType":"sync"}`)
	if out, err := w.UnwrapIncomingFromPeerEnvelope(plain, "a.", EnvelopeNone); err != nil || string(out) != string(plain) {
		t.Fatalf("none: out=%q err=%v", out, err)
	}
	if _, err := w.UnwrapIncomingFromPeerEnvelope([]byte("eyJhbGciOi..."), "a.", EnvelopeJOSE); err == nil {
		t.Fatal("jose without crypto must fail")
	}
	if _, err := w.UnwrapIncomingFromPeerEnvelope(plain, "a.", EnvelopeCOSE); err == nil {
		t.Fatal("cose must fail")
	}
	if out, err := w.UnwrapIncomingFromPeerEnvelope(plain, "a.", EnvelopeUnknown); err != nil || string(out) != string(plain) {
		t.Fatalf("unlabelled plain: out=%q err=%v", out, err)
	}
}

// payloadIsJOSE reads the label when there is one and sniffs otherwise.
func TestPayloadIsJOSE(t *testing.T) {
	ctx := NewMessageContext(nil, "127.0.0.1:0")
	ctx.ChunkPayload = []byte(`{"MessageType":"sync"}`)
	if ctx.payloadIsJOSE() {
		t.Fatal("unlabelled plain JSON sniffed as JOSE")
	}
	ctx.ChunkEnvelope = EnvelopeJOSE
	if !ctx.payloadIsJOSE() {
		t.Fatal("label JOSE ignored")
	}
	ctx.ChunkEnvelope = EnvelopeNone
	ctx.ChunkPayload = []byte("bm90IGpzb24gYXQgYWxsLCBidXQgYmFzZTY0")
	if ctx.payloadIsJOSE() {
		t.Fatal("label none overridden by the sniff")
	}
}
