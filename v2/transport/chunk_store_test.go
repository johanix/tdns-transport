package transport

import (
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/distrib"
	"github.com/johanix/tdns/v2/core"
)

func TestMemChunkStore(t *testing.T) {
	s := newMemChunkStore(time.Hour)
	chunks := []*core.CHUNK{{Sequence: 0, Total: 1, Data: []byte("manifest")}, {Sequence: 1, Total: 1, Data: []byte("data")}}
	s.SetChunks("b.d1.a.", chunks)
	chunks[1].Data[0] = 'X' // the store keeps its own copy

	got, ok := s.GetChunk("b.d1.a.", 1)
	if !ok || string(got.Data) != "data" {
		t.Fatalf("GetChunk(1) = %q %v", got, ok)
	}
	got.Data[0] = 'Y' // and hands out copies
	again, _ := s.GetChunk("b.d1.a.", 1)
	if string(again.Data) != "data" {
		t.Fatalf("stored chunk mutated through a returned copy: %q", again.Data)
	}
	if _, ok := s.GetChunk("b.d1.a.", 2); ok {
		t.Fatal("sequence past the array must not be found")
	}
	if _, ok := s.GetChunk("other.", 0); ok {
		t.Fatal("unknown qname must not be found")
	}
	if s.Len() != 1 {
		t.Fatalf("Len = %d", s.Len())
	}

	expired := newMemChunkStore(time.Nanosecond)
	expired.SetChunks("b.d2.a.", chunks)
	time.Sleep(2 * time.Millisecond)
	if _, ok := expired.GetChunk("b.d2.a.", 0); ok {
		t.Fatal("expired entry served")
	}
}

// The manifest carries the payload's envelope label in query mode.
func TestEnvelopeFromManifest(t *testing.T) {
	chunks, err := distrib.PrepareDistributionChunks([]byte("payload"), "ping", "d1", "b.", nil, 0,
		map[string]interface{}{manifestEnvelopeKey: EnvelopeJOSE})
	if err != nil {
		t.Fatal(err)
	}
	md, err := core.ExtractManifestData(chunks[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := envelopeFromManifest(md); got != EnvelopeJOSE {
		t.Errorf("envelope from manifest = %d, want %d", got, EnvelopeJOSE)
	}
	plain, _ := distrib.PrepareDistributionChunks([]byte("payload"), "ping", "d2", "b.", nil, 0, nil)
	md2, _ := core.ExtractManifestData(plain[0])
	if got := envelopeFromManifest(md2); got != EnvelopeUnknown {
		t.Errorf("envelope from an unlabelled manifest = %d, want unknown", got)
	}
}
