package distrib

import (
	"testing"

	"github.com/johanix/tdns/v2/core"
)

func TestCreateManifestMetadata(t *testing.T) {
	extra := map[string]interface{}{
		"zone_count": 5,
		"key_count":  10,
	}

	metadata := CreateManifestMetadata("key_operations", "dist-123", "node-456", extra)

	if metadata["content"] != "key_operations" {
		t.Errorf("content should be 'key_operations', got %v", metadata["content"])
	}
	if metadata["distribution_id"] != "dist-123" {
		t.Errorf("distribution_id should be 'dist-123', got %v", metadata["distribution_id"])
	}
	if metadata["receiver_id"] != "node-456" {
		t.Errorf("receiver_id should be 'node-456', got %v", metadata["receiver_id"])
	}
	if _, ok := metadata["timestamp"]; !ok {
		t.Error("timestamp should be set")
	}
	if metadata["zone_count"] != 5 {
		t.Errorf("zone_count should be 5, got %v", metadata["zone_count"])
	}
	if metadata["key_count"] != 10 {
		t.Errorf("key_count should be 10, got %v", metadata["key_count"])
	}
}

func TestShouldIncludePayloadInline(t *testing.T) {
	tests := []struct {
		payloadSize  int
		totalSize    int
		expectInline bool
	}{
		{100, 300, true},   // Small payload, small total
		{500, 800, true},   // At threshold
		{501, 800, false},  // Just over threshold
		{100, 1200, false}, // Small payload but large total
		{600, 1000, false}, // Large payload
	}

	for _, tt := range tests {
		result := ShouldIncludePayloadInline(tt.payloadSize, tt.totalSize)
		if result != tt.expectInline {
			t.Errorf("ShouldIncludePayloadInline(%d, %d) = %v, expected %v",
				tt.payloadSize, tt.totalSize, result, tt.expectInline)
		}
	}
}

func TestEstimateManifestSize(t *testing.T) {
	metadata := map[string]interface{}{
		"content":         "test",
		"distribution_id": "dist-123",
	}
	payload := []byte("test payload")

	size := EstimateManifestSize(metadata, payload)

	// Size should be reasonable (header overhead + JSON)
	if size < 50 || size > 500 {
		t.Errorf("EstimateManifestSize returned unexpected size: %d", size)
	}
}

func TestSplitIntoCHUNKs(t *testing.T) {
	// Create 150 bytes of test data
	data := make([]byte, 150)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Split into 50-byte chunks
	chunks := SplitIntoCHUNKs(data, 50, core.FormatJSON)

	if len(chunks) != 3 {
		t.Fatalf("Expected 3 chunks, got %d", len(chunks))
	}

	// Verify chunk properties
	for i, chunk := range chunks {
		if chunk.Sequence != uint16(i+1) {
			t.Errorf("Chunk %d: expected sequence %d, got %d", i, i+1, chunk.Sequence)
		}
		if chunk.Total != 3 {
			t.Errorf("Chunk %d: expected total 3, got %d", i, chunk.Total)
		}
		if chunk.Format != core.FormatJSON {
			t.Errorf("Chunk %d: expected format %d, got %d", i, core.FormatJSON, chunk.Format)
		}
	}

	// First two chunks should be 50 bytes, last should be remaining
	if len(chunks[0].Data) != 50 {
		t.Errorf("First chunk should have 50 bytes, got %d", len(chunks[0].Data))
	}
	if len(chunks[1].Data) != 50 {
		t.Errorf("Second chunk should have 50 bytes, got %d", len(chunks[1].Data))
	}
	if len(chunks[2].Data) != 50 {
		t.Errorf("Third chunk should have 50 bytes, got %d", len(chunks[2].Data))
	}
}

func TestSplitIntoCHUNKsDefaultSize(t *testing.T) {
	data := []byte("small data")
	chunks := SplitIntoCHUNKs(data, 0, core.FormatJSON) // 0 = use default

	if len(chunks) != 1 {
		t.Errorf("Expected 1 chunk for small data, got %d", len(chunks))
	}
}

func TestReassembleCHUNKs(t *testing.T) {
	// Create test data
	data := make([]byte, 150)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Split and reassemble
	chunks := SplitIntoCHUNKs(data, 50, core.FormatJSON)
	reassembled, err := ReassembleCHUNKs(chunks)

	if err != nil {
		t.Fatalf("ReassembleCHUNKs failed: %v", err)
	}

	if len(reassembled) != len(data) {
		t.Errorf("Reassembled length %d doesn't match original %d", len(reassembled), len(data))
	}

	for i := range data {
		if reassembled[i] != data[i] {
			t.Errorf("Byte %d mismatch: expected %d, got %d", i, data[i], reassembled[i])
			break
		}
	}
}

func TestReassembleCHUNKsErrors(t *testing.T) {
	// Empty chunks
	_, err := ReassembleCHUNKs(nil)
	if err == nil {
		t.Error("Expected error for nil chunks")
	}

	_, err = ReassembleCHUNKs([]*core.CHUNK{})
	if err == nil {
		t.Error("Expected error for empty chunks")
	}

	// Mismatched total
	chunks := []*core.CHUNK{
		{Sequence: 1, Total: 2, Data: []byte("a")},
	}
	_, err = ReassembleCHUNKs(chunks)
	if err == nil {
		t.Error("Expected error for mismatched chunk count")
	}
}
