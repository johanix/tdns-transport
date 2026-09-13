/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * The byte sniff that survives as the fallback for an unlabelled payload
 * (query mode, until F2b labels it).
 */

package transport

import "testing"

func TestIsPayloadEncrypted(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		{
			name:     "JSON payload",
			payload:  []byte(`{"test":"value"}`),
			expected: false,
		},
		{
			name:     "Empty payload",
			payload:  []byte{},
			expected: false,
		},
		{
			name:     "Base64 encrypted",
			payload:  []byte("YmFzZTY0ZW5jb2RlZA=="),
			expected: true,
		},
		{
			name:     "Invalid base64",
			payload:  []byte("not-base64!@#"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPayloadEncrypted(tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for payload: %s", tt.expected, result, tt.payload)
			}
		})
	}
}
