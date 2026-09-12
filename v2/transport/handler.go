/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Message types and payload parsing utilities for DNS transport.
 */

package transport

import (
	"encoding/json"
	"strings"
	"time"
)

// IncomingMessage is a message received via the DNS mechanism, as the
// application's parser (ChunkNotifyHandler.ParseApp) produced it. The
// router keys on TypeToken; the callback hands the whole message to the
// application.
type IncomingMessage struct {
	TypeToken       string    // the verb: transport-own ("hello", "beat", "ping", "confirm") or the application's
	DistributionID  string    // Distribution ID from QNAME (unique identifier for this CHUNK distribution)
	SenderID        string    // Sender identity (from payload OriginatorID — original author)
	TransportSender string    // Transport-level sender (from QNAME — who actually sent the DNS NOTIFY)
	Zone            string    // Zone (for zone-scoped operations)
	Nonce           string    // Nonce from the sync/update message (echoed in confirmation)
	Payload         []byte    // Raw payload (JSON)
	ReceivedAt      time.Time // When the message was received
	SourceAddr      string    // Source address of the sender
}

// parseConfirmStatus converts a status string to ConfirmStatus.
// Accepts both the legacy agent format (SUCCESS/PARTIAL/FAILED) and
// the combiner format (ok/partial/error).
func parseConfirmStatus(s string) ConfirmStatus {
	switch strings.ToUpper(s) {
	case "SUCCESS", "OK":
		return ConfirmSuccess
	case "PARTIAL":
		return ConfirmPartial
	case "FAILED", "ERROR":
		return ConfirmFailed
	case "REJECTED":
		return ConfirmRejected
	case "PENDING":
		return ConfirmPending
	case "IGNORED":
		return ConfirmIgnored
	default:
		return ConfirmFailed
	}
}

// ParseHelloPayload parses a hello message payload.
func ParseHelloPayload(payload []byte) (*DnsHelloPayload, error) {
	var p DnsHelloPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseBeatPayload parses a beat message payload.
func ParseBeatPayload(payload []byte) (*DnsBeatPayload, error) {
	var p DnsBeatPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
