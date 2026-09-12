/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The wire form of transport's own verbs on the DNS mechanism (C4b,
 * cleanup plan step 3): what a hello, beat and ping NOTIFY(CHUNK) carries.
 *
 * These structs replace the tdns core Agent*Post structs the senders used
 * to marshal, byte for byte: every JSON key, its order and its omission
 * rules are the same, and testdata/golden-wire pins them. The receive side
 * still parses with DnsHelloPayload, DnsBeatPayload and DnsPingPayload
 * (dns.go), which also accept the legacy lower-case field names; the two
 * describe the same wire and change together.
 *
 * Until tdns's core/messages.go is retired, the tdns copies of these
 * structs still exist for the HTTPS mechanism; transport owns the DNS
 * wire, and the goldens are the drift detector.
 */

package transport

import (
	"encoding/json"
	"time"

	"github.com/miekg/dns"
)

// Transport's own verbs, as they appear on the wire and as the router keys
// on them.
const (
	VerbHello   = "hello"
	VerbBeat    = "beat"
	VerbPing    = "ping"
	VerbConfirm = "confirm"
)

// HelloPost is the hello payload as sent over DNS.
//
// TLSA is a deprecated field with no value, kept because encoding/json
// does not omit a zero struct under omitempty, so every hello on the wire
// carries it and the byte-identity gate requires it. It goes at the next
// declared wire break (F1).
type HelloPost struct {
	MessageType  string
	MyIdentity   string   // Sender identity (FQDN)
	YourIdentity string   // Recipient identity (FQDN)
	TLSA         dns.TLSA `json:"tlsa,omitempty"` // DEPRECATED, see above
	Zone         string   // Zone that triggered this hello (one zone per hello)
	Time         time.Time
}

// BeatPost is the beat payload as sent over DNS.
type BeatPost struct {
	MessageType    string
	MyIdentity     string   // Sender identity
	YourIdentity   string   // Recipient identity
	MyBeatInterval uint32   // Intended beat interval in seconds
	Zones          []string // Zones the sender believes it shares with the peer
	Time           time.Time
	Gossip         json.RawMessage `json:"Gossip,omitempty"` // Opaque application data piggybacked on the beat
}

// PingPost is the ping payload as sent over DNS.
type PingPost struct {
	MessageType  string
	MyIdentity   string // Sender identity
	YourIdentity string // Recipient identity
	Nonce        string // Echoed by the receiver
	Time         time.Time
}

// buildHelloPost is the hello DNSTransport.Hello sends: the first shared
// zone is the hello's zone.
func buildHelloPost(req *HelloRequest, peerID string) *HelloPost {
	var zone string
	if len(req.SharedZones) > 0 {
		zone = req.SharedZones[0]
	}
	return &HelloPost{
		MessageType:  VerbHello,
		MyIdentity:   req.SenderID,
		YourIdentity: peerID,
		Zone:         zone,
		Time:         req.Timestamp,
	}
}

// buildBeatPost is the beat DNSTransport.Beat sends.
func buildBeatPost(req *BeatRequest, peerID string) *BeatPost {
	return &BeatPost{
		MessageType:  VerbBeat,
		MyIdentity:   req.SenderID,
		YourIdentity: peerID,
		Time:         req.Timestamp,
		Zones:        req.Zones,
		Gossip:       req.Gossip,
	}
}

// buildPingPost is the ping DNSTransport.Ping sends.
func buildPingPost(req *PingRequest, peerID string) *PingPost {
	return &PingPost{
		MessageType:  VerbPing,
		MyIdentity:   req.SenderID,
		YourIdentity: peerID,
		Nonce:        req.Nonce,
		Time:         req.Timestamp,
	}
}
