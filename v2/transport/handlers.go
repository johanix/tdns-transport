/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Refactored message handlers using the DNS message router.
 * Replaces the monolithic chunk_notify_handler.go with modular handlers.
 */

package transport

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// HandleConfirmation processes confirmation messages.
// Routes the confirmation to the transport's reliable message queue and
// forwards per-RR detail to the SynchedDataEngine via OnConfirmationReceived.
func HandleConfirmation(ctx *MessageContext) error {
	lgTransport().Debug("processing confirmation", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	// Parse the confirmation message.
	// Size bounded: ctx.ChunkPayload originates from a DNS message (max ~65535 bytes over TCP).
	var confirm DnsConfirmPayload
	if err := json.Unmarshal(ctx.ChunkPayload, &confirm); err != nil {
		return fmt.Errorf("failed to parse confirmation: %w", err)
	}

	status := parseConfirmStatus(confirm.Status)

	// Forward to transport's reliable message queue (marks distribution as confirmed).
	if transport := ctx.DNSTransport(); transport != nil {
		transport.HandleIncomingConfirmation(&IncomingConfirmation{
			DistributionID: confirm.DistributionID,
			PeerID:         confirm.SenderID,
			Status:         status,
			Message:        confirm.Message,
			Timestamp:      time.Unix(confirm.Timestamp, 0),
			Zone:           confirm.Zone,
			AppliedRecords: confirm.AppliedRecords,
			RemovedRecords: confirm.RemovedRecords,
			RejectedItems:  confirm.RejectedItems,
			IgnoredRecords: confirm.IgnoredRecords,
			Truncated:      confirm.Truncated,
			Nonce:          confirm.Nonce,
		})
	}

	// Forward confirmation detail to the application's consumer
	if cb := ctx.ConfirmationCallback(); cb != nil && confirm.DistributionID != "" {
		cb(confirm.DistributionID, confirm.SenderID, status,
			confirm.Zone, confirm.AppliedRecords, confirm.RemovedRecords, confirm.RejectedItems, confirm.IgnoredRecords, confirm.Truncated, confirm.Nonce)
	}

	lgTransport().Debug("confirmation processed", "peer", ctx.PeerID, "status", confirm.Status)
	return nil
}

// HandlePing processes ping messages and sends immediate response.
func HandlePing(ctx *MessageContext) error {
	lgTransport().Info("HandlePing: enter", "peer", ctx.PeerID, "distrib", ctx.DistributionID,
		"payload_len", len(ctx.ChunkPayload), "wire_envelope", EnvelopeString(ctx.WireEnvelope()))

	// Log the raw payload for debugging (truncate if long)
	payloadStr := string(ctx.ChunkPayload)
	if len(payloadStr) > 500 {
		payloadStr = payloadStr[:500] + "..."
	}
	lgTransport().Debug("HandlePing: raw payload", "payload", payloadStr)

	// Get the pre-parsed message from context (set by RouteViaRouter)
	incomingMsg, ok := ctx.Incoming()
	if ok {
		lgTransport().Debug("HandlePing: pre-parsed message", "type", incomingMsg.Token(), "sender", incomingMsg.SenderID, "zone", incomingMsg.Zone)
		// Use pre-parsed message for type check
		if incomingMsg.Token() != "ping" {
			return fmt.Errorf("invalid message type for ping handler: %s", incomingMsg.Token())
		}
	} else {
		lgTransport().Debug("HandlePing: no pre-parsed incoming_message in context")
	}

	// Parse the ping message using DnsPingPayload (handles both standard and legacy field names)
	var ping DnsPingPayload
	if err := json.Unmarshal(ctx.ChunkPayload, &ping); err != nil {
		return fmt.Errorf("failed to parse ping: %w (payload: %s)", err, payloadStr)
	}

	lgTransport().Debug("HandlePing: parsed ping", "type", ping.Type, "msgtype", ping.MessageType,
		"nonce", ping.Nonce, "sender", ping.SenderID, "myid", ping.MyIdentity)

	if !ok && ping.Type != "ping" && ping.MessageType != "ping" {
		return fmt.Errorf("invalid message type for ping handler: type=%s MessageType=%s", ping.Type, ping.MessageType)
	}

	if ping.Nonce == "" {
		return fmt.Errorf("ping has empty nonce (payload: %s)", payloadStr)
	}

	// Local identity, set by RouteViaRouter; "" when it is not known.
	localID := ctx.LocalID()

	// Create confirmation response matching DnsPingConfirmPayload format
	confirmation := &DnsPingConfirmPayload{
		Type:           "ping_confirm",
		SenderID:       localID,
		Nonce:          ping.Nonce,
		DistributionID: ctx.DistributionID,
		Status:         "ok",
		Timestamp:      time.Now().Unix(),
	}

	confirmPayload, err := json.Marshal(confirmation)
	if err != nil {
		return fmt.Errorf("failed to marshal ping confirmation: %w", err)
	}

	// Store confirmation in context for response middleware
	ctx.SetResponsePayload(confirmPayload)
	ctx.SetHandledType("ping")

	lgTransport().Debug("ping processed", "peer", ctx.PeerID, "nonce", ping.Nonce)
	return nil
}

// HandleHello processes hello messages for peer introduction.
func HandleHello(ctx *MessageContext) error {
	lgTransport().Debug("processing hello", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	// The parsed message, stored by RouteViaRouter before the router was
	// entered; a router entered without it is misused.
	helloMsg, ok := ctx.Incoming()
	if !ok {
		return fmt.Errorf("hello handler: no parsed message in context")
	}

	if helloMsg.Token() != "hello" {
		return fmt.Errorf("invalid message type for hello handler: %s", helloMsg.Token())
	}

	// Store for the callback to the application
	ctx.SetIncoming(helloMsg)
	ctx.SetHandledType("hello")

	lgTransport().Debug("hello processed", "peer", ctx.PeerID)
	return nil
}

// HandleBeat processes heartbeat messages.
// Works for both agent and combiner — the confirm response is always constructed,
// and the RouteToCallback middleware hands the message to the application for further processing.
func HandleBeat(ctx *MessageContext) error {
	lgTransport().Debug("processing beat", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	// The parsed message, stored by RouteViaRouter before the router was
	// entered; a router entered without it is misused.
	beatMsg, ok := ctx.Incoming()
	if !ok {
		return fmt.Errorf("beat handler: no parsed message in context")
	}

	if beatMsg.Token() != "beat" {
		return fmt.Errorf("invalid message type for beat handler: %s", beatMsg.Token())
	}

	// Store for the callback to the application
	ctx.SetIncoming(beatMsg)
	ctx.SetHandledType("beat")

	// Construct confirm response with optional gossip (used by both agent and combiner)
	confirmPayload := struct {
		Type           string          `json:"type"`
		DistributionID string          `json:"distribution_id"`
		Status         string          `json:"status"`
		Message        string          `json:"message"`
		Timestamp      int64           `json:"timestamp"`
		Gossip         json.RawMessage `json:"Gossip,omitempty"`
	}{
		Type:           "confirm",
		DistributionID: ctx.DistributionID,
		Status:         "ok",
		Message:        "beat acknowledged",
		Timestamp:      time.Now().Unix(),
	}

	// Include our gossip for the sender in the response
	if gossipFn := ctx.GossipForPeer(); gossipFn != nil {
		confirmPayload.Gossip = gossipFn(ctx.PeerID)
	}

	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		lgTransport().Error("failed to marshal beat confirm", "err", err)
	} else {
		ctx.SetResponsePayload(payloadBytes)
	}

	lgTransport().Debug("beat processed", "peer", ctx.PeerID)
	return nil
}

// DefaultUnsupportedHandler returns a handler for message types that have no
// registered handler. Instead of returning an error (which causes SERVFAIL),
// it sends a clean REFUSED response with an error payload explaining that the
// message type is not supported.
func DefaultUnsupportedHandler(ctx *MessageContext) error {
	msgType := "unknown"
	if mt, ok := ctx.UnhandledType(); ok {
		msgType = mt
	}

	lgTransport().Warn("unsupported message type", "type", msgType, "peer", ctx.PeerID)

	errorPayload := struct {
		Type           string `json:"type"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Message        string `json:"message"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "error",
		DistributionID: ctx.DistributionID,
		Status:         "unsupported",
		Message:        fmt.Sprintf("message type %q not supported", msgType),
		Timestamp:      time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(errorPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal unsupported-type error response: %w", err)
	}

	ctx.SetResponsePayload(payloadBytes)
	ctx.SetResponseRcode(dns.RcodeRefused)
	return nil
}

// encryptResponsePayload encrypts a response payload if the context carries
// an enabled SecureWrapper. Returns the (possibly encrypted) payload and the
// appropriate format byte.
func encryptResponsePayload(ctx *MessageContext, payload []byte) ([]byte, uint8) {
	if sw := ctx.SecureWrapper(); sw != nil && sw.IsEnabled() {
		if peerID := ctx.ResponsePeerID(); peerID != "" {
			if encrypted, err := sw.WrapOutgoing(peerID, payload); err == nil {
				return encrypted, sw.Envelope()
			} else {
				lgTransport().Error("response encryption failed", "peer", peerID, "err", err)
			}
		}
	}
	return payload, core.FormatJSON
}

// SendResponseMiddleware sends the DNS response after all handlers complete.
// This middleware should be the outermost one (last to wrap, first to execute on return).
func SendResponseMiddleware(w dns.ResponseWriter, msg *dns.Msg) MiddlewareFunc {
	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		// Execute the handler chain
		err := next(ctx)

		// Determine response code
		rcode := dns.RcodeSuccess
		if err != nil {
			lgTransport().Error("handler error", "err", err)
			rcode = dns.RcodeServerFailure
		}

		// An explicit rcode (set by the default handler, etc.) wins
		if rc, ok := ctx.ResponseRcode(); ok {
			rcode = rc
		}

		// The handler's own response payload (the inline confirmation)
		if payload, ok := ctx.ResponsePayload(); ok {
			payload, format := encryptResponsePayload(ctx, payload)
			return sendChunkResponse(w, msg, payload, format, rcode)
		}

		// Build a generic EDNS0 confirmation for all other message types (hello, beat, etc).
		// The sender requires an EDNS0 CHUNK confirmation to distinguish "message received
		// and processed" from a bare DNS ACK (which could come from any DNS server).
		if rcode == dns.RcodeSuccess {
			confirmPayload := struct {
				Type           string `json:"type"`
				DistributionID string `json:"distribution_id"`
				Status         string `json:"status"`
				Message        string `json:"message"`
				Timestamp      int64  `json:"timestamp"`
			}{
				Type:           "confirm",
				DistributionID: ctx.DistributionID,
				Status:         "ok",
				Message:        "received",
				Timestamp:      time.Now().Unix(),
			}
			payloadBytes, marshalErr := json.Marshal(confirmPayload)
			if marshalErr == nil {
				payloadBytes, format := encryptResponsePayload(ctx, payloadBytes)
				return sendChunkResponse(w, msg, payloadBytes, format, rcode)
			}
		}
		return sendStandardResponse(w, msg, rcode)
	}
}

// sendChunkResponse sends a DNS response with CHUNK payload in EDNS0.
func sendChunkResponse(w dns.ResponseWriter, req *dns.Msg, payload []byte, format uint8, rcode int) error {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = rcode

	// Add EDNS0 with CHUNK option using proper framing
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)

	opt.Option = append(opt.Option, edns0.CreateChunkOption(format, nil, payload))
	resp.Extra = append(resp.Extra, opt)

	return w.WriteMsg(resp)
}

// sendStandardResponse sends a standard DNS response without CHUNK.
func sendStandardResponse(w dns.ResponseWriter, req *dns.Msg, rcode int) error {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = rcode
	return w.WriteMsg(resp)
}

// RouteToCallback creates middleware that calls a callback function
// for each successfully processed message. The callback receives
// the parsed IncomingMessage and can dispatch to typed channels,
// process inline, or route however the application needs.
//
// Applications register this instead of consuming a channel; they get
// per-type fan-out instead of a single IncomingChan.
//
// The callback runs in the DNS server goroutine — it must be
// non-blocking (e.g., push to a buffered channel and return).
func RouteToCallback(fn func(*IncomingMessage)) MiddlewareFunc {
	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		err := next(ctx)
		if err != nil {
			return err
		}

		// A verb with no registered handler was answered REFUSED by
		// DefaultUnsupportedHandler. It must not also be delivered to the
		// application: before this guard an agent processed an "update"
		// it had just refused on the wire (C0.5 dispatch gate).
		if _, unhandled := ctx.UnhandledType(); unhandled {
			return nil
		}

		if incomingMsg, ok := ctx.Incoming(); ok {
			fn(incomingMsg)
		}

		return nil
	}
}
