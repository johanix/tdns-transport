/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CHUNK NOTIFY handler registration for multi-provider DNSSEC coordination.
 * This handler is registered via tdns.RegisterNotifyHandler() and processes
 * incoming NOTIFY(CHUNK) messages for agent-to-agent communication.
 */

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/johanix/tdns-transport/v2/distrib"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const (
	// unsolicitedWarnThreshold is the number of unsolicited messages from unauthorized
	// senders before escalating log level from Debug to Warn. This helps detect sustained
	// DoS attempts without flooding the log with individual Debug entries.
	unsolicitedWarnThreshold uint64 = 100
)

// ChunkNotifyHandler handles incoming NOTIFY(CHUNK) messages for agent communication.
// It extracts the distribution ID and payload, then routes to the appropriate handler.
type ChunkNotifyHandler struct {
	// ControlZone is the zone suffix to strip from QNAMEs to get distribution ID
	ControlZone string

	// Transport is the DNS transport for routing confirmations
	Transport *DNSTransport

	// Router handles message routing and middleware (optional, if nil uses legacy routing)
	Router *DNSMessageRouter

	// LocalID is our agent identity for filtering
	LocalID string

	// SecureWrapper handles optional JWS/JWE decryption for payloads
	SecureWrapper *SecurePayloadWrapper

	// GetPeerAddress returns the configured address (host:port) for a peer by identity.
	// Used in chunk_mode=query when NOTIFY has no EDNS0 CHUNK_QUERY_ENDPOINT: receiver uses
	// this to send the CHUNK query to the correct host:port (e.g. from agent.peers config).
	// If nil, fallback is NOTIFY source with port 53.
	GetPeerAddress func(senderID string) (address string, ok bool)

	// IsPeerAuthorized checks if a sender is authorized to send us messages.
	// This is called BEFORE expensive operations (decryption, query fetch) to prevent DoS attacks.
	// If nil, no authorization check is performed (not recommended for production).
	IsPeerAuthorized func(senderID string, zone string) (authorized bool, reason string)

	// OnPeerDiscoveryNeeded is called when we receive a message from an authorized peer
	// but don't have their verification key yet. Handler should trigger discovery asynchronously.
	OnPeerDiscoveryNeeded func(peerID string)

	// OnConfirmationReceived is called when a confirmation is received for a distribution ID.
	// Used by TransportManager to mark messages as confirmed in the ReliableMessageQueue
	// and to forward per-RR detail to the SynchedDataEngine.
	OnConfirmationReceived func(distributionID string, senderID string, status ConfirmStatus,
		zone string, applied []string, removed []string, rejected []RejectedItemDTO, ignored []string, truncated bool, nonce string)

	// GossipForPeer returns serialized gossip data for a given peer.
	// Used by handleBeat to include gossip in beat responses.
	GossipForPeer func(peerID string) json.RawMessage

	// ParseApp is the application's payload parser, and it is required.
	// After transport has fetched and decrypted the payload it calls
	// ParseApp to obtain the verb (TypeToken), the application-level
	// sender, the scope (zone) and the nonce; the field names inside the
	// payload are the application's business, transport has no parser of
	// its own. Transport-own verbs (hello, beat, ping, confirm) arrive
	// through the same parser, so it must at least read the verb and the
	// sender identity; cmd/transport-exercise shows the minimum.
	// Contract: a nil error means a non-nil message; a parser that cannot
	// produce one returns an error (the sender gets FORMERR either way).
	ParseApp func(distributionID string, payload []byte, sourceAddr string) (*IncomingMessage, error)

	// unsolicitedCount tracks rejected messages from unauthorized senders (DoS mitigation)
	// Use atomic operations to increment (accessed from multiple NOTIFY handler goroutines)
	unsolicitedCount uint64
}

// NewChunkNotifyHandler creates a new ChunkNotifyHandler.
func NewChunkNotifyHandler(controlZone, localID string, transport *DNSTransport) *ChunkNotifyHandler {
	h := &ChunkNotifyHandler{
		ControlZone: dns.Fqdn(controlZone),
		Transport:   transport,
		LocalID:     localID,
	}

	// Inherit secure wrapper from transport if available
	if transport != nil && transport.SecureWrapper != nil {
		h.SecureWrapper = transport.SecureWrapper
	}

	return h
}

// extractDistributionIDAndSender extracts the distribution ID and sender identity from a QNAME.
// QNAME format: <distributionID>.<sender-identity> e.g. "6981284f.agent.alpha.dnslab."
// The first label is the distribution ID; the rest is the sender's identity (FQDN).
// Returns (distributionID, senderID, error). senderID may be empty if QNAME has only one label.
func (h *ChunkNotifyHandler) extractDistributionIDAndSender(qname string) (distributionID, senderID string, err error) {
	qname = dns.Fqdn(qname)
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if len(labels) == 0 {
		return "", "", fmt.Errorf("empty QNAME")
	}
	distributionID = labels[0]
	if distributionID == "" {
		return "", "", fmt.Errorf("no distribution ID in QNAME %s", qname)
	}
	if len(labels) > 1 {
		senderID = dns.Fqdn(strings.Join(labels[1:], "."))
	}
	// M16: Reject empty senderID — every CHUNK NOTIFY must identify its sender
	if senderID == "" || senderID == "." {
		return "", "", fmt.Errorf("missing sender identity in QNAME %s", qname)
	}
	return distributionID, senderID, nil
}

// extractChunkPayload extracts the CHUNK payload from the EDNS0 option using ChunkOption framing.
// Returns the payload data, the format byte (FormatJSON or FormatJWT), and any error.
func (h *ChunkNotifyHandler) extractChunkPayload(msg *dns.Msg) ([]byte, uint8, error) {
	if msg == nil {
		return nil, 0, fmt.Errorf("message is nil")
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return nil, 0, fmt.Errorf("no EDNS0 OPT record")
	}

	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == edns0.EDNS0_CHUNK_OPTION_CODE {
				chunkOpt, err := edns0.ParseChunkOption(localOpt)
				if err != nil {
					return nil, 0, fmt.Errorf("invalid CHUNK option: %w", err)
				}
				return chunkOpt.Data, chunkOpt.Format, nil
			}
		}
	}

	return nil, 0, fmt.Errorf("no CHUNK EDNS0 option found")
}

// extractChunkQueryEndpointFromMsg returns the sender's CHUNK query endpoint (host:port) from NOTIFY EDNS0 option 65005, or "" if absent.
func extractChunkQueryEndpointFromMsg(msg *dns.Msg) string {
	if msg == nil {
		return ""
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		if local, ok := o.(*dns.EDNS0_LOCAL); ok && local.Code == edns0.EDNS0_CHUNK_QUERY_ENDPOINT_CODE {
			s := string(local.Data)
			if s != "" {
				return s
			}
		}
	}
	return ""
}

// fetchChunkViaQuery fetches the CHUNK payload via DNS CHUNK query when NOTIFY had no EDNS0 payload (chunk_mode=query).
// Uses manifest-first fetch: fetches manifest (sequence 0), checks if inline, otherwise fetches data chunks 1..N.
// Builds base qname as {receiver}.{distid}.{sender} and queries the sender.
// The payload's envelope label is in the manifest's metadata (F2b); a
// manifest from a sender that predates it carries none, and the receiver
// falls back to sniffing the bytes (EnvelopeUnknown).
func (h *ChunkNotifyHandler) fetchChunkViaQuery(ctx context.Context, senderID, distributionID string, msg *dns.Msg, w dns.ResponseWriter) ([]byte, uint8, error) {
	if h.Transport == nil {
		return nil, EnvelopeUnknown, fmt.Errorf("query mode needs a DNS transport to fetch the CHUNK records")
	}
	if senderID == "" {
		return nil, EnvelopeUnknown, fmt.Errorf("cannot derive sender for query mode (empty senderID)")
	}

	baseQname := buildChunkQueryQname(h.LocalID, distributionID, senderID)
	queryTarget := extractChunkQueryEndpointFromMsg(msg)
	if queryTarget == "" && h.GetPeerAddress != nil {
		if addr, ok := h.GetPeerAddress(senderID); ok && addr != "" {
			queryTarget = addr
		}
	}
	if queryTarget == "" && w != nil {
		queryTarget = w.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(queryTarget); err == nil && host != "" {
			queryTarget = net.JoinHostPort(host, "53")
		}
	}
	if queryTarget == "" {
		return nil, EnvelopeUnknown, fmt.Errorf("no CHUNK payload in EDNS0 and no CHUNK query endpoint (no EDNS0 option 65005, no peer address for %q)", senderID)
	}

	// Phase 1: Fetch manifest (sequence 0)
	manifestQname := buildChunkQueryQnameWithSeq(0, baseQname)
	manifestChunk, err := h.Transport.fetchChunkRR(ctx, queryTarget, manifestQname)
	if err != nil {
		return nil, EnvelopeUnknown, fmt.Errorf("failed to fetch manifest (seq 0): %w", err)
	}

	// Phase 2: Extract manifest data — check if payload is inline
	manifestData, err := core.ExtractManifestData(manifestChunk)
	if err != nil {
		return nil, EnvelopeUnknown, fmt.Errorf("failed to parse manifest: %w", err)
	}
	envelope := envelopeFromManifest(manifestData)
	if manifestData.ChunkCount == 0 {
		// Payload is inline in the manifest
		return manifestData.Payload, envelope, nil
	}

	// Phase 3: Fetch data chunks 1..N and reassemble
	dataChunks := make([]*core.CHUNK, 0, manifestData.ChunkCount)
	for i := uint16(1); i <= manifestData.ChunkCount; i++ {
		chunkQname := buildChunkQueryQnameWithSeq(i, baseQname)
		chunk, err := h.Transport.fetchChunkRR(ctx, queryTarget, chunkQname)
		if err != nil {
			return nil, EnvelopeUnknown, fmt.Errorf("failed to fetch chunk %d/%d: %w", i, manifestData.ChunkCount, err)
		}
		dataChunks = append(dataChunks, chunk)
	}
	payload, err := distrib.ReassembleCHUNKs(dataChunks)
	if err != nil {
		return nil, EnvelopeUnknown, err
	}
	return payload, envelope, nil
}

// sendResponse sends a DNS response with the given rcode.
func (h *ChunkNotifyHandler) sendResponse(w dns.ResponseWriter, req *dns.Msg, rcode int) error {
	if w == nil {
		return nil // No response writer, nothing to send
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Rcode = rcode

	return w.WriteMsg(resp)
}

// sendConfirmResponse sends a DNS response with an EDNS0 CHUNK confirmation payload.
// This proves to the sender that the message was received and routed (not just DNS-level ACK).
func (h *ChunkNotifyHandler) sendConfirmResponse(w dns.ResponseWriter, req *dns.Msg, distributionID, msgType, senderID string) error {
	if w == nil {
		return nil
	}

	confirmPayload := struct {
		Type           string `json:"type"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Message        string `json:"message"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "confirm",
		DistributionID: distributionID,
		Status:         "ok",
		Message:        fmt.Sprintf("%s received", msgType),
		Timestamp:      time.Now().Unix(),
	}
	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return h.sendResponse(w, req, dns.RcodeServerFailure)
	}

	// Encrypt response when SecureWrapper is configured.
	// H6: If encryption is enabled but fails, return SERVFAIL rather than sending plaintext.
	// Sending an unencrypted response when encryption is expected would leak information.
	var payloadFormat uint8 = EnvelopeNone
	if h.SecureWrapper != nil && h.SecureWrapper.IsEnabled() && senderID != "" {
		encrypted, encErr := h.SecureWrapper.wrapOutgoing(senderID, payloadBytes)
		if encErr != nil {
			lgTransport().Error("confirm response encryption failed, refusing to send plaintext", "peer", senderID, "err", encErr)
			return h.sendResponse(w, req, dns.RcodeServerFailure)
		}
		payloadBytes = encrypted
		payloadFormat = EnvelopeJOSE
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	resp.SetEdns0(4096, true)
	opt := resp.IsEdns0()
	if opt != nil {
		opt.Option = append(opt.Option, edns0.CreateChunkOption(payloadFormat, nil, payloadBytes))
	}
	return w.WriteMsg(resp)
}

// createNotifyHandlerFunc creates a function compatible with tdns.NotifyHandlerFunc.
// This is a helper that wraps RouteViaRouter for use with tdns.RegisterNotifyHandler.
//
// Usage in agent initialization:
//
//	handler := transport.NewChunkNotifyHandler(controlZone, localID, dnsTransport)
//	handlerFunc := handler.createNotifyHandlerFunc()
//	tdns.RegisterNotifyHandler(core.TypeCHUNK, handlerFunc)
//
// Note: The returned function adapts to the tdns.NotifyHandlerFunc signature:
//
//	func(ctx context.Context, req *tdns.DnsNotifyRequest) error
func (h *ChunkNotifyHandler) createNotifyHandlerFunc() interface{} {
	// Return a closure that can be type-asserted to the correct signature
	// in the calling code that has access to tdns types
	return func(ctx context.Context, qname string, msg *dns.Msg, w dns.ResponseWriter) error {
		return h.RouteViaRouter(ctx, qname, msg, w)
	}
}

// unsolicitedMessageCount returns the number of rejected messages from unauthorized senders.
// This counter is used for DoS attack monitoring and should be exported via metrics/monitoring.
func (h *ChunkNotifyHandler) unsolicitedMessageCount() uint64 {
	return atomic.LoadUint64(&h.unsolicitedCount)
}

// RouteViaRouter routes a message through the DNS message router with middleware.
// This is the only routing path — the router must be configured.
func (h *ChunkNotifyHandler) RouteViaRouter(ctx context.Context, qname string, msg *dns.Msg, w dns.ResponseWriter) error {
	if h.Router == nil {
		lgTransport().Error("router is nil, cannot route message", "qname", qname)
		return fmt.Errorf("router not configured")
	}
	if h.ParseApp == nil {
		lgTransport().Error("no payload parser installed, cannot route message", "qname", qname)
		return fmt.Errorf("ParseApp not configured")
	}

	sourceAddr := ""
	if w != nil {
		sourceAddr = w.RemoteAddr().String()
	}

	lgTransport().Debug("received NOTIFY(CHUNK)", "qname", qname, "source", sourceAddr)

	// Extract distribution ID and sender identity from QNAME
	distributionID, senderHint, err := h.extractDistributionIDAndSender(qname)
	if err != nil {
		lgTransport().Error("failed to extract distribution ID", "qname", qname, "err", err)
		return h.sendResponse(w, msg, dns.RcodeFormatError)
	}

	// H8: Pre-crypto authorization check. Reject unknown senders BEFORE doing any expensive
	// crypto or query operations. This prevents DoS attacks where an attacker sends messages
	// with forged sender identities to force expensive decryption attempts.
	// Note: zone is not yet known at this point (it's inside the encrypted payload), so we
	// pass "" — the callback should check if the sender is known at all.
	if h.IsPeerAuthorized != nil {
		authorized, reason := h.IsPeerAuthorized(senderHint, "")
		if !authorized {
			count := atomic.AddUint64(&h.unsolicitedCount, 1)
			// M18: Escalate log level when unsolicited count exceeds threshold
			if count%unsolicitedWarnThreshold == 0 {
				lgTransport().Warn("sustained unsolicited messages from unauthorized senders",
					"total_count", count, "latest_peer", senderHint, "source", sourceAddr, "reason", reason)
			} else {
				lgTransport().Debug("rejected message from unauthorized sender",
					"peer", senderHint, "source", sourceAddr, "reason", reason)
			}
			return h.sendResponse(w, msg, dns.RcodeRefused)
		}
	}

	// Extract CHUNK payload: first try EDNS0 (edns0 mode); if absent, fetch via CHUNK query (query mode)
	payload, envelope, err := h.extractChunkPayload(msg)
	if err != nil {
		// Query mode: NOTIFY has no EDNS0 payload; fetch using {receiver}.{distid}.{sender} from sender
		payload, envelope, err = h.fetchChunkViaQuery(ctx, senderHint, distributionID, msg, w)
		if err != nil {
			lgTransport().Error("failed to get CHUNK payload (EDNS0 and query mode)", "err", err)
			return h.sendResponse(w, msg, dns.RcodeFormatError)
		}
	}
	// The envelope label decides what happens next; a label the receiver
	// cannot handle is a malformed message, answered before any crypto.
	if err := checkEnvelope(envelope); err != nil {
		lgTransport().Warn("rejecting payload", "source", sourceAddr, "peer", senderHint, "err", err)
		return h.sendResponse(w, msg, dns.RcodeFormatError)
	}
	if envelope == EnvelopeJOSE && (h.SecureWrapper == nil || !h.SecureWrapper.IsEnabled()) {
		lgTransport().Warn("JOSE-wrapped payload but payload crypto is not enabled", "source", sourceAddr, "peer", senderHint)
		return h.sendResponse(w, msg, dns.RcodeFormatError)
	}

	// Decrypt the payload if it is encrypted.
	// SECURITY: Use strict decryption — ONLY try the claimed sender's key.
	// H7: No combiner key fallback. If decryption fails with the sender's key, reject.
	if h.SecureWrapper != nil {
		lgTransport().Debug("attempting to decrypt payload", "source", sourceAddr, "key_for", senderHint)

		decrypted, err := h.SecureWrapper.unwrapIncomingFromPeerEnvelope(payload, senderHint, envelope)
		if err != nil {
			// H5: Use sentinel error instead of string matching
			if errors.Is(err, ErrNoVerificationKey) {
				lgTransport().Info("missing verification key, triggering discovery", "peer", senderHint, "source", sourceAddr)
				if h.OnPeerDiscoveryNeeded != nil {
					go h.OnPeerDiscoveryNeeded(senderHint)
				}
				// Drop this message — sender will retry and we'll have the key by then
				return nil
			}

			// Decryption failed with the claimed sender's key — possible forgery
			lgTransport().Warn("SECURITY: decryption failed for NOTIFY, possible forgery",
				"source", sourceAddr, "claimed_peer", senderHint, "err", err)
			return h.sendResponse(w, msg, dns.RcodeRefused)
		}
		payload = decrypted
		lgTransport().Debug("successfully decrypted payload", "source", sourceAddr, "key_for", senderHint)
	}

	return h.route(ctx, routeInput{
		distributionID: distributionID,
		senderHint:     senderHint,
		payload:        payload,
		envelope:       envelope,
		sourceAddr:     sourceAddr,
		mechanism:      MechanismDNS,
		request:        msg,
	}, dnsReply{w: w, msg: msg})
}

// Mechanism names as IncomingMessage.Mechanism carries them.
const (
	MechanismDNS = "DNS"
	MechanismAPI = "API"
)

// RouteAPIPayload is the receive pipeline's entry for the HTTPS mechanism:
// the body of a POST to one of the sync API endpoints, already
// authenticated by TLS and the application's TLSA check, and not
// encrypted at the payload level. It is parsed with the application's
// parser, the sender it names is authorized (at all, then for the zone),
// the verb is routed like a NOTIFY(CHUNK)'s, and the answer goes to the
// sink the application supplies, which shapes the HTTP response.
func (h *ChunkNotifyHandler) RouteAPIPayload(ctx context.Context, payload []byte, sourceAddr string, sink ReplySink) error {
	if h.Router == nil {
		lgTransport().Error("router is nil, cannot route API message", "source", sourceAddr)
		return sink.Fail(dns.RcodeServerFailure)
	}
	if h.ParseApp == nil {
		lgTransport().Error("no payload parser installed, cannot route API message", "source", sourceAddr)
		return sink.Fail(dns.RcodeServerFailure)
	}
	return h.route(ctx, routeInput{
		distributionID: GenerateDistributionID(),
		payload:        payload,
		envelope:       EnvelopeNone,
		sourceAddr:     sourceAddr,
		mechanism:      MechanismAPI,
	}, sink)
}

// routeInput is what the pipeline tail needs from either entry.
type routeInput struct {
	distributionID string
	// senderHint is the transport-level sender when the mechanism names
	// one before the payload is read (the NOTIFY query name); empty means
	// the parsed message names the sender, and the sender authorization
	// that the DNS entry ran before decryption runs after parsing instead.
	senderHint string
	payload    []byte // plaintext
	envelope   uint8  // the label as received (kept on the context for the record)
	sourceAddr string
	mechanism  string
	request    *dns.Msg // the DNS request, nil for the HTTPS mechanism
}

// route is the pipeline tail shared by both mechanisms: parse, authorize
// the sender for the zone, build the context, run the router under the
// reply wrapper.
func (h *ChunkNotifyHandler) route(ctx context.Context, in routeInput, sink ReplySink) error {
	// Parse the payload with the application's parser; the result carries
	// the verb transport routes on.
	incomingMsg, err := h.ParseApp(in.distributionID, in.payload, in.sourceAddr)
	if err != nil {
		lgTransport().Error("failed to parse payload", "err", err)
		return sink.Fail(dns.RcodeFormatError)
	}
	if incomingMsg == nil {
		lgTransport().Error("payload parser returned no message", "distrib", in.distributionID, "source", in.sourceAddr)
		return sink.Fail(dns.RcodeFormatError)
	}

	senderHint := in.senderHint
	if senderHint == "" {
		// The HTTPS mechanism: the parsed message names the sender, and
		// the "known at all" authorization the DNS entry ran before its
		// crypto runs here.
		senderHint = incomingMsg.SenderID
		if senderHint == "" {
			lgTransport().Warn("message names no sender", "source", in.sourceAddr, "mechanism", in.mechanism)
			return sink.Fail(dns.RcodeFormatError)
		}
		if h.IsPeerAuthorized != nil {
			if authorized, reason := h.IsPeerAuthorized(senderHint, ""); !authorized {
				count := atomic.AddUint64(&h.unsolicitedCount, 1)
				if count%unsolicitedWarnThreshold == 0 {
					lgTransport().Warn("sustained unsolicited messages from unauthorized senders",
						"total_count", count, "latest_peer", senderHint, "source", in.sourceAddr, "reason", reason)
				} else {
					lgTransport().Debug("rejected message from unauthorized sender",
						"peer", senderHint, "source", in.sourceAddr, "reason", reason)
				}
				return sink.Fail(dns.RcodeRefused)
			}
		}
	}
	// Set the transport-level sender — distinct from SenderID (payload OriginatorID).
	// For forwarded messages, SenderID is the original author while TransportSender is the relay agent.
	incomingMsg.TransportSender = senderHint
	incomingMsg.Mechanism = in.mechanism

	msgType := MessageType(incomingMsg.Token())
	lgTransport().Debug("determined message type", "type", msgType, "sender", incomingMsg.SenderID, "transport_sender", senderHint, "mechanism", in.mechanism)

	// Create message context
	msgCtx := NewMessageContext(in.request, in.sourceAddr)
	msgCtx.DistributionID = in.distributionID
	msgCtx.PeerID = senderHint
	msgCtx.ChunkPayload = in.payload
	msgCtx.RemoteAddr = in.sourceAddr
	// The payload is plaintext now. The label as received is kept for the record.
	msgCtx.ChunkEnvelope = EnvelopeNone
	msgCtx.setWireEnvelope(in.envelope)
	// Local identity, so handlers (e.g. ping) can include it in responses
	msgCtx.setLocalID(h.LocalID)
	// Transport, for confirmation handling
	if h.Transport != nil {
		msgCtx.setDNSTransport(h.Transport)
	}
	// SecureWrapper + peer ID, so the DNS reply can encrypt the response;
	// the HTTPS mechanism carries no payload crypto.
	if h.SecureWrapper != nil && in.mechanism == MechanismDNS {
		msgCtx.SetSecureWrapper(h.SecureWrapper)
	}
	msgCtx.setResponsePeerID(senderHint)
	if h.OnConfirmationReceived != nil {
		msgCtx.setConfirmationCallback(h.OnConfirmationReceived)
	}
	if h.GossipForPeer != nil {
		msgCtx.setGossipForPeer(h.GossipForPeer)
	}
	// The parsed message, so handlers don't need to re-parse
	msgCtx.SetIncoming(incomingMsg)
	// The zone, for the zone-peer authorization below
	if incomingMsg.Zone != "" {
		msgCtx.setZone(incomingMsg.Zone)
		lgTransport().Debug("extracted zone for authorization", "zone", incomingMsg.Zone)
	} else if msgType == MessageType(VerbBeat) {
		// For beat messages, extract zones from the Zones array
		var beatPayload struct {
			Zones []string `json:"Zones"`
		}
		// M11: payload is wire-sourced (bounded by message size), safe to unmarshal without size limit
		if err := json.Unmarshal(in.payload, &beatPayload); err == nil && len(beatPayload.Zones) > 0 {
			// Use first shared zone for authorization
			msgCtx.setZone(beatPayload.Zones[0])
			lgTransport().Debug("extracted zone from beat for authorization", "zone", beatPayload.Zones[0])
		}
	}

	// M20: Zone-peer authorization check. Now that we have the zone from the payload,
	// verify that this peer is authorized for this specific zone. The pre-crypto check
	// only verified the peer is known at all (zone=""); this check validates the zone-peer binding.
	if h.IsPeerAuthorized != nil {
		if zone := msgCtx.Zone(); zone != "" {
			authorized, reason := h.IsPeerAuthorized(senderHint, zone)
			if !authorized {
				lgTransport().Warn("peer not authorized for zone", "peer", senderHint, "zone", zone, "reason", reason)
				return sink.Fail(dns.RcodeRefused)
			}
		}
	}

	// Route through router (middleware + handlers); the reply wrapper answers.
	err = replyMiddleware(sink)(msgCtx, func(ctx *MessageContext) error {
		return h.Router.Route(ctx, msgType)
	})
	if err != nil {
		lgTransport().Error("routing failed", "err", err)
		return sink.Fail(dns.RcodeServerFailure)
	}
	return nil
}
