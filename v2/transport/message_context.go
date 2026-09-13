/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Typed access to what the receive pipeline and the application exchange
 * through MessageContext.Data (cleanup plan, step 1).
 *
 * RouteViaRouter populates the context before it calls Router.Route; the
 * transport-own handlers, the response wrapper, the callback wrapper and the
 * application's verb handlers read and write it. The string keys are the
 * contract that existed before these accessors and are unchanged, so a
 * consumer that still reads Data directly keeps working; new code uses the
 * accessors and never spells a key.
 */

package transport

import "encoding/json"

const (
	ctxKeyIncoming        = "incoming_message"
	ctxKeyResponse        = "response"
	ctxKeyResponseRcode   = "response_rcode"
	ctxKeyResponsePeerID  = "response_peer_id"
	ctxKeyLocalID         = "local_id"
	ctxKeyTransport       = "transport"
	ctxKeySecureWrapper   = "secure_wrapper"
	ctxKeyConfirmCallback = "on_confirmation_received"
	ctxKeyGossipForPeer   = "gossip_for_peer"
	ctxKeyZone            = "zone"
	ctxKeyWireEnvelope    = "wire_envelope"
	ctxKeyUnhandledType   = "unhandled_message_type"
	ctxKeyHandledType     = "message_type"
)

// ConfirmationCallback is what a role that sends confirmed distributions
// installs as ChunkNotifyHandler.OnConfirmationReceived. HandleConfirmation
// calls it with the parsed confirmation. It is an alias of the field's
// function type, so a value stored through either name is the same type.
type ConfirmationCallback = func(distributionID string, senderID string, status ConfirmStatus,
	zone string, applied []string, removed []string, rejected []RejectedItemDTO, ignored []string, truncated bool, nonce string)

// GossipProvider returns the gossip the local node wants to piggyback on a
// beat response to the named peer, or nil.
type GossipProvider = func(peerID string) json.RawMessage

// Incoming returns the parsed message the pipeline stored for the handlers.
func (ctx *MessageContext) Incoming() (*IncomingMessage, bool) {
	m, ok := ctx.Data[ctxKeyIncoming].(*IncomingMessage)
	return m, ok && m != nil
}

// SetIncoming stores the parsed message for the handlers and the callback.
func (ctx *MessageContext) SetIncoming(m *IncomingMessage) {
	ctx.Data[ctxKeyIncoming] = m
}

// SetResponsePayload sets the application payload the response wrapper puts
// in the EDNS0 CHUNK option of the DNS response (the inline confirmation).
func (ctx *MessageContext) SetResponsePayload(payload []byte) {
	ctx.Data[ctxKeyResponse] = payload
}

// responsePayload returns the payload set by SetResponsePayload.
func (ctx *MessageContext) responsePayload() ([]byte, bool) {
	p, ok := ctx.Data[ctxKeyResponse].([]byte)
	return p, ok
}

// SetResponseRcode overrides the rcode of the DNS response (REFUSED for an
// unsupported verb, for example). Without it the wrapper answers NOERROR
// on success and SERVFAIL on a handler error.
func (ctx *MessageContext) SetResponseRcode(rcode int) {
	ctx.Data[ctxKeyResponseRcode] = rcode
}

// responseRcode returns the override set by SetResponseRcode.
func (ctx *MessageContext) responseRcode() (int, bool) {
	rc, ok := ctx.Data[ctxKeyResponseRcode].(int)
	return rc, ok
}

// LocalID is the receiving node's own identity, for handlers that name it
// in a response.
func (ctx *MessageContext) LocalID() string {
	id, _ := ctx.Data[ctxKeyLocalID].(string)
	return id
}

// setLocalID records the receiving node's identity.
func (ctx *MessageContext) setLocalID(id string) {
	ctx.Data[ctxKeyLocalID] = id
}

// Zone is the zone the message is about, as the pipeline extracted it for
// the zone authorization; empty for a scope-less message.
func (ctx *MessageContext) Zone() string {
	z, _ := ctx.Data[ctxKeyZone].(string)
	return z
}

// setZone records the message's zone.
func (ctx *MessageContext) setZone(zone string) {
	ctx.Data[ctxKeyZone] = zone
}

// responsePeerID is the identity the response is encrypted for.
func (ctx *MessageContext) responsePeerID() string {
	id, _ := ctx.Data[ctxKeyResponsePeerID].(string)
	return id
}

// setResponsePeerID records the identity the response is encrypted for.
func (ctx *MessageContext) setResponsePeerID(id string) {
	ctx.Data[ctxKeyResponsePeerID] = id
}

// SecureWrapper is the payload crypto the response wrapper encrypts with,
// or nil when the receiver runs without payload crypto.
func (ctx *MessageContext) SecureWrapper() *SecurePayloadWrapper {
	sw, _ := ctx.Data[ctxKeySecureWrapper].(*SecurePayloadWrapper)
	return sw
}

// SetSecureWrapper records the payload crypto for the response.
func (ctx *MessageContext) SetSecureWrapper(sw *SecurePayloadWrapper) {
	ctx.Data[ctxKeySecureWrapper] = sw
}

// DNSTransport is the receiving node's DNS transport, which the confirm
// handler tells about an incoming confirmation; nil on a role without one.
func (ctx *MessageContext) DNSTransport() *DNSTransport {
	t, _ := ctx.Data[ctxKeyTransport].(*DNSTransport)
	return t
}

// setDNSTransport records the receiving node's DNS transport.
func (ctx *MessageContext) setDNSTransport(t *DNSTransport) {
	ctx.Data[ctxKeyTransport] = t
}

// ConfirmationCallback is the application's confirmation consumer, or nil.
func (ctx *MessageContext) ConfirmationCallback() ConfirmationCallback {
	cb, _ := ctx.Data[ctxKeyConfirmCallback].(ConfirmationCallback)
	return cb
}

// setConfirmationCallback records the application's confirmation consumer.
func (ctx *MessageContext) setConfirmationCallback(cb ConfirmationCallback) {
	ctx.Data[ctxKeyConfirmCallback] = cb
}

// GossipForPeer is the application's gossip provider for beat responses,
// or nil.
func (ctx *MessageContext) GossipForPeer() GossipProvider {
	fn, _ := ctx.Data[ctxKeyGossipForPeer].(GossipProvider)
	return fn
}

// setGossipForPeer records the application's gossip provider.
func (ctx *MessageContext) setGossipForPeer(fn GossipProvider) {
	ctx.Data[ctxKeyGossipForPeer] = fn
}

// wireEnvelope is the envelope label the payload carried on the wire
// (ChunkEnvelope is the label of the payload as it is now, which after
// decryption is EnvelopeNone).
func (ctx *MessageContext) wireEnvelope() uint8 {
	e, _ := ctx.Data[ctxKeyWireEnvelope].(uint8)
	return e
}

// setWireEnvelope records the envelope label as received.
func (ctx *MessageContext) setWireEnvelope(e uint8) {
	ctx.Data[ctxKeyWireEnvelope] = e
}

// SetHandledType records the verb a handler accepted. Handlers set it as
// their last act; the dispatch gate (tdns-mp's transport_dispatch_test)
// reads it to prove that the registered handler ran through the real chain.
func (ctx *MessageContext) SetHandledType(verb string) {
	ctx.Data[ctxKeyHandledType] = verb
}

// handledType returns the verb recorded by SetHandledType.
func (ctx *MessageContext) handledType() (string, bool) {
	v, ok := ctx.Data[ctxKeyHandledType].(string)
	return v, ok
}

// unhandledType returns the verb the router found no handler for, when the
// default handler is running or has run.
func (ctx *MessageContext) unhandledType() (string, bool) {
	t, ok := ctx.Data[ctxKeyUnhandledType].(string)
	return t, ok
}

func (ctx *MessageContext) markUnhandled(msgType string) {
	ctx.Data[ctxKeyUnhandledType] = msgType
}
