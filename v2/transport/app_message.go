/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The opaque application carrier (transport redesign, Stage C1).
 *
 * Transport's own vocabulary is hello/beat/ping/confirm/chunk. Everything
 * the application says on top of that travels as one AppMessage: a scope,
 * a type token and an uninterpreted payload. Transport moves it, applies
 * sender authorization and crypto, and hands it to the application's
 * RouteToCallback callback; it does not look inside Payload.
 *
 * C1 is additive. The TypeToken is the same string that has always been
 * the wire "MessageType" (the router's registration key), so an upgraded
 * node and an un-upgraded node exchange identical bytes.
 */

package transport

import "encoding/json"

// AppMessage is the opaque application carrier.
type AppMessage struct {
	// Scope is the application-defined scope of the message. For the
	// multi-provider application it is the zone (FQDN) the message is
	// about; empty for scope-less messages.
	Scope string

	// TypeToken is the application verb. It is the wire "MessageType"
	// value and the key handlers are registered under.
	TypeToken string

	// Payload is the application payload, uninterpreted by transport.
	Payload json.RawMessage
}

// Token returns the application verb of an incoming message: TypeToken
// when set, else the legacy Type. Both carry the same value during
// Stage C; TypeToken becomes the only one at C6.
func (m *IncomingMessage) Token() string {
	if m == nil {
		return ""
	}
	if m.TypeToken != "" {
		return m.TypeToken
	}
	return m.Type
}

// App returns the message as the opaque carrier.
func (m *IncomingMessage) App() AppMessage {
	if m == nil {
		return AppMessage{}
	}
	return AppMessage{Scope: m.Zone, TypeToken: m.Token(), Payload: json.RawMessage(m.Payload)}
}
