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

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

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

	// DistributionID is the transport correlation id for this send
	// (the NOTIFY qname label and the pending-confirmation key). It is
	// generated when empty.
	DistributionID string

	// FireAndForget sends without registering a pending distribution and
	// without requiring an inline confirmation; only the DNS rcode is
	// checked. Used for status-update notifications.
	FireAndForget bool
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

// AppResponse is what the receiver's inline confirmation said about an
// AppMessage. Status/Message are always set; the record lists are the
// sync-family confirmation detail and are empty for other verbs.
type AppResponse struct {
	ResponderID    string
	Scope          string
	TypeToken      string
	DistributionID string
	Status         ConfirmStatus
	Message        string
	Timestamp      time.Time
	AppliedRecords []string
	RemovedRecords []string
	RejectedItems  []RejectedItemDTO
	Truncated      bool
}

// IsSyncFamily reports whether a verb is one of the zone-data verbs whose
// application-level rejection the sender treats as a retryable failure
// (the pre-C2 DNSTransport.Sync contract).
func IsSyncFamily(token string) bool {
	switch token {
	case "sync", "update", "rfi":
		return true
	}
	return false
}

// SendApp sends one opaque application message as a NOTIFY(CHUNK) and
// returns the receiver's inline confirmation. Unless msg.FireAndForget is
// set, the send is registered as a pending distribution and a missing
// confirmation is an error, exactly as the typed sends behaved before C2.
func (t *DNSTransport) SendApp(ctx context.Context, peer *Peer, msg *AppMessage) (*AppResponse, error) {
	if msg == nil || msg.TypeToken == "" {
		return nil, NewTransportError("DNS", "SendApp", peer.ID, fmt.Errorf("empty application message"), false)
	}
	addr := peer.CurrentAddress()
	if addr == nil {
		return nil, NewTransportError("DNS", msg.TypeToken, peer.ID, fmt.Errorf("no address available"), false)
	}
	distributionID := msg.DistributionID
	if distributionID == "" {
		distributionID = GenerateDistributionID()
	}
	qname := t.buildNotifyQNAME(distributionID)
	if msg.FireAndForget {
		if err := t.sendNotifyUnconfirmed(ctx, peer, qname, msg.TypeToken, msg.Payload); err != nil {
			return nil, err
		}
		return &AppResponse{ResponderID: peer.ID, Scope: msg.Scope, TypeToken: msg.TypeToken,
			DistributionID: distributionID, Status: ConfirmSuccess, Timestamp: time.Now()}, nil
	}
	resp, err := t.sendNotifyWithPayload(ctx, peer, qname, msg.TypeToken, distributionID, msg.Payload, false)
	if err != nil {
		return nil, err
	}
	return &AppResponse{
		ResponderID:    peer.ID,
		Scope:          msg.Scope,
		TypeToken:      msg.TypeToken,
		DistributionID: distributionID,
		Status:         resp.Status,
		Message:        resp.Message,
		Timestamp:      time.Now(),
		AppliedRecords: resp.AppliedRecords,
		RemovedRecords: resp.RemovedRecords,
		RejectedItems:  resp.RejectedItems,
		Truncated:      resp.Truncated,
	}, nil
}

// sendNotifyUnconfirmed is the fire-and-forget NOTIFY(CHUNK): the payload
// rides inline in EDNS0, no pending distribution is registered and only
// the DNS rcode is checked (the pre-C2 SendStatusUpdate contract).
func (t *DNSTransport) sendNotifyUnconfirmed(ctx context.Context, peer *Peer, qname, opType string, payload []byte) error {
	addr := peer.CurrentAddress()
	finalPayload := payload
	var payloadFormat uint8 = core.FormatJSON
	if t.SecureWrapper != nil && t.SecureWrapper.IsEnabled() {
		encrypted, err := t.SecureWrapper.WrapOutgoing(peer.ID, payload)
		if err != nil {
			return NewTransportError("DNS", opType, peer.ID,
				fmt.Errorf("encryption required but failed: %w", err), false)
		}
		finalPayload = encrypted
		payloadFormat = core.FormatJWT
	}
	m := new(dns.Msg)
	m.SetNotify(qname)
	m.Question = []dns.Question{
		{Name: qname, Qtype: core.TypeCHUNK, Qclass: dns.ClassINET},
	}
	m.SetEdns0(4096, true)
	if opt := m.IsEdns0(); opt != nil {
		opt.Option = append(opt.Option, edns0.CreateChunkOption(payloadFormat, nil, finalPayload))
	}
	dnsAddr := fmt.Sprintf("%s:%d", addr.Host, addr.Port)
	res, _, err := t.DNSClient.ExchangeContext(ctx, m, dnsAddr)
	if err != nil {
		return NewTransportError("DNS", opType, peer.ID,
			fmt.Errorf("NOTIFY exchange failed: %w", err), true)
	}
	if res.Rcode != dns.RcodeSuccess {
		return NewTransportError("DNS", opType, peer.ID,
			fmt.Errorf("NOTIFY returned rcode %s", dns.RcodeToString[res.Rcode]), true)
	}
	peer.Stats.RecordMessageSent(opType)
	return nil
}

// SendApp over the API mechanism. Only the sync family has an API
// endpoint (/sync); the body is re-derived from the application payload
// into the pre-C2 apiSyncRequest shape. sync_type and serial are not
// part of the application payload and are sent as their zero values.
// Every other verb is DNS-only, as before C2.
func (t *APITransport) SendApp(ctx context.Context, peer *Peer, msg *AppMessage) (*AppResponse, error) {
	if msg == nil || msg.TypeToken == "" {
		return nil, NewTransportError("API", "SendApp", peer.ID, fmt.Errorf("empty application message"), false)
	}
	if !IsSyncFamily(msg.TypeToken) {
		return nil, NewTransportError("API", msg.TypeToken, peer.ID,
			fmt.Errorf("verb %q is not supported over the API mechanism", msg.TypeToken), false)
	}
	url, err := apiURL(peer, "/sync")
	if err != nil {
		return nil, NewTransportError("API", msg.TypeToken, peer.ID, err, false)
	}
	// The sync-family payload is the application's; transport reads only
	// the fields the API body needs, without importing the application's
	// types (C4).
	var app struct {
		OriginatorID string              `json:"OriginatorID"`
		Zone         string              `json:"Zone"`
		Records      map[string][]string `json:"records"`
		Operations   json.RawMessage     `json:"operations"`
		RfiType      string              `json:"RfiType"`
		Time         time.Time           `json:"Time"`
	}
	if err := json.Unmarshal(msg.Payload, &app); err != nil {
		return nil, NewTransportError("API", msg.TypeToken, peer.ID,
			fmt.Errorf("application payload is not a sync-family message: %w", err), false)
	}
	apiReq := &apiSyncRequest{
		MessageType:    msg.TypeToken,
		OriginatorID:   app.OriginatorID,
		YourIdentity:   peer.ID,
		Zone:           app.Zone,
		SyncType:       "UNKNOWN",
		Records:        app.Records,
		Operations:     app.Operations,
		DistributionID: msg.DistributionID,
		RfiType:        app.RfiType,
		Timestamp:      app.Time.Unix(),
	}
	respBody, err := t.doRequest(ctx, "POST", url, apiReq)
	if err != nil {
		return nil, NewTransportError("API", msg.TypeToken, peer.ID, err, true)
	}
	var apiResp apiSyncResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, NewTransportError("API", msg.TypeToken, peer.ID,
			fmt.Errorf("failed to unmarshal response: %w", err), false)
	}
	status := ConfirmSuccess
	if apiResp.Error {
		status = ConfirmFailed
	}
	return &AppResponse{
		ResponderID:    apiResp.Identity,
		Scope:          msg.Scope,
		TypeToken:      msg.TypeToken,
		DistributionID: msg.DistributionID,
		Status:         status,
		Message:        apiResp.Msg,
		Timestamp:      time.Now(),
	}, nil
}
