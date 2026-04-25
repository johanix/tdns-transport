/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Generic TransportManager for tdns-transport.
 *
 * Orchestrates transport components (DNS/API transports, Router,
 * PeerRegistry, ChunkHandler, ReliableMessageQueue) at startup.
 * At runtime, messages flow directly between components without
 * passing through the TransportManager.
 *
 * Applications register their own message handlers on the Router
 * and use Enqueue for reliable outgoing delivery. The TM has no
 * knowledge of specific message types or application semantics.
 */
package transport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// TransportManagerConfig holds configuration for creating a TransportManager.
// Application-specific behavior is injected via callbacks.
type TransportManagerConfig struct {
	// Identity
	LocalID     string
	ControlZone string

	// Transport timeouts
	APITimeout time.Duration
	DNSTimeout time.Duration

	// CHUNK configuration
	ChunkMode                  string // "edns0" or "query"
	ChunkMaxSize               int
	ChunkQueryEndpoint         string
	ChunkQueryEndpointInNotify bool

	// CHUNK query-mode payload store callbacks (nil disables query mode)
	ChunkPayloadGet func(qname string) ([]byte, uint8, bool)
	ChunkPayloadSet func(qname string, payload []byte, format uint8)

	// Crypto
	PayloadCrypto *PayloadCrypto

	// Which transports to enable: "api", "dns"
	SupportedMechanisms []string

	// TLS client config for API transport
	ClientCertFile string
	ClientKeyFile  string

	// Application callbacks
	IsPeerAuthorized      func(senderID, zone string) (bool, string)
	IsRecipientReady      func(recipientID string) bool
	GetPeerAddress        func(senderID string) (string, bool)
	OnPeerDiscoveryNeeded func(peerID string)

	// Distribution tracking callbacks (optional)
	DistributionAdd           func(qname, senderID, receiverID, operation, distributionID string, payloadSize int)
	DistributionMarkCompleted func(qname string)

	// RMQ configuration
	RMQBaseBackoff       time.Duration
	RMQMaxBackoff        time.Duration
	RMQConfirmTimeout    time.Duration
	RMQExpirationTimeout time.Duration
}

// TransportManager orchestrates transport components.
// After construction, applications interact with the components
// directly (Router for incoming, ReliableQueue for outgoing).
type TransportManager struct {
	// Components — applications access these directly
	APITransport  *APITransport
	DNSTransport  *DNSTransport
	ChunkHandler  *ChunkNotifyHandler
	Router        *DNSMessageRouter
	PeerRegistry  *PeerRegistry
	ReliableQueue *ReliableMessageQueue

	// Identity
	LocalID     string
	ControlZone string

	// OnPeerDiscovered is invoked by the application's discovery loop
	// (or, in a future phase, by transport itself) when peer discovery
	// completes successfully. The application registers a function here
	// at startup; transport never sets it. Optional — if nil, callers
	// must skip the invocation.
	//
	// This is the seam through which the per-application discovery
	// completion logic (sync state, set preferred mechanism, transition
	// peer to KNOWN) is dispatched. See Bite 8 in
	// tdns-mp/docs/2026-04-25-transport-refactor-early-bites.md.
	OnPeerDiscovered func(peerID string)

	// Which mechanisms are active
	supportedMechanisms []string
}

// NewTransportManager creates and wires all transport components.
// After creation, the application should:
//  1. Register message handlers on tm.Router
//  2. Call tm.RegisterChunkNotifyHandler() to plug into the DNS server
//  3. Call tm.StartReliableQueue() to begin outgoing delivery
func NewTransportManager(cfg *TransportManagerConfig) *TransportManager {
	tm := &TransportManager{
		LocalID:             cfg.LocalID,
		ControlZone:         cfg.ControlZone,
		supportedMechanisms: cfg.SupportedMechanisms,
	}

	// Create PeerRegistry
	tm.PeerRegistry = NewPeerRegistry()

	// Create Router
	tm.Router = NewDNSMessageRouter()

	// Create DNS transport if enabled
	if isIn(cfg.SupportedMechanisms, "dns") {
		dnsTimeout := cfg.DNSTimeout
		if dnsTimeout == 0 {
			dnsTimeout = 5 * time.Second
		}
		tm.DNSTransport = NewDNSTransport(&DNSTransportConfig{
			LocalID:                    cfg.LocalID,
			ControlZone:                cfg.ControlZone,
			Timeout:                    dnsTimeout,
			PayloadCrypto:              cfg.PayloadCrypto,
			ChunkMode:                  cfg.ChunkMode,
			ChunkPayloadGet:            cfg.ChunkPayloadGet,
			ChunkPayloadSet:            cfg.ChunkPayloadSet,
			ChunkQueryEndpoint:         cfg.ChunkQueryEndpoint,
			ChunkQueryEndpointInNotify: cfg.ChunkQueryEndpointInNotify,
			ChunkMaxSize:               cfg.ChunkMaxSize,
			DistributionAdd:            cfg.DistributionAdd,
			DistributionMarkCompleted:  cfg.DistributionMarkCompleted,
		})
	}

	// Create API transport if enabled
	if isIn(cfg.SupportedMechanisms, "api") {
		apiTimeout := cfg.APITimeout
		if apiTimeout == 0 {
			apiTimeout = 5 * time.Second
		}
		tm.APITransport = NewAPITransport(&APITransportConfig{
			LocalID:        cfg.LocalID,
			DefaultTimeout: apiTimeout,
		})
	}

	// Create ChunkNotifyHandler if DNS transport is available
	if tm.DNSTransport != nil {
		tm.ChunkHandler = NewChunkNotifyHandler(cfg.ControlZone, cfg.LocalID, tm.DNSTransport)
		tm.ChunkHandler.Router = tm.Router

		// Wire application callbacks into ChunkHandler
		if cfg.IsPeerAuthorized != nil {
			tm.ChunkHandler.IsPeerAuthorized = cfg.IsPeerAuthorized
		}
		if cfg.GetPeerAddress != nil {
			tm.ChunkHandler.GetPeerAddress = cfg.GetPeerAddress
		}
		if cfg.OnPeerDiscoveryNeeded != nil {
			tm.ChunkHandler.OnPeerDiscoveryNeeded = cfg.OnPeerDiscoveryNeeded
		}
		if cfg.PayloadCrypto != nil {
			tm.ChunkHandler.SecureWrapper = NewSecurePayloadWrapper(cfg.PayloadCrypto)
		}
	}

	// Create ReliableMessageQueue
	tm.ReliableQueue = NewReliableMessageQueue(&ReliableMessageQueueConfig{
		IsRecipientReady:  cfg.IsRecipientReady,
		BaseBackoff:       cfg.RMQBaseBackoff,
		MaxBackoff:        cfg.RMQMaxBackoff,
		ConfirmTimeout:    cfg.RMQConfirmTimeout,
		ExpirationTimeout: cfg.RMQExpirationTimeout,
	})

	return tm
}

// SelectTransport chooses the best transport for a peer.
// Respects peer's PreferredTransport, falls back to API then DNS.
func (tm *TransportManager) SelectTransport(peer *Peer) Transport {
	switch peer.PreferredTransport {
	case "DNS":
		if tm.DNSTransport != nil && peer.CurrentAddress() != nil {
			return tm.DNSTransport
		}
	case "API":
		if tm.APITransport != nil && peer.APIEndpoint != "" {
			return tm.APITransport
		}
	}

	// Default: API first (more reliable), then DNS
	if tm.APITransport != nil && peer.APIEndpoint != "" {
		return tm.APITransport
	}
	if tm.DNSTransport != nil && peer.CurrentAddress() != nil {
		return tm.DNSTransport
	}

	return nil
}

// RegisterChunkNotifyHandler registers the CHUNK NOTIFY handler
// with the DNS server. The registerFn is provided by the application
// (typically tdns.RegisterNotifyHandler).
func (tm *TransportManager) RegisterChunkNotifyHandler(
	registerFn func(qtype uint16, handler interface{}) error,
) error {
	if tm.ChunkHandler == nil {
		return nil // DNS transport not enabled
	}
	// The application provides the registration function that
	// bridges to its DNS server's handler registry.
	// The ChunkHandler.RouteViaRouter method matches the expected signature.
	return registerFn(0, tm.ChunkHandler) // 0 = application determines qtype
}

// StartReliableQueue starts the RMQ background worker.
// The sendFunc is called by RMQ to deliver messages — the application
// provides this to handle transport selection and actual sending.
func (tm *TransportManager) StartReliableQueue(ctx context.Context,
	sendFunc func(ctx context.Context, msg *OutgoingMessage) error) {
	tm.ReliableQueue.SetSendFunc(sendFunc)
	go tm.ReliableQueue.Start(ctx)
	slog.Info("reliable queue started")
}

// Enqueue adds a message to the reliable delivery queue.
// Returns the distribution ID for confirmation tracking.
func (tm *TransportManager) Enqueue(msg *OutgoingMessage) (string, error) {
	return msg.DistributionID, tm.ReliableQueue.Enqueue(msg)
}

// MarkDeliveryConfirmed marks a queued message as confirmed.
// Returns true if the message was found and confirmed.
func (tm *TransportManager) MarkDeliveryConfirmed(distributionID, senderID string) bool {
	return tm.ReliableQueue.MarkConfirmed(distributionID, senderID)
}

// Send delivers a message to a peer using the primary transport
// chosen by SelectTransport, falling back to the alternative on
// error. The message type is determined by the concrete type of req:
//
//   - *SyncRequest    → Transport.Sync
//   - *PingRequest    → Transport.Ping
//   - *RelocateRequest → Transport.Relocate
//
// (Hello and Beat are deliberately NOT supported by this generic
// path. In the current codebase those operations send on all
// available transports in parallel rather than primary-then-
// fallback, with substantial application-side bookkeeping mixed
// in. Wrapping them under a generic Send would change semantics.
// Phase 5 of the main refactor will address that separately.)
//
// Returns the response (one of *SyncResponse, *PingResponse,
// *RelocateResponse) or an error if both transports failed or the
// message type is unsupported.
//
// Bite 3 of the transport refactor early-bites plan; see
// tdns-mp/docs/2026-04-25-transport-refactor-early-bites.md.
func (tm *TransportManager) Send(ctx context.Context, peer *Peer, req interface{}) (interface{}, error) {
	if peer == nil {
		return nil, fmt.Errorf("Send: peer is nil")
	}
	primary := tm.SelectTransport(peer)

	dispatch := func(t Transport) (interface{}, error) {
		if t == nil {
			return nil, fmt.Errorf("no transport selected")
		}
		switch r := req.(type) {
		case *SyncRequest:
			return t.Sync(ctx, peer, r)
		case *PingRequest:
			return t.Ping(ctx, peer, r)
		case *RelocateRequest:
			return t.Relocate(ctx, peer, r)
		default:
			return nil, fmt.Errorf("Send: unsupported message type %T (use Hello/Beat directly for parallel-send semantics)", req)
		}
	}

	if primary != nil {
		resp, err := dispatch(primary)
		if err == nil {
			return resp, nil
		}
		// Don't fall back on non-retryable errors. The same problem
		// (e.g. missing crypto key, no address, marshal failure) will
		// hit the alternate transport identically — falling back just
		// turns a clear error into a confusing one. Errors not wrapped
		// in *TransportError are treated as fall-back-eligible (safe
		// default for unaudited code paths).
		var te *TransportError
		if errors.As(err, &te) && !te.Retryable {
			slog.Debug("primary transport failed with non-retryable error, not falling back",
				"transport", primary.Name(), "peer", peer.ID, "err", err)
			return nil, err
		}
		slog.Debug("primary transport failed, trying fallback",
			"transport", primary.Name(), "peer", peer.ID, "err", err)
	}

	// Pick the fallback (the one that isn't the primary).
	var fallback Transport
	if primary == tm.APITransport && tm.DNSTransport != nil {
		fallback = tm.DNSTransport
	} else if primary == tm.DNSTransport && tm.APITransport != nil {
		fallback = tm.APITransport
	}
	if fallback != nil {
		return dispatch(fallback)
	}

	return nil, fmt.Errorf("Send: all transports failed for peer %s", peer.ID)
}

// GetQueueStats returns RMQ statistics.
func (tm *TransportManager) GetQueueStats() QueueStats {
	return tm.ReliableQueue.GetStats()
}

// GetQueuePendingMessages returns a snapshot of pending messages.
func (tm *TransportManager) GetQueuePendingMessages() []PendingMessageInfo {
	return tm.ReliableQueue.GetPendingMessages()
}

// SendPing sends a ping to a peer using the best available transport.
func (tm *TransportManager) SendPing(ctx context.Context, peer *Peer) (*PingResponse, error) {
	t := tm.SelectTransport(peer)
	if t == nil {
		return nil, NewTransportError("", "ping", peer.ID, fmt.Errorf("no transport available for peer %s", peer.ID), false)
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate ping nonce: %w", err)
	}
	return t.Ping(ctx, peer, &PingRequest{
		SenderID:  tm.LocalID,
		Nonce:     hex.EncodeToString(nonce),
		Timestamp: time.Now(),
	})
}

// IsTransportSupported checks if a transport mechanism is enabled.
func (tm *TransportManager) IsTransportSupported(mechanism string) bool {
	return isIn(tm.supportedMechanisms, mechanism)
}

// isIn checks if a string is in a slice.
func isIn(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
