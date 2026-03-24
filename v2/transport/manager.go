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
	return "", tm.ReliableQueue.Enqueue(msg)
}

// MarkDeliveryConfirmed marks a queued message as confirmed.
// Returns true if the message was found and confirmed.
func (tm *TransportManager) MarkDeliveryConfirmed(distributionID, senderID string) bool {
	return tm.ReliableQueue.MarkConfirmed(distributionID, senderID)
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
		return nil, NewTransportError("", "ping", peer.ID, nil, false)
	}
	return t.Ping(ctx, peer, &PingRequest{
		SenderID:  tm.LocalID,
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
