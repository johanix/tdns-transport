/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Router initialization and handler registration.
 */

package transport

import (
	"github.com/miekg/dns"
)

// RouterConfig holds configuration for router initialization.
type RouterConfig struct {
	// TransportManager for authorization middleware
	TransportManager interface {
		IsPeerAuthorized(senderID string, zone string) (bool, string)
	}

	// PeerRegistry for statistics tracking
	PeerRegistry *PeerRegistry

	// PayloadCrypto for signature and decryption middleware
	PayloadCrypto *PayloadCrypto

	// ResponseWriter for sending DNS responses
	ResponseWriter dns.ResponseWriter

	// RequestMsg for DNS response correlation
	RequestMsg *dns.Msg

	// TriggerDiscoveryOnMissingKey enables auto-discovery
	TriggerDiscoveryOnMissingKey bool

	// AllowUnencrypted allows unencrypted payloads (for testing/compatibility)
	AllowUnencrypted bool

	// VerboseStats enables verbose logging for statistics middleware
	VerboseStats bool

	// Confirmations registers the confirm handler. Roles that send
	// confirmed distributions (agent, auditor) set it; the signer and
	// combiner did not register it before C3 and still do not.
	Confirmations bool
}

// InitializeRouter registers all handlers and middleware with the router.
func InitializeRouter(router *DNSMessageRouter, cfg *RouterConfig) error {
	if router == nil {
		return nil // No router to initialize
	}

	lgTransport().Info("registering handlers and middleware")

	// Register default handler for unregistered message types
	router.SetDefaultHandler(DefaultUnsupportedHandler)

	// Register global middleware (executed in order for all messages)
	// Order matters: outer middleware wraps inner middleware

	// 1. Authorization (outermost - prevents unauthorized access)
	if cfg.TransportManager != nil {
		router.Use(NewAuthorizationMiddleware(cfg.TransportManager))
		lgTransport().Info("registered authorization middleware")
	}

	// 2. Signature verification (authenticates sender)
	if cfg.PayloadCrypto != nil && cfg.PayloadCrypto.Enabled {
		cryptoCfg := &CryptoMiddlewareConfig{
			PayloadCrypto:                cfg.PayloadCrypto,
			TriggerDiscoveryOnMissingKey: cfg.TriggerDiscoveryOnMissingKey,
			AllowUnencrypted:             cfg.AllowUnencrypted,
		}
		router.Use(NewSignatureMiddleware(cryptoCfg))
		lgTransport().Info("registered signature middleware")
	}

	// 3. Statistics tracking (after authentication, before processing)
	if cfg.PeerRegistry != nil {
		statsCfg := &StatsMiddlewareConfig{
			PeerRegistry: cfg.PeerRegistry,
			Verbose:      cfg.VerboseStats,
		}
		router.Use(NewStatsMiddleware(statsCfg))
		lgTransport().Info("registered statistics middleware")
	}

	// 4. Logging (for visibility)
	router.Use(NewLoggingMiddleware(true))
	lgTransport().Info("registered logging middleware")

	// Register the transport-own message handlers. Application verbs
	// (sync, rfi, keystate, ...) are registered by the application on
	// top of this (C3); see RouteToCallback for how they reach it.
	handlerCount := 3
	var err error
	if cfg.Confirmations {
		// Confirmation handler (priority: 100) — for roles that send
		// confirmed distributions and expect confirm NOTIFYs back.
		err = router.Register(
			"ConfirmationHandler",
			MessageType("confirm"),
			HandleConfirmation,
			WithPriority(100),
			WithDescription("Processes confirmation messages for pending operations"),
		)
		if err != nil {
			return err
		}
		handlerCount++
	}

	// Ping handler (priority: 100)
	err = router.Register(
		"PingHandler",
		MessageType("ping"),
		HandlePing,
		WithPriority(100),
		WithDescription("Processes ping messages and sends immediate echo response"),
	)
	if err != nil {
		return err
	}

	// Hello handler (priority: 100)
	err = router.Register(
		"HelloHandler",
		MessageType("hello"),
		HandleHello,
		WithPriority(100),
		WithDescription("Processes Hello messages for peer introduction"),
	)
	if err != nil {
		return err
	}

	// Beat handler (priority: 100)
	err = router.Register(
		"BeatHandler",
		MessageType("beat"),
		HandleBeat,
		WithPriority(100),
		WithDescription("Processes heartbeat messages from peers"),
	)
	if err != nil {
		return err
	}

	lgTransport().Info("registered message handlers", "count", handlerCount)
	lgTransport().Info("router initialization complete")

	return nil
}
