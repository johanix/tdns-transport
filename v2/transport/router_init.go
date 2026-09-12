/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Router initialization: the role-neutral middleware and the transport-own
 * verb handlers.
 */

package transport

// RouterConfig holds configuration for router initialization.
//
// Authorization and crypto are not configured here (cleanup plan, step 1):
// they belong to ChunkNotifyHandler.RouteViaRouter, which runs them before
// the router is entered. A router that is entered directly, by a test or a
// consumer of its own, gets a verb table, the statistics and logging
// middleware, and nothing more.
type RouterConfig struct {
	// PeerRegistry for statistics tracking
	PeerRegistry *PeerRegistry

	// VerboseStats enables verbose logging for statistics middleware
	VerboseStats bool

	// Confirmations registers the confirm handler. Roles that send
	// confirmed distributions (agent, auditor) set it; the signer and
	// combiner did not register it before C3 and still do not.
	Confirmations bool
}

// InitializeRouter registers the middleware and the transport-own handlers
// with the router. Application verbs are registered by the application on
// top of this (C3); see RouteToCallback for how they reach it.
func InitializeRouter(router *DNSMessageRouter, cfg *RouterConfig) error {
	if router == nil {
		return nil // No router to initialize
	}

	lgTransport().Info("registering handlers and middleware")

	// Register default handler for unregistered message types
	router.SetDefaultHandler(defaultUnsupportedHandler)

	// Global middleware, executed in order for every message. Outer
	// middleware wraps inner middleware.

	// 1. Statistics tracking
	if cfg.PeerRegistry != nil {
		statsCfg := &StatsMiddlewareConfig{
			PeerRegistry: cfg.PeerRegistry,
			Verbose:      cfg.VerboseStats,
		}
		router.Use(newStatsMiddleware(statsCfg))
		lgTransport().Info("registered statistics middleware")
	}

	// 2. Logging (for visibility)
	router.Use(newLoggingMiddleware(true))
	lgTransport().Info("registered logging middleware")

	// Register the transport-own message handlers.
	handlerCount := 3
	var err error
	if cfg.Confirmations {
		// Confirmation handler (priority: 100) — for roles that send
		// confirmed distributions and expect confirm NOTIFYs back.
		err = router.Register(
			"ConfirmationHandler",
			MessageType(VerbConfirm),
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
		MessageType(VerbPing),
		handlePing,
		WithPriority(100),
		WithDescription("Processes ping messages and sends immediate echo response"),
	)
	if err != nil {
		return err
	}

	// Hello handler (priority: 100)
	err = router.Register(
		"HelloHandler",
		MessageType(VerbHello),
		handleHello,
		WithPriority(100),
		WithDescription("Processes Hello messages for peer introduction"),
	)
	if err != nil {
		return err
	}

	// Beat handler (priority: 100)
	err = router.Register(
		"BeatHandler",
		MessageType(VerbBeat),
		handleBeat,
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
