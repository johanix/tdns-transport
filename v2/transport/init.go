/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Initialization helpers for the transport package.
 * These functions help integrate the transport package with the main tdns package.
 */

package transport

/*
INTEGRATION GUIDE

To integrate the CHUNK NOTIFY handler with tdns, add the following code to your
agent initialization (e.g., in tdns-agent/main.go or agent setup):

	import (
		"github.com/johanix/tdns/v2"
		"github.com/johanix/tdns-transport/v2/transport"
		"github.com/johanix/tdns/v2/core"
	)

	func setupDNSTransport(controlZone, localID string) (*transport.DNSTransport, *transport.ChunkNotifyHandler) {
		// Create DNS transport
		dnsTransport := transport.NewDNSTransport(&transport.DNSTransportConfig{
			LocalID:     localID,
			ControlZone: controlZone,
			Timeout:     5 * time.Second,
		})

		// Create CHUNK NOTIFY handler and its router. The router runs the
		// middleware chain (authorization, crypto, stats) and the per-verb
		// handlers registered by InitializeRouter.
		chunkHandler := transport.NewChunkNotifyHandler(controlZone, localID, dnsTransport)
		router := transport.NewDNSMessageRouter()
		// Confirmations: a role that sends confirmed distributions (agent,
		// auditor) must register the confirm handler, or confirmation
		// NOTIFYs are answered REFUSED and the reliable queue never clears.
		if err := transport.InitializeRouter(router, &transport.RouterConfig{
			PeerRegistry:  peerRegistry,
			Confirmations: true,
		}); err != nil {
			panic(err)
		}
		chunkHandler.Router = router

		// Register a handler for every application verb this role accepts.
		// InitializeRouter registers only the transport-own verbs (ping,
		// hello, beat, confirm); an unregistered verb is answered REFUSED
		// and never reaches the callback below. The handler itself can be
		// a no-op: the middleware chain has already authorized, decrypted
		// and parsed the message into ctx.Data["incoming_message"], and the
		// application-level work happens in processIncomingDNSMessage.
		appVerbHandler := func(ctx *transport.MessageContext) error { return nil }
		for _, verb := range []string{"sync", "rfi", "keystate", "edits", "config", "audit", "status-update", "relocate"} {
			if err := router.Register(verb+"-handler", transport.MessageType(verb), appVerbHandler,
				transport.WithPriority(100), transport.WithDescription("application verb "+verb)); err != nil {
				panic(err)
			}
		}

		// Register the handler with tdns
		// This creates an adapter from the generic handler to tdns.NotifyHandlerFunc
		tdns.RegisterNotifyHandler(core.TypeCHUNK, func(ctx context.Context, req *tdns.DnsNotifyRequest) error {
			return chunkHandler.RouteViaRouter(ctx, req.Qname, req.Msg, req.ResponseWriter)
		})

		// Hand every successfully handled message to the application. The
		// callback runs in the DNS server goroutine, so it must not block
		// (push to a buffered channel and return). There is no channel to
		// consume: RouteToCallback replaced the old IncomingChan.
		router.Use(transport.RouteToCallback(processIncomingDNSMessage))

		return dnsTransport, chunkHandler
	}

	func processIncomingDNSMessage(msg *transport.IncomingMessage) {
		switch msg.Type {
		case "hello":
			// Parse and handle hello
			payload, _ := transport.ParseHelloPayload(msg.Payload)
			// ... handle hello from remote agent
		case "beat":
			// Parse and handle beat
			payload, _ := transport.ParseBeatPayload(msg.Payload)
			// ... handle heartbeat
		default:
			// Application verbs (sync, keystate, ...): msg.Token() is the
			// verb, msg.Payload the application's own JSON — parse it with
			// the application's types (they do not live in this package).
		}
	}

TRANSPORT SELECTION

The hsyncengine should select transport based on peer configuration:

	func (engine *HsyncEngine) selectTransport(peer *transport.Peer) transport.Transport {
		// Check peer's preferred transport
		switch peer.PreferredTransport {
		case "DNS":
			if engine.dnsTransport != nil {
				return engine.dnsTransport
			}
		case "API":
			if engine.apiTransport != nil {
				return engine.apiTransport
			}
		}

		// Default: try API first, then DNS
		if engine.apiTransport != nil && peer.APIEndpoint != "" {
			return engine.apiTransport
		}
		if engine.dnsTransport != nil && peer.CurrentAddress() != nil {
			return engine.dnsTransport
		}

		return nil
	}

FALLBACK LOGIC

For robust communication, implement transport fallback:

	func (engine *HsyncEngine) sendWithFallback(ctx context.Context, peer *transport.Peer, msg *transport.AppMessage) (*transport.AppResponse, error) {
		// Try preferred transport first
		t := engine.selectTransport(peer)
		if t != nil {
			resp, err := t.SendApp(ctx, peer, msg)
			if err == nil {
				return resp, nil
			}
			log.Printf("Primary transport %s failed: %v, trying fallback", t.Name(), err)
		}

		// Try alternative transport (TransportManager.Send does this for you)
		if t == engine.apiTransport && engine.dnsTransport != nil {
			return engine.dnsTransport.SendApp(ctx, peer, msg)
		}
		if t == engine.dnsTransport && engine.apiTransport != nil {
			return engine.apiTransport.SendApp(ctx, peer, msg)
		}

		return nil, fmt.Errorf("all transports failed")
	}
*/
