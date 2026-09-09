/*
 * transport-exercise: exercises the tdns-transport public API.
 *
 * Creates a router, registers handlers, routes messages through
 * middleware, and verifies the peer registry. Prints PASS/FAIL.
 *
 * Usage: go run ./cmd/transport-exercise
 */
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose"
	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

func main() {
	ok := true
	ok = testRouter() && ok
	ok = testPeerRegistry() && ok
	ok = testMiddleware() && ok
	ok = testCryptoBackend() && ok
	ok = testDiscovery() && ok

	if ok {
		fmt.Println("\nPASS: all transport-exercise checks passed")
	} else {
		fmt.Println("\nFAIL: some checks failed")
		os.Exit(1)
	}
}

func testRouter() bool {
	fmt.Println("--- Router ---")
	router := transport.NewDNSMessageRouter()

	// Register handlers for two message types
	var beatCalled, syncCalled bool

	err := router.Register("test-beat", transport.MessageType("beat"),
		func(ctx *transport.MessageContext) error {
			beatCalled = true
			ctx.Data["handled"] = "beat"
			return nil
		},
		transport.WithPriority(10),
		transport.WithDescription("test beat handler"),
	)
	if err != nil {
		fmt.Printf("  FAIL: register beat handler: %v\n", err)
		return false
	}

	err = router.Register("test-update", transport.MessageType("update"),
		func(ctx *transport.MessageContext) error {
			syncCalled = true
			ctx.Data["handled"] = "update"
			return nil
		},
	)
	if err != nil {
		fmt.Printf("  FAIL: register update handler: %v\n", err)
		return false
	}

	// Route a beat message
	msg := new(dns.Msg)
	msg.SetQuestion("test.example.", dns.TypeNS)
	ctx := transport.NewMessageContext(msg, "192.0.2.1:53")
	if err := router.Route(ctx, transport.MessageType("beat")); err != nil {
		fmt.Printf("  FAIL: route beat: %v\n", err)
		return false
	}
	if !beatCalled || ctx.Data["handled"] != "beat" {
		fmt.Println("  FAIL: beat handler not called correctly")
		return false
	}
	fmt.Println("  OK: beat message routed to handler")

	// Route an update message
	ctx2 := transport.NewMessageContext(msg, "192.0.2.2:53")
	if err := router.Route(ctx2, transport.MessageType("update")); err != nil {
		fmt.Printf("  FAIL: route update: %v\n", err)
		return false
	}
	if !syncCalled {
		fmt.Println("  FAIL: update handler not called")
		return false
	}
	fmt.Println("  OK: update message routed to handler")

	// Route unknown type — should fail (no default handler)
	ctx3 := transport.NewMessageContext(msg, "192.0.2.3:53")
	if err := router.Route(ctx3, transport.MessageTypeUnknown); err == nil {
		fmt.Println("  FAIL: expected error for unknown type")
		return false
	}
	fmt.Println("  OK: unknown message type rejected")

	// Set default handler and retry
	router.SetDefaultHandler(func(ctx *transport.MessageContext) error {
		ctx.Data["default"] = true
		return nil
	})
	ctx4 := transport.NewMessageContext(msg, "192.0.2.4:53")
	if err := router.Route(ctx4, transport.MessageTypeUnknown); err != nil {
		fmt.Printf("  FAIL: default handler: %v\n", err)
		return false
	}
	fmt.Println("  OK: default handler caught unknown type")

	// Duplicate registration — should fail
	err = router.Register("test-beat", transport.MessageType("beat"),
		func(ctx *transport.MessageContext) error { return nil },
	)
	if err == nil {
		fmt.Println("  FAIL: expected error for duplicate name")
		return false
	}
	fmt.Println("  OK: duplicate handler name rejected")

	return true
}

func testPeerRegistry() bool {
	fmt.Println("--- PeerRegistry ---")
	reg := transport.NewPeerRegistry()

	p := transport.NewPeer("agent.alpha.example.")
	reg.Add(p)

	got, ok := reg.Get("agent.alpha.example.")
	if !ok || got != p {
		fmt.Println("  FAIL: peer not found after add")
		return false
	}
	fmt.Println("  OK: peer added and retrieved")

	reg.Remove("agent.alpha.example.")
	_, ok = reg.Get("agent.alpha.example.")
	if ok {
		fmt.Println("  FAIL: peer still found after remove")
		return false
	}
	fmt.Println("  OK: peer removed")

	return true
}

func testMiddleware() bool {
	fmt.Println("--- Middleware ---")
	router := transport.NewDNSMessageRouter()

	var order []string
	router.Use(func(ctx *transport.MessageContext, next transport.MessageHandlerFunc) error {
		order = append(order, "mw1-before")
		err := next(ctx)
		order = append(order, "mw1-after")
		return err
	})
	router.Use(func(ctx *transport.MessageContext, next transport.MessageHandlerFunc) error {
		order = append(order, "mw2-before")
		err := next(ctx)
		order = append(order, "mw2-after")
		return err
	})

	_ = router.Register("test", transport.MessageType("beat"),
		func(ctx *transport.MessageContext) error {
			order = append(order, "handler")
			return nil
		},
	)

	msg := new(dns.Msg)
	ctx := transport.NewMessageContext(msg, "192.0.2.1:53")
	if err := router.Route(ctx, transport.MessageType("beat")); err != nil {
		fmt.Printf("  FAIL: route with middleware: %v\n", err)
		return false
	}

	expected := []string{"mw1-before", "mw2-before", "handler", "mw2-after", "mw1-after"}
	if len(order) != len(expected) {
		fmt.Printf("  FAIL: middleware order: got %v, want %v\n", order, expected)
		return false
	}
	for i := range expected {
		if order[i] != expected[i] {
			fmt.Printf("  FAIL: middleware order[%d]: got %q, want %q\n", i, order[i], expected[i])
			return false
		}
	}
	fmt.Println("  OK: middleware chain executes in correct order")

	return true
}

func testCryptoBackend() bool {
	fmt.Println("--- CryptoBackend ---")

	// JOSE backend should be auto-registered via the blank import
	backend, err := crypto.GetBackend("jose")
	if err != nil {
		fmt.Printf("  FAIL: get JOSE backend: %v\n", err)
		return false
	}
	fmt.Printf("  OK: JOSE backend registered: %s\n", backend.Name())

	return true
}

// testDiscovery exercises the discovery surface a non-MP consumer sees
// (transport redesign, Stage E residual): DiscoverPeer's short-circuit for
// an already-known peer, its clean failure without a resolver, and the
// registration contract that a discovered endpoint without a verification
// key is refused. No network is touched.
func testDiscovery() bool {
	fmt.Println("--- Discovery ---")
	tm := transport.NewTransportManager(&transport.TransportManagerConfig{
		LocalID:             "exercise.example.",
		ControlZone:         "mp-control.example.",
		SupportedMechanisms: []string{"dns"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// No resolver configured: an unknown identity must fail cleanly.
	if _, err := tm.DiscoverPeer(ctx, "unknown.example."); err == nil || !strings.Contains(err.Error(), "no IMR accessor") {
		fmt.Printf("  FAIL: DiscoverPeer without IMR: err=%v\n", err)
		return false
	}
	fmt.Println("  OK: unknown peer without a resolver fails cleanly")

	// An identity already at KNOWN is returned without a resolver.
	seeded := tm.PeerRegistry.GetOrCreate("known.example.")
	seeded.SetState(transport.PeerStateKnown, "seeded by transport-exercise")
	got, err := tm.DiscoverPeer(ctx, "known.example.")
	if err != nil || got == nil || got.ID != "known.example." {
		fmt.Printf("  FAIL: DiscoverPeer for a KNOWN peer: got=%v err=%v\n", got, err)
		return false
	}
	fmt.Println("  OK: known peer returned without discovery")

	// A discovered endpoint without a verification key is refused (the
	// receive path needs the key to decrypt), and the completion seam
	// does not fire for it.
	fired := false
	tm.OnPeerDiscovered = func(p *transport.Peer) { fired = true }
	err = tm.RegisterDiscoveredPeer(&transport.DiscoveryResult{
		Identity:     "found.example.",
		DNSUri:       "dns://dns.found.example.:8054/",
		DNSAddresses: []string{"192.0.2.10"},
	})
	if err == nil || !strings.Contains(err.Error(), "verification key") || fired {
		fmt.Printf("  FAIL: RegisterDiscoveredPeer without key: err=%v fired=%v\n", err, fired)
		return false
	}
	fmt.Println("  OK: endpoint without verification key refused; OnPeerDiscovered not fired")
	return true
}
