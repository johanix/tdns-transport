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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose"
	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

func main() {
	ok := true
	ok = testRouter() && ok
	ok = testPeerRegistry() && ok
	ok = testMiddleware() && ok
	ok = testCryptoBackend() && ok
	ok = testDiscovery() && ok
	ok = testReceivePipeline() && ok

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
	// Payload crypto is what makes a verification key mandatory for a
	// discovered DNS endpoint; a consumer without crypto accepts any
	// endpoint. Exercise the documented contract: with crypto on.
	backend, err := crypto.GetBackend("jose")
	if err != nil {
		fmt.Printf("  FAIL: get JOSE backend: %v\n", err)
		return false
	}
	priv, pub, err := backend.GenerateKeypair()
	if err != nil {
		fmt.Printf("  FAIL: generate keypair: %v\n", err)
		return false
	}
	pc, err := transport.NewPayloadCrypto(&transport.PayloadCryptoConfig{Backend: backend, Enabled: true})
	if err != nil {
		fmt.Printf("  FAIL: payload crypto: %v\n", err)
		return false
	}
	pc.SetLocalKeys(priv, pub)
	tm := transport.NewTransportManager(&transport.TransportManagerConfig{
		LocalID:             "exercise.example.",
		ControlZone:         "mp-control.example.",
		SupportedMechanisms: []string{"dns"},
		PayloadCrypto:       pc,
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

	// A discovered DNS endpoint without a verification key is refused when
	// payload crypto is on (the receive path needs the key to decrypt), and
	// the completion seam does not fire for it.
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

// parseExercisePayload is the minimum a consumer must give transport as
// ChunkNotifyHandler.ParseApp: the verb and the sender identity, read from
// the consumer's own payload format. Transport has no parser of its own;
// its own verbs (hello, beat, ping, confirm) arrive through this one too.
func parseExercisePayload(distributionID string, payload []byte, sourceAddr string) (*transport.IncomingMessage, error) {
	var fields struct {
		Verb   string `json:"MessageType"`
		Sender string `json:"MyIdentity"`
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, err
	}
	if fields.Verb == "" {
		return nil, fmt.Errorf("no verb in payload")
	}
	return &transport.IncomingMessage{
		TypeToken:      fields.Verb,
		SenderID:       fields.Sender,
		DistributionID: distributionID,
		Payload:        payload,
		ReceivedAt:     time.Now(),
		SourceAddr:     sourceAddr,
	}, nil
}

// captureWriter is a dns.ResponseWriter that keeps the reply.
type captureWriter struct {
	reply *dns.Msg
}

func (w *captureWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
}
func (w *captureWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 5300}
}
func (w *captureWriter) WriteMsg(m *dns.Msg) error { w.reply = m; return nil }
func (w *captureWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("raw write not supported") }
func (w *captureWriter) Close() error              { return nil }
func (w *captureWriter) TsigStatus() error         { return nil }
func (w *captureWriter) TsigTimersOnly(bool)       {}
func (w *captureWriter) Hijack()                   {}

// testReceivePipeline drives a NOTIFY(CHUNK) through the receive pipeline
// with the minimal parser above and no payload crypto: the ping is routed
// to transport's own handler and the DNS response carries its inline
// confirmation in the EDNS0 CHUNK option.
func testReceivePipeline() bool {
	fmt.Println("--- Receive pipeline ---")
	tm := transport.NewTransportManager(&transport.TransportManagerConfig{
		LocalID:             "exercise.example.",
		ControlZone:         "mp-control.example.",
		SupportedMechanisms: []string{"dns"},
	})
	if err := transport.InitializeRouter(tm.Router, &transport.RouterConfig{PeerRegistry: tm.PeerRegistry}); err != nil {
		fmt.Printf("  FAIL: InitializeRouter: %v\n", err)
		return false
	}
	tm.ChunkHandler.ParseApp = parseExercisePayload

	payload := []byte(`{"MessageType":"ping","MyIdentity":"peer.example.","nonce":"n-1"}`)
	qname := "d1.peer.example."
	notify := new(dns.Msg)
	notify.SetNotify(qname)
	notify.Question = []dns.Question{{Name: qname, Qtype: core.TypeCHUNK, Qclass: dns.ClassINET}}
	notify.SetEdns0(4096, true)
	notify.IsEdns0().Option = append(notify.IsEdns0().Option, edns0.CreateChunkOption(core.FormatJSON, nil, payload))

	w := &captureWriter{}
	if err := tm.ChunkHandler.RouteViaRouter(context.Background(), qname, notify, w); err != nil {
		fmt.Printf("  FAIL: RouteViaRouter: %v\n", err)
		return false
	}
	if w.reply == nil || w.reply.Rcode != dns.RcodeSuccess {
		fmt.Printf("  FAIL: no NOERROR reply: %v\n", w.reply)
		return false
	}
	opt := w.reply.IsEdns0()
	if opt == nil {
		fmt.Println("  FAIL: reply carries no EDNS0")
		return false
	}
	var confirm string
	for _, o := range opt.Option {
		if local, ok := o.(*dns.EDNS0_LOCAL); ok && local.Code == edns0.EDNS0_CHUNK_OPTION_CODE {
			chunk, err := edns0.ParseChunkOption(local)
			if err != nil {
				fmt.Printf("  FAIL: reply CHUNK option: %v\n", err)
				return false
			}
			confirm = string(chunk.Data)
		}
	}
	if !strings.Contains(confirm, `"ping_confirm"`) || !strings.Contains(confirm, `"n-1"`) {
		fmt.Printf("  FAIL: inline confirmation %q lacks the ping echo\n", confirm)
		return false
	}
	fmt.Println("  OK: ping routed through the pipeline; inline confirmation echoed the nonce")

	// Without a parser the pipeline refuses to run at all.
	tm.ChunkHandler.ParseApp = nil
	if err := tm.ChunkHandler.RouteViaRouter(context.Background(), qname, notify, &captureWriter{}); err == nil {
		fmt.Println("  FAIL: pipeline ran without a parser")
		return false
	}
	fmt.Println("  OK: pipeline refuses to run without a parser")
	return true
}
