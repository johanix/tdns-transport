package transport

import "testing"

// Token is the verb; App carries scope, token and payload.
func TestIncomingMessageToken(t *testing.T) {
	var nilMsg *IncomingMessage
	if nilMsg.Token() != "" || nilMsg.App().TypeToken != "" {
		t.Fatal("nil message must yield empty token")
	}
	m := &IncomingMessage{TypeToken: "sync", Zone: "z.example.", Payload: []byte(`{"MessageType":"sync"}`)}
	if m.Token() != "sync" {
		t.Errorf("Token(): got %q", m.Token())
	}
	app := m.App()
	if app.Scope != "z.example." || app.TypeToken != "sync" || string(app.Payload) != `{"MessageType":"sync"}` {
		t.Errorf("App(): %+v", app)
	}
}

// RouteToCallback delivers a handled message and skips one the default
// handler refused (unhandled_message_type set).
func TestRouteToCallback_skipsUnhandled(t *testing.T) {
	delivered := 0
	mw := RouteToCallback(func(*IncomingMessage) { delivered++ })
	next := func(*MessageContext) error { return nil }
	ctx := NewMessageContext(nil, "127.0.0.1:0")
	ctx.SetIncoming(&IncomingMessage{TypeToken: "sync"})
	ctx.markUnhandled("sync")
	if err := mw(ctx, next); err != nil || delivered != 0 {
		t.Fatalf("refused verb: err=%v delivered=%d, want no delivery", err, delivered)
	}
	delete(ctx.Data, ctxKeyUnhandledType)
	if err := mw(ctx, next); err != nil || delivered != 1 {
		t.Fatalf("handled verb: err=%v delivered=%d, want 1", err, delivered)
	}
}

// A transport-own handler needs the parsed message the pipeline stores; a
// router entered without one is misused and says so.
func TestTransportOwnHandlersNeedParsedMessage(t *testing.T) {
	for name, h := range map[string]MessageHandlerFunc{"hello": handleHello, "beat": handleBeat} {
		ctx := NewMessageContext(nil, "127.0.0.1:0")
		ctx.ChunkPayload = []byte(`{"MessageType":"` + name + `","MyIdentity":"a."}`)
		if err := h(ctx); err == nil {
			t.Errorf("%s: handler accepted a context without a parsed message", name)
		}
		ctx.SetIncoming(&IncomingMessage{TypeToken: name, SenderID: "a."})
		if err := h(ctx); err != nil {
			t.Errorf("%s: handler with a parsed message: %v", name, err)
		}
		if got, _ := ctx.handledType(); got != name {
			t.Errorf("%s: handled type = %q", name, got)
		}
	}
}
