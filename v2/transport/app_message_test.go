package transport

import "testing"

// Token prefers TypeToken over the legacy Type field when both are set.
func TestIncomingMessageToken_prefersTypeToken(t *testing.T) {
	m := &IncomingMessage{Type: "sync", TypeToken: "keystate"}
	if m.Token() != "keystate" {
		t.Fatalf("Token() = %q, want keystate", m.Token())
	}
	if m.App().TypeToken != "keystate" {
		t.Fatalf("App().TypeToken = %q, want keystate", m.App().TypeToken)
	}
}

// RouteToCallback delivers a handled message and skips one the default
// handler refused (unhandled_message_type set).
func TestRouteToCallback_skipsUnhandled(t *testing.T) {
	delivered := 0
	mw := RouteToCallback(func(*IncomingMessage) { delivered++ })
	next := func(*MessageContext) error { return nil }
	ctx := NewMessageContext(nil, "127.0.0.1:0")
	ctx.Data["incoming_message"] = &IncomingMessage{Type: "sync", TypeToken: "sync"}
	ctx.Data["unhandled_message_type"] = "sync"
	if err := mw(ctx, next); err != nil || delivered != 0 {
		t.Fatalf("refused verb: err=%v delivered=%d, want no delivery", err, delivered)
	}
	delete(ctx.Data, "unhandled_message_type")
	if err := mw(ctx, next); err != nil || delivered != 1 {
		t.Fatalf("handled verb: err=%v delivered=%d, want 1", err, delivered)
	}
}

func TestIncomingMessageToken(t *testing.T) {
	var nilMsg *IncomingMessage
	if nilMsg.Token() != "" || nilMsg.App().TypeToken != "" {
		t.Fatal("nil message must yield empty token")
	}
	legacy := &IncomingMessage{Type: "sync", Zone: "z.example.", Payload: []byte(`{"MessageType":"sync"}`)}
	if legacy.Token() != "sync" {
		t.Errorf("Token() fallback: got %q", legacy.Token())
	}
	app := legacy.App()
	if app.Scope != "z.example." || app.TypeToken != "sync" || string(app.Payload) != `{"MessageType":"sync"}` {
		t.Errorf("App(): %+v", app)
	}
	both := &IncomingMessage{Type: "sync", TypeToken: "sync"}
	if both.Token() != "sync" {
		t.Errorf("Token(): got %q", both.Token())
	}
}

func TestParseIncomingMessageSetsTypeToken(t *testing.T) {
	for _, payload := range []string{`{"MessageType":"rfi","OriginatorID":"a.","Zone":"z."}`, `{"type":"relocate","sender_id":"a."}`} {
		m := ParseIncomingMessage([]byte(payload))
		if m == nil {
			t.Fatalf("parse failed for %s", payload)
		}
		if m.TypeToken == "" || m.TypeToken != m.Type {
			t.Errorf("%s: Type=%q TypeToken=%q", payload, m.Type, m.TypeToken)
		}
	}
	h := &ChunkNotifyHandler{}
	m, err := h.parsePayload("d1", []byte(`{"MessageType":"keystate","MyIdentity":"a.","Zone":"z."}`), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if m.TypeToken != "keystate" || m.Token() != "keystate" || m.App().Scope != "z." {
		t.Errorf("parsePayload: %+v", *m)
	}
}
