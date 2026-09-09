package transport

import "testing"

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
