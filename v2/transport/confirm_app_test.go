/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The application's own field on a confirmation (tdns-mp #211, P2): App is
 * carried as is, over both mechanisms, and reaches the application's
 * OnConfirmationReceived with the confirmation's message. A confirmation
 * without it is as before, byte for byte.
 */
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/miekg/dns"
)

// testConfirmApp is the application data testConfirmRequest carries.
const testConfirmApp = `{"stamp":"s-1"}`

// routeConfirm sends req's payload through the receive pipeline as one
// posted to /msg by a.example., and returns what the application's
// OnConfirmationReceived got.
func routeConfirm(t *testing.T, req *ConfirmRequest) *IncomingConfirmation {
	t.Helper()
	h := NewChunkNotifyHandler("control.example.", "b.example.", nil)
	h.ParseApp = func(distributionID string, payload []byte, sourceAddr string) (*IncomingMessage, error) {
		var c DnsConfirmPayload
		if err := json.Unmarshal(payload, &c); err != nil {
			return nil, err
		}
		return &IncomingMessage{TypeToken: c.Type, SenderID: c.SenderID, Zone: c.Zone, DistributionID: distributionID,
			Payload: payload, SourceAddr: sourceAddr}, nil
	}
	h.IsPeerAuthorized = func(string, string) (bool, string) { return true, "test policy" }
	var got []*IncomingConfirmation
	h.OnConfirmationReceived = func(c *IncomingConfirmation) { got = append(got, c) }
	h.Router = NewDNSMessageRouter()
	if err := InitializeRouter(h.Router, &RouterConfig{Confirmations: true}); err != nil {
		t.Fatal(err)
	}

	body, err := json.Marshal(buildConfirmPayload(req))
	if err != nil {
		t.Fatal(err)
	}
	sink := &recordingSink{}
	if err := h.RouteAPIPayload(context.Background(), body, "127.0.0.1:0", "a.example.", sink); err != nil {
		t.Fatalf("RouteAPIPayload: %v", err)
	}
	if sink.failed || sink.rcode != dns.RcodeSuccess {
		t.Fatalf("the confirmation was refused: rcode %s", dns.RcodeToString[sink.rcode])
	}
	if len(got) != 1 {
		t.Fatalf("OnConfirmationReceived called %d times, want 1", len(got))
	}
	return got[0]
}

// The application's field goes out in the confirmation (the golden, which
// both mechanisms send byte for byte: TestAPIConfirmPostsTheDNSConfirmPayload)
// and reaches the receiving application as sent.
func TestConfirmCarriesTheApplicationField(t *testing.T) {
	c := routeConfirm(t, testConfirmRequest())
	if !bytes.Equal(c.App, []byte(testConfirmApp)) {
		t.Errorf("App %s, want %s", c.App, testConfirmApp)
	}
}

// A confirmation without the field is the one sent before it existed, byte
// for byte, and the receiving application gets no App.
func TestAConfirmWithoutTheFieldIsAsBefore(t *testing.T) {
	req := testConfirmRequest()
	req.App = nil
	got, err := json.Marshal(buildConfirmPayload(req))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/golden-wire/confirm-noapp.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("confirm without App:\n got  %s\n want %s", got, want)
	}
	if c := routeConfirm(t, req); len(c.App) != 0 {
		t.Errorf("App %s for a confirmation that carries none", c.App)
	}
}

// The application gets the whole confirmation: a PENDING's text with its
// status, and the fields it got before as arguments.
func TestTheCallbackGetsTheMessage(t *testing.T) {
	req := testConfirmRequest()
	req.Status, req.Message = ConfirmPending, "kept: this agent acts by serial 8, the message was made under 7"
	c := routeConfirm(t, req)
	if c.Status != ConfirmPending || c.Message != req.Message {
		t.Errorf("status %v message %q, want PENDING %q", c.Status, c.Message, req.Message)
	}
	if c.DistributionID != "d-1" || c.PeerID != "a.example." || c.Zone != "z.example." || c.Nonce != "n-1" ||
		len(c.AppliedRecords) != 1 || len(c.RemovedRecords) != 1 || len(c.RejectedItems) != 1 || len(c.IgnoredRecords) != 1 || !c.Truncated {
		t.Errorf("the confirmation's other fields did not all arrive: %+v", c)
	}
}
