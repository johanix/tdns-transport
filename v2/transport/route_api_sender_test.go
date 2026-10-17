package transport

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// recordingSink is a ReplySink that keeps what the pipeline answered.
type recordingSink struct {
	payload []byte
	rcode   int
	failed  bool
}

func (s *recordingSink) Reply(_ *MessageContext, payload []byte, rcode int) error {
	s.payload, s.rcode = payload, rcode
	return nil
}

func (s *recordingSink) Fail(rcode int) error {
	s.failed, s.rcode = true, rcode
	return nil
}

// apiPipeline is a receive pipeline that takes beats from the identities
// in known, and records whom it was asked about, whom it built gossip
// for, and what it routed.
type apiPipeline struct {
	h         *ChunkNotifyHandler
	asked     []string
	gossipFor []string
	routed    []*IncomingMessage
}

func newAPIPipeline(t *testing.T, known ...string) *apiPipeline {
	t.Helper()
	p := &apiPipeline{h: NewChunkNotifyHandler("control.example.", "bob.example.", nil)}
	p.h.ParseApp = func(distributionID string, payload []byte, sourceAddr string) (*IncomingMessage, error) {
		var b BeatPost
		if err := json.Unmarshal(payload, &b); err != nil {
			return nil, err
		}
		return &IncomingMessage{TypeToken: b.MessageType, SenderID: b.MyIdentity, DistributionID: distributionID,
			Payload: payload, SourceAddr: sourceAddr}, nil
	}
	p.h.IsPeerAuthorized = func(sender, zone string) (bool, string) {
		p.asked = append(p.asked, sender)
		return slices.Contains(known, sender), "test policy"
	}
	p.h.GossipForPeer = func(peerID string) json.RawMessage {
		p.gossipFor = append(p.gossipFor, peerID)
		return json.RawMessage(`{"for":"` + peerID + `"}`)
	}
	p.h.Router = NewDNSMessageRouter()
	if err := InitializeRouter(p.h.Router, &RouterConfig{}); err != nil {
		t.Fatal(err)
	}
	p.h.Router.Use(RouteToCallback(func(m *IncomingMessage) { p.routed = append(p.routed, m) }))
	return p
}

// beatBody is a beat whose body names sender.
func beatBody(t *testing.T, sender string) []byte {
	t.Helper()
	body, err := json.Marshal(&BeatPost{MessageType: "beat", MyIdentity: sender, YourIdentity: "bob.example.",
		Zones: []string{"zone.example."}, Time: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Over HTTPS the transport-level sender is the identity the connection
// authenticated, as over DNS it is the identity in the query name: it is
// the one authorized, the message's TransportSender and the context's
// PeerID, and the one the answer's gossip is built for, whoever the body
// names. The body's name stays the message's SenderID.
func TestRouteAPIPayload_SenderIsTheAuthenticatedIdentity(t *testing.T) {
	p := newAPIPipeline(t, "alice.example.")
	sink := &recordingSink{}
	if err := p.h.RouteAPIPayload(context.Background(), beatBody(t, "carol.example."), "127.0.0.1:0", "alice.example", sink); err != nil {
		t.Fatalf("RouteAPIPayload: %v", err)
	}
	if sink.failed || sink.rcode != dns.RcodeSuccess {
		t.Fatalf("the beat was refused: rcode %s", dns.RcodeToString[sink.rcode])
	}
	for _, who := range p.asked {
		if who != "alice.example." {
			t.Errorf("authorization asked about %q, want only the authenticated alice.example.", who)
		}
	}
	if len(p.asked) == 0 {
		t.Error("the authenticated sender was not authorized")
	}
	if len(p.routed) != 1 {
		t.Fatalf("routed %d messages, want 1", len(p.routed))
	}
	if m := p.routed[0]; m.TransportSender != "alice.example." || m.SenderID != "carol.example." || m.Mechanism != MechanismAPI {
		t.Errorf("routed TransportSender %q SenderID %q Mechanism %q, want alice.example., carol.example., %s",
			m.TransportSender, m.SenderID, m.Mechanism, MechanismAPI)
	}
	if !slices.Equal(p.gossipFor, []string{"alice.example."}) {
		t.Errorf("gossip built for %v, want [alice.example.]", p.gossipFor)
	}
	var confirm struct {
		Gossip json.RawMessage `json:"Gossip"`
	}
	if err := json.Unmarshal(sink.payload, &confirm); err != nil || string(confirm.Gossip) != `{"for":"alice.example."}` {
		t.Errorf("the answer's gossip %s (%v), want alice's", confirm.Gossip, err)
	}
}

// An authenticated sender the application does not know is refused before
// the body is read, though the body names one it knows.
func TestRouteAPIPayload_UnknownAuthenticatedSenderRefused(t *testing.T) {
	p := newAPIPipeline(t, "carol.example.")
	sink := &recordingSink{}
	_ = p.h.RouteAPIPayload(context.Background(), beatBody(t, "carol.example."), "127.0.0.1:0", "alice.example.", sink)
	if !sink.failed || sink.rcode != dns.RcodeRefused {
		t.Errorf("failed %v rcode %s, want REFUSED", sink.failed, dns.RcodeToString[sink.rcode])
	}
	if !slices.Equal(p.asked, []string{"alice.example."}) {
		t.Errorf("authorization asked about %v, want [alice.example.]", p.asked)
	}
	if len(p.routed) != 0 || len(p.gossipFor) != 0 {
		t.Errorf("a refused sender's beat was routed (%d) or answered with gossip (%v)", len(p.routed), p.gossipFor)
	}
}

// A request no certificate authenticated leaves the sender to the body.
func TestRouteAPIPayload_NoAuthenticatedSender(t *testing.T) {
	p := newAPIPipeline(t, "carol.example.")
	sink := &recordingSink{}
	if err := p.h.RouteAPIPayload(context.Background(), beatBody(t, "carol.example."), "127.0.0.1:0", "", sink); err != nil {
		t.Fatalf("RouteAPIPayload: %v", err)
	}
	if sink.failed || sink.rcode != dns.RcodeSuccess {
		t.Fatalf("the beat was refused: rcode %s", dns.RcodeToString[sink.rcode])
	}
	if len(p.routed) != 1 || p.routed[0].TransportSender != "carol.example." {
		t.Fatalf("routed %+v, want one message from carol.example.", p.routed)
	}
	if !slices.Equal(p.gossipFor, []string{"carol.example."}) {
		t.Errorf("gossip built for %v, want [carol.example.]", p.gossipFor)
	}
}
