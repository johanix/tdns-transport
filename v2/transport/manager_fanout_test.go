package transport

import (
	"context"
	"errors"
	"testing"
)

// fanoutTransport is a Transport whose Hello/Beat record the call order and
// return canned outcomes.
type fanoutTransport struct {
	name  string
	calls *[]string
	fail  bool
}

func (f *fanoutTransport) Hello(ctx context.Context, peer *Peer, req *HelloRequest) (*HelloResponse, error) {
	*f.calls = append(*f.calls, f.name+":hello")
	if f.fail {
		return nil, errors.New(f.name + " hello failed")
	}
	return &HelloResponse{ResponderID: peer.ID, Accepted: true}, nil
}
func (f *fanoutTransport) Beat(ctx context.Context, peer *Peer, req *BeatRequest) (*BeatResponse, error) {
	*f.calls = append(*f.calls, f.name+":beat")
	if f.fail {
		return nil, errors.New(f.name + " beat failed")
	}
	return &BeatResponse{ResponderID: peer.ID, Ack: true, Sequence: req.Sequence}, nil
}
func (f *fanoutTransport) SendApp(context.Context, *Peer, *AppMessage) (*AppResponse, error) {
	return nil, errors.New("not used")
}
func (f *fanoutTransport) Confirm(context.Context, *Peer, *ConfirmRequest) error { return nil }
func (f *fanoutTransport) Ping(context.Context, *Peer, *PingRequest) (*PingResponse, error) {
	return nil, errors.New("not used")
}
func (f *fanoutTransport) Name() string { return f.name }

func TestSendAll(t *testing.T) {
	var calls []string
	api := &fanoutTransport{name: "API", calls: &calls, fail: true}
	dns := &fanoutTransport{name: "DNS", calls: &calls}
	tm := &TransportManager{PeerRegistry: NewPeerRegistry()}
	// Only the DNS mechanism is configured through the real field; the API
	// transport is exercised through mechanismTransport's interface value.
	tm.DNSTransport = nil
	peer := tm.PeerRegistry.GetOrCreate("peer.example.")

	// Wire the fakes through a tiny override of mechanismTransport by
	// temporarily using the map-returning helper on a struct literal:
	// TransportManager's fields are concrete types, so use a shim manager.
	shim := &fanoutManager{tm: tm, api: api, dns: dns}

	res := shim.sendAll(context.Background(), peer, []string{"api", "DNS"}, &BeatRequest{SenderID: "me.", Sequence: 7})
	if len(res) != 2 || res["API"].Err == nil || res["DNS"].Err != nil {
		t.Fatalf("results: %+v", res)
	}
	if br, ok := res["DNS"].Response.(*BeatResponse); !ok || br.Sequence != 7 || !br.Ack {
		t.Errorf("DNS beat response: %+v", res["DNS"].Response)
	}
	if res["API"].Response != nil {
		t.Errorf("failed mechanism must carry a nil Response, got %T", res["API"].Response)
	}
	if len(calls) != 2 || calls[0] != "API:beat" || calls[1] != "DNS:beat" {
		t.Errorf("order/coverage: %v (every eligible mechanism must be tried, in order)", calls)
	}

	res = shim.sendAll(context.Background(), peer, []string{"DNS"}, &HelloRequest{SenderID: "me."})
	if hr, ok := res["DNS"].Response.(*HelloResponse); !ok || !hr.Accepted {
		t.Errorf("hello: %+v", res["DNS"])
	}
	res = shim.sendAll(context.Background(), peer, []string{"DOQ"}, &HelloRequest{})
	if res["DOQ"].Err == nil {
		t.Error("unknown mechanism must be reported as an error")
	}
	res = shim.sendAll(context.Background(), peer, []string{"DNS"}, &PingRequest{})
	if res["DNS"].Err == nil {
		t.Error("unsupported request type must be reported as an error")
	}
}

// fanoutManager reproduces SendAll over injectable transports so the test
// does not need real API/DNS transports.
type fanoutManager struct {
	tm       *TransportManager
	api, dns Transport
}

func (f *fanoutManager) sendAll(ctx context.Context, peer *Peer, mechanisms []string, req interface{}) map[string]MechanismResult {
	lookup := func(name string) Transport {
		switch name {
		case "API":
			return f.api
		case "DNS":
			return f.dns
		}
		return nil
	}
	return sendAllWith(ctx, peer, mechanisms, req, lookup)
}
