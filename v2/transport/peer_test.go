/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package transport

import (
	"testing"
	"time"
)

// fakeAgent is a minimal AgentLike implementation for testing
// PopulateFromAgent. It returns the configured snapshots verbatim.
type fakeAgent struct {
	api AgentMechanismSnapshot
	dns AgentMechanismSnapshot
}

func (f *fakeAgent) APIMechanismState() AgentMechanismSnapshot { return f.api }
func (f *fakeAgent) DNSMechanismState() AgentMechanismSnapshot { return f.dns }

func TestPopulateFromAgent_FillsBothMechanisms(t *testing.T) {
	now := time.Now()
	helloRecv := now.Add(-30 * time.Second)
	beatRecv := now.Add(-5 * time.Second)
	beatSent := now.Add(-7 * time.Second)

	dnsAddr := &Address{Host: "1.2.3.4", Port: 53, Transport: "udp"}

	agent := &fakeAgent{
		api: AgentMechanismSnapshot{
			State:            PeerStateOperational,
			StateReason:      "api hello-done",
			LastHelloRecv:    helloRecv,
			LastBeatRecv:     beatRecv,
			LastBeatSent:     beatSent,
			BeatSequence:     42,
			ConsecutiveFails: 0,
		},
		dns: AgentMechanismSnapshot{
			State:            PeerStateOperational,
			StateReason:      "dns hello-done",
			Address:          dnsAddr,
			LastHelloRecv:    helloRecv,
			LastBeatRecv:     beatRecv,
			LastBeatSent:     beatSent,
			BeatSequence:     17,
			ConsecutiveFails: 1,
		},
	}

	peer := NewPeer("test.example.com.")
	peer.PopulateFromAgent(agent)

	api := peer.Mechanisms["API"]
	if api == nil {
		t.Fatal("expected API mechanism populated")
	}
	if api.State != PeerStateOperational {
		t.Errorf("API state: got %v, want %v", api.State, PeerStateOperational)
	}
	if api.StateReason != "api hello-done" {
		t.Errorf("API reason: got %q", api.StateReason)
	}
	if !api.LastHelloRecv.Equal(helloRecv) {
		t.Errorf("API LastHelloRecv: got %v, want %v", api.LastHelloRecv, helloRecv)
	}
	if api.BeatSequence != 42 {
		t.Errorf("API BeatSequence: got %d, want 42", api.BeatSequence)
	}

	dns := peer.Mechanisms["DNS"]
	if dns == nil {
		t.Fatal("expected DNS mechanism populated")
	}
	if dns.State != PeerStateOperational {
		t.Errorf("DNS state: got %v, want %v", dns.State, PeerStateOperational)
	}
	if dns.Address == nil || dns.Address.Host != "1.2.3.4" || dns.Address.Port != 53 {
		t.Errorf("DNS Address: got %+v", dns.Address)
	}
	if dns.ConsecutiveFails != 1 {
		t.Errorf("DNS ConsecutiveFails: got %d, want 1", dns.ConsecutiveFails)
	}
}

func TestPopulateFromAgent_NilAgentIsNoop(t *testing.T) {
	peer := NewPeer("test.example.com.")
	peer.PopulateFromAgent(nil)
	// Mechanisms are pre-populated by NewPeer in NEEDED state; ensure
	// nothing changed.
	if peer.Mechanisms["API"].State != PeerStateNeeded {
		t.Errorf("API state changed unexpectedly: %v", peer.Mechanisms["API"].State)
	}
}

func TestPopulateFromAgent_StateChangedTimestampOnlyOnTransition(t *testing.T) {
	peer := NewPeer("test.example.com.")
	originalChanged := peer.Mechanisms["API"].StateChanged

	// Same state — StateChanged must NOT update.
	agent := &fakeAgent{
		api: AgentMechanismSnapshot{State: PeerStateNeeded},
		dns: AgentMechanismSnapshot{State: PeerStateNeeded},
	}
	time.Sleep(2 * time.Millisecond)
	peer.PopulateFromAgent(agent)

	if !peer.Mechanisms["API"].StateChanged.Equal(originalChanged) {
		t.Errorf("StateChanged updated despite no transition: orig=%v new=%v",
			originalChanged, peer.Mechanisms["API"].StateChanged)
	}

	// Real transition — StateChanged must update.
	agent.api.State = PeerStateOperational
	time.Sleep(2 * time.Millisecond)
	peer.PopulateFromAgent(agent)

	if peer.Mechanisms["API"].StateChanged.Equal(originalChanged) {
		t.Error("StateChanged did not update on real transition")
	}
}

func TestPopulateFromAgent_HasMechanismAfterPopulate(t *testing.T) {
	peer := NewPeer("test.example.com.")
	if peer.HasMechanism("DNS") {
		t.Error("fresh peer should not have DNS mechanism (no Address)")
	}

	agent := &fakeAgent{
		dns: AgentMechanismSnapshot{
			State:   PeerStateOperational,
			Address: &Address{Host: "1.2.3.4", Port: 53, Transport: "udp"},
		},
	}
	peer.PopulateFromAgent(agent)

	if !peer.HasMechanism("DNS") {
		t.Error("after PopulateFromAgent with DNS Address, HasMechanism(DNS) should be true")
	}

	// API still false: PopulateFromAgent does not set peer.APIEndpoint.
	if peer.HasMechanism("API") {
		t.Error("HasMechanism(API) should remain false until peer.APIEndpoint is set")
	}

	// Set APIEndpoint and re-check.
	peer.APIEndpoint = "https://test.example.com/api"
	if !peer.HasMechanism("API") {
		t.Error("HasMechanism(API) should be true once APIEndpoint is set")
	}
}
