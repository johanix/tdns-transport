/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A DNS send reads the peer's address once (#45). A DNS refusal can clear
 * it between the send's check and the dial; the helpers dial the address
 * the caller checked, and do not read the peer's again.
 */
package transport

import (
	"context"
	"testing"
	"time"
)

// The peer's DNS carrier address is gone, as after a refusal that came
// between the caller's check and the send. Each helper still sends to the
// address the caller checked, and does not dereference the empty slot.
func TestADNSSendDialsTheAddressItChecked(t *testing.T) {
	rcv := newDNSChunkReceiver(t)
	rcv.setConfirm(true)
	dt := NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example.", Timeout: 2 * time.Second})
	peer := NewPeer("b.example.")
	if peer.DNSCarrierAddress() != nil {
		t.Fatal("the peer has a DNS carrier address; the test needs it gone")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	id := GenerateDistributionID()
	if _, err := dt.sendNotifyWithPayload(ctx, peer, rcv.addr, dt.buildNotifyQNAME(id), "beat", id, []byte(`{"MessageType":"beat"}`), false); err != nil {
		t.Errorf("sendNotifyWithPayload: %v", err)
	}
	if err := dt.sendNotifyUnconfirmed(ctx, peer, rcv.addr, dt.buildNotifyQNAME(GenerateDistributionID()), "status", []byte(`{"type":"status"}`)); err != nil {
		t.Errorf("sendNotifyUnconfirmed: %v", err)
	}
	if got := len(rcv.received()); got != 2 {
		t.Errorf("the receiver at the checked address got %d NOTIFYs, want 2", got)
	}
}
