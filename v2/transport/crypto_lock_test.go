/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The peer key maps are written by discovery while messages to and from
 * other peers are wrapped and unwrapped. Run under -race.
 */

package transport

import (
	"fmt"
	"sync"
	"testing"
)

func TestAKeyAddedDuringTrafficDoesNotRaceTheWrap(t *testing.T) {
	sender, receiver := seamPair(t)
	_, _, aPub, _, bPub := seamKeys(t)

	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 50 {
			id := fmt.Sprintf("p%d.example.", i)
			sender.GetCrypto().AddPeerKey(id, bPub)
			sender.GetCrypto().AddPeerVerificationKey(id, bPub)
			receiver.GetCrypto().AddPeerKey(id, aPub)
			receiver.GetCrypto().AddPeerVerificationKey(id, aPub)
		}
	})
	wg.Go(func() {
		for range 20 {
			wire, err := sender.wrapOutgoing("b.example.", []byte(seamPlaintext))
			if err != nil {
				t.Errorf("wrap: %v", err)
				return
			}
			plain, err := receiver.unwrapIncomingFromPeerEnvelope(wire, "a.example.", EnvelopeJOSE)
			if err != nil {
				t.Errorf("unwrap: %v", err)
				return
			}
			if string(plain) != seamPlaintext {
				t.Errorf("unwrap = %q, want %q", plain, seamPlaintext)
				return
			}
		}
	})
	wg.Wait()

	if ids := receiver.GetCrypto().peerVerificationKeyIDs(); len(ids) != 51 {
		t.Errorf("receiver holds %d verification keys, want 51", len(ids))
	}
}
