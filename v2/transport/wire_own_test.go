/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Byte-identity gate for transport's own wire structs (C4b). The goldens
 * in testdata/golden-wire were captured from the tdns core Agent*Post
 * structs the senders marshalled before step 3, with these exact inputs;
 * a change to any key, its order or its omission rule fails here.
 */

package transport

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestOwnWireGoldens(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := map[string]interface{}{
		"hello": buildHelloPost(&HelloRequest{SenderID: "a.example.", SharedZones: []string{"z.example.", "ignored.example."}, Timestamp: at}, "b.example."),
		"beat": buildBeatPost(&BeatRequest{SenderID: "a.example.", Timestamp: at, Zones: []string{"z1.example.", "z2.example."},
			Gossip: json.RawMessage(`[{"group_hash":"abc"}]`)}, "b.example."),
		"beat-nogossip": buildBeatPost(&BeatRequest{SenderID: "a.example.", Timestamp: at}, "b.example."),
		"ping":          buildPingPost(&PingRequest{SenderID: "a.example.", Nonce: "n-1", Timestamp: at}, "b.example."),
	}
	for name, v := range cases {
		got, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want, err := os.ReadFile("testdata/golden-wire/" + name + ".json")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s wire bytes changed:\n got  %s\n want %s", name, got, want)
		}
	}
}

// The receive-side structs read what the send-side structs write.
func TestOwnWireRoundTrip(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	hb, _ := json.Marshal(buildHelloPost(&HelloRequest{SenderID: "a.example.", SharedZones: []string{"z.example."}, Timestamp: at}, "b.example."))
	hello, err := ParseHelloPayload(hb)
	if err != nil || hello.GetSenderID() != "a.example." || hello.MessageType != VerbHello || hello.Zone != "z.example." {
		t.Errorf("hello round trip: %+v %v", hello, err)
	}
	bb, _ := json.Marshal(buildBeatPost(&BeatRequest{SenderID: "a.example.", Timestamp: at, Zones: []string{"z1.example."}}, "b.example."))
	beat, err := ParseBeatPayload(bb)
	if err != nil || beat.GetSenderID() != "a.example." || beat.MessageType != VerbBeat || len(beat.Zones) != 1 {
		t.Errorf("beat round trip: %+v %v", beat, err)
	}
	pb, _ := json.Marshal(buildPingPost(&PingRequest{SenderID: "a.example.", Nonce: "n-1", Timestamp: at}, "b.example."))
	var ping DnsPingPayload
	if err := json.Unmarshal(pb, &ping); err != nil || ping.GetSenderID() != "a.example." || ping.Nonce != "n-1" || ping.MessageType != VerbPing {
		t.Errorf("ping round trip: %+v %v", ping, err)
	}
}
