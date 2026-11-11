package transport

import (
	"testing"
	"time"
)

// A failed outbound send on a mechanism that still gets beats makes that
// mechanism read DEGRADED (tdns-mp #236): a one-way confirmation pair must
// show in the per-mechanism reading, not only in an hourly log.
func TestRecordMechanismFailureDegradesTheMechanism(t *testing.T) {
	p := NewPeer("peer.example.")
	p.SetMechanismState("API", PeerStateOperational, "beat ok")
	p.SetMechanismLastBeatSent("API", time.Now())
	if st, _ := p.MechanismEffectiveState("API"); st != PeerStateOperational {
		t.Fatalf("before failure: %v, want OPERATIONAL", st)
	}

	p.RecordMechanismFailure("API")
	if p.MechanismConsecutiveFails("API") != 1 {
		t.Fatalf("ConsecutiveFails %d, want 1", p.MechanismConsecutiveFails("API"))
	}
	if st, _ := p.MechanismEffectiveState("API"); st != PeerStateDegraded {
		t.Fatalf("after failure: %v, want DEGRADED", st)
	}

	p.RecordMechanismSuccess("API")
	if p.MechanismConsecutiveFails("API") != 0 {
		t.Fatalf("after success: ConsecutiveFails %d, want 0", p.MechanismConsecutiveFails("API"))
	}
	if st, _ := p.MechanismEffectiveState("API"); st != PeerStateOperational {
		t.Fatalf("after success: %v, want OPERATIONAL", st)
	}
}

// A failed send says nothing of whether the peer is alive: on the only
// mechanism of a pair whose beats succeed, the peer stays OPERATIONAL, and
// that mechanism alone reads DEGRADED. Beats that stop still move the peer
// down (tdns-mp #337).
func TestAFailedSendLeavesEffectiveStateToTheBeats(t *testing.T) {
	p := NewPeer("peer.example.")
	p.SetMechanismState("DNS", PeerStateOperational, "beat ok")
	p.SetMechanismLastBeatSent("DNS", time.Now())

	p.RecordMechanismFailure("DNS")
	if st := p.EffectiveState(); st != PeerStateOperational {
		t.Fatalf("after a failed send: %v, want OPERATIONAL", st)
	}
	if st, _ := p.MechanismEffectiveState("DNS"); st != PeerStateDegraded {
		t.Fatalf("the mechanism after a failed send: %v, want DEGRADED", st)
	}

	// a beat's success does not clear the count: only a send does
	p.SetMechanismLastBeatSent("DNS", time.Now())
	if st, _ := p.MechanismEffectiveState("DNS"); st != PeerStateDegraded {
		t.Fatalf("the mechanism after a beat: %v, want DEGRADED", st)
	}

	p.SetMechanismLastBeatSent("DNS", time.Now().Add(-3*30*time.Second))
	if st := p.EffectiveState(); st != PeerStateDegraded {
		t.Fatalf("beats 3 intervals old: %v, want DEGRADED", st)
	}
	p.SetMechanismLastBeatSent("DNS", time.Now().Add(-11*30*time.Second))
	if st := p.EffectiveState(); st != PeerStateInterrupted {
		t.Fatalf("beats 11 intervals old: %v, want INTERRUPTED", st)
	}
	if st, _ := p.MechanismEffectiveState("DNS"); st != PeerStateInterrupted {
		t.Fatalf("the mechanism with beats 11 intervals old: %v, want INTERRUPTED", st)
	}
}
