package transport

import (
	"testing"
	"time"
)

// A failed outbound send on a mechanism that still gets beats makes
// EffectiveState DEGRADED (tdns-mp #236): a one-way confirmation pair
// must show in the gossip matrix, not only in an hourly log.
func TestRecordMechanismFailureDegradesEffectiveState(t *testing.T) {
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
