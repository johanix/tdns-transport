/*
 * Tests for the per-mechanism crypto slots (Phase 2.5: material moved here
 * from tdns-mp's transitional agentMeta sidecar).
 */
package transport

import (
	"testing"

	"github.com/miekg/dns"
)

func TestMechanismCryptoAccessors(t *testing.T) {
	p := NewPeer("agent.crypto.test.")

	t.Run("empty peer returns zero values", func(t *testing.T) {
		if p.MechanismTLSA("API") != nil {
			t.Fatal("expected nil TLSA on fresh peer")
		}
		if jwk, alg := p.MechanismJWK("DNS"); jwk != "" || alg != "" {
			t.Fatal("expected empty JWK on fresh peer")
		}
		if p.MechanismKeyRR("DNS") != nil {
			t.Fatal("expected nil KeyRR on fresh peer")
		}
	})

	t.Run("set and get per mechanism, independently", func(t *testing.T) {
		tlsa := &dns.TLSA{Usage: 3, Selector: 1, MatchingType: 1, Certificate: "abcd"}
		key := &dns.KEY{}
		p.SetMechanismTLSA("API", tlsa)
		p.SetMechanismJWK("DNS", `{"kty":"OKP"}`, "Ed25519")
		p.SetMechanismKeyRR("DNS", key)

		if got := p.MechanismTLSA("API"); got != tlsa {
			t.Fatal("API TLSA not returned")
		}
		if got := p.MechanismTLSA("DNS"); got != nil {
			t.Fatal("DNS must not see the API TLSA")
		}
		jwk, alg := p.MechanismJWK("DNS")
		if jwk != `{"kty":"OKP"}` || alg != "Ed25519" {
			t.Fatalf("DNS JWK round-trip failed: %q %q", jwk, alg)
		}
		if got := p.MechanismKeyRR("DNS"); got != key {
			t.Fatal("DNS KeyRR not returned")
		}
	})

	t.Run("replace semantics: TLSA/KeyRR overwrite, including to nil", func(t *testing.T) {
		p.SetMechanismTLSA("API", nil)
		if p.MechanismTLSA("API") != nil {
			t.Fatal("re-discovery must be able to clear the TLSA")
		}
		p.SetMechanismKeyRR("DNS", nil)
		if p.MechanismKeyRR("DNS") != nil {
			t.Fatal("re-discovery must be able to clear the KeyRR")
		}
		// JWK survives (callers gate on non-empty; the setter itself was not
		// called again) — the sidecar's merge semantics.
		if jwk, _ := p.MechanismJWK("DNS"); jwk == "" {
			t.Fatal("JWK must survive TLSA/KeyRR replacement")
		}
	})
}
