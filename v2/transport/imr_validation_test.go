/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Discovery trusts only what the resolver validated, when told to.
 */
package transport

import (
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

func TestDiscoveryLookupsRequireValidationWhenTheImrDoes(t *testing.T) {
	strict := &Imr{Imr: &tdns.Imr{RequireDnssecValidation: true}}
	lax := &Imr{Imr: &tdns.Imr{}}
	validated := &tdns.ImrResponse{Validated: true}
	insecure := &tdns.ImrResponse{Validated: false}

	if err := strict.requireValidated(validated, "SVCB", "dns.agent.example."); err != nil {
		t.Errorf("a validated answer refused: %v", err)
	}
	err := strict.requireValidated(insecure, "SVCB", "dns.agent.example.")
	if err == nil {
		t.Fatal("an unvalidated answer taken under require-dnssec-validation")
	}
	if !strings.Contains(err.Error(), "SVCB at dns.agent.example.") || !strings.Contains(err.Error(), "require-dnssec-validation") {
		t.Errorf("the refusal does not say what and why: %v", err)
	}
	if err := lax.requireValidated(insecure, "KEY", "agent.example."); err != nil {
		t.Errorf("without the setting an unvalidated answer is refused: %v", err)
	}
	// no IMR, no answer: nothing to judge
	var none *Imr
	if err := none.requireValidated(insecure, "URI", "x."); err != nil {
		t.Errorf("a nil IMR refused: %v", err)
	}
	if err := strict.requireValidated(nil, "URI", "x."); err != nil {
		t.Errorf("a nil answer refused: %v", err)
	}
}
