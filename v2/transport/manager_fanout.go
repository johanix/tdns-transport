/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Multi-mechanism fan-out for the transport-own hello and beat (transport
 * redesign, Stage D1). The application used to hold this loop in its
 * SendHelloWithFallback / SendBeatWithFallback; it now decides only WHICH
 * mechanisms are eligible and what each outcome means.
 */

package transport

import (
	"context"
	"fmt"
	"strings"
)

// MechanismResult is one mechanism's outcome in a SendAll fan-out.
type MechanismResult struct {
	Mechanism string
	Response  interface{} // *HelloResponse or *BeatResponse; nil when Err is set
	Err       error
}

// mechanismTransport maps a mechanism name ("API", "DNS") to the transport
// that serves it, or nil when that transport is not configured.
func (tm *TransportManager) mechanismTransport(name string) Transport {
	switch strings.ToUpper(name) {
	case "API":
		if tm.APITransport != nil {
			return tm.APITransport
		}
	case "DNS":
		if tm.DNSTransport != nil {
			return tm.DNSTransport
		}
	}
	return nil
}

// SendAll sends a *HelloRequest or *BeatRequest on every listed mechanism,
// sequentially and in the given order, and returns each mechanism's
// outcome keyed by mechanism name (string-keyed, so a third mechanism
// slots in without an API change). Unlike Send it never stops at the
// first success: hello and beat maintain per-mechanism state, so every
// eligible mechanism is exercised (the pre-D1 semantics of the
// application's fallback senders). A mechanism without a configured
// transport is reported as an error in its result. The caller decides
// eligibility and applies the results.
func (tm *TransportManager) SendAll(ctx context.Context, peer *Peer, mechanisms []string, req interface{}) map[string]MechanismResult {
	return sendAllWith(ctx, peer, mechanisms, req, tm.mechanismTransport)
}

func sendAllWith(ctx context.Context, peer *Peer, mechanisms []string, req interface{}, lookup func(string) Transport) map[string]MechanismResult {
	out := make(map[string]MechanismResult, len(mechanisms))
	for _, m := range mechanisms {
		key := strings.ToUpper(m)
		t := lookup(key)
		if t == nil {
			out[key] = MechanismResult{Mechanism: key, Err: fmt.Errorf("SendAll: mechanism %q has no configured transport", key)}
			continue
		}
		var (
			resp interface{}
			err  error
		)
		switch r := req.(type) {
		case *HelloRequest:
			var hr *HelloResponse
			hr, err = t.Hello(ctx, peer, r)
			if err == nil && hr != nil {
				resp = hr
			}
		case *BeatRequest:
			var br *BeatResponse
			br, err = t.Beat(ctx, peer, r)
			if err == nil && br != nil {
				resp = br
			}
		default:
			err = fmt.Errorf("SendAll: unsupported request type %T (use Send for application messages)", req)
		}
		out[key] = MechanismResult{Mechanism: key, Response: resp, Err: err}
	}
	return out
}
