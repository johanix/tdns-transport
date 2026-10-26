/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Peer discovery: DNS-based lookup of a peer's contact information and keys,
 * plus registration of the result onto the canonical transport.Peer.
 *
 * Phase 2.6 of the road-to-Stage-C plan: the discovery PROCESS lives here
 * (moved from tdns-mp's agent_discovery.go); the GATE — deciding WHICH peers
 * are needed — stays with the application, because it needs zone knowledge
 * transport never has. The application declares intent via
 * TransportManager.DiscoverPeer (or its own scheduling) and receives the
 * completed peer through the OnPeerDiscovered callback, which fires at the
 * end of RegisterDiscoveredPeer on every successful registration path.
 *
 * Carried invariants (peer-state truth fixes, 2026-06-11 — do not regress):
 *   - Fix E: only locally-supported mechanisms are probed.
 *   - Fix C: a mechanism is USABLE only with BOTH a URI and a resolved
 *     address; URI-without-address stays NEEDED (ContactInfo "partial") so
 *     the retrier revisits it, and no unusable contact URL is advertised.
 */
package transport

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

// DiscoveryResult holds the result of discovering a peer's transports.
type DiscoveryResult struct {
	Identity     string
	APIUri       string           // Base URI from URI record (e.g., https://agent.example.com:8443/api)
	DNSUri       string           // DNS endpoint if discovered
	JWKData      string           // Base64url-encoded JWK (preferred)
	PublicKey    crypto.PublicKey // Decoded public key from JWK
	KeyAlgorithm string           // Algorithm from JWK (e.g., "ES256")
	LegacyKeyRR  *dns.KEY         // Legacy KEY record (fallback if no JWK)
	TLSA         TLSASet          // TLSA RRset for TLS verification (its owner even when empty)
	TLSAFailed   bool             // the TLSA lookup failed: it says nothing, keep what was known
	tlsaSeq      uint64           // the TLSA lookup's number (nextTLSALookup); zero: numbered when registered
	APIAddresses []string         // IP addresses for API service from SVCB
	DNSAddresses []string         // IP addresses for DNS service from SVCB
	Port         uint16           // Port from URI record
	Error        error            // Any error during discovery; a *DiscoveryError when nothing could be used
	Partial      bool             // True if some records were found but discovery incomplete
	// Lookups is what each lookup saw: the DNSSEC verdict on the RRset, when
	// it expires from the cache, and why it gave nothing to use
	// (discovery_status.go).
	Lookups []DiscoveryLookup
}

// saw records a lookup made for mechanism.
func (r *DiscoveryResult) saw(mechanism string, l DiscoveryLookup) {
	l.Mechanism = mechanism
	r.Lookups = append(r.Lookups, l)
}

// usable reports whether the result alone makes mechanism usable: for the
// API a URI, an address and a usable TLSA from this lookup; for DNS a URI,
// an address and a key.
func (r *DiscoveryResult) usable(mechanism string) bool {
	switch mechanism {
	case "API":
		return r.APIUri != "" && len(r.APIAddresses) > 0 && !r.TLSAFailed && len(r.TLSA.Records) > 0
	case "DNS":
		return r.DNSUri != "" && len(r.DNSAddresses) > 0 && (r.JWKData != "" || r.LegacyKeyRR != nil)
	}
	return false
}

// refused reports whether mechanism's data was refused for want of DNSSEC
// validation, so that the mechanism cannot be used: some of its lookups were
// refused, and what the others found does not make it usable. Data that
// validated when it was looked up is used until it expires from the cache;
// once a lookup after that is refused, the mechanism has nothing validated
// to stand on, whatever it held before.
func (r *DiscoveryResult) refused(mechanism string) (DiscoveryLookup, bool) {
	if r.usable(mechanism) {
		return DiscoveryLookup{}, false
	}
	for _, l := range r.Lookups {
		if l.Mechanism == mechanism && l.Failure == FailureNotValidated {
			return l, true
		}
	}
	return DiscoveryLookup{}, false
}

// status is the result as the peer's discovery status, at now.
func (r *DiscoveryResult) status(now time.Time) DiscoveryStatus {
	s := DiscoveryStatus{At: now, Lookups: r.Lookups}
	var de *DiscoveryError
	if errors.As(r.Error, &de) {
		s.Failure, s.Reason = de.Failure(), de.Error()
	} else if r.Error != nil {
		s.Failure, s.Reason = FailureQuery, r.Error.Error()
	}
	return s
}

// logLookup logs a lookup that gave nothing to use: at Debug when the
// records are simply not there, as msg says, and at Warn when they may be
// there and could not be used, so that a refusal for want of validation or
// a resolver that cannot reach the zone is seen without debug logging.
func logLookup(msg, identity string, l DiscoveryLookup) {
	if l.Failure == FailureNoRecords {
		lgTransport().Debug(msg, "identity", identity, "lookup", l.String())
		return
	}
	lgTransport().Warn("discovery lookup gave nothing to use", "identity", identity, "lookup", l.String(), "failure", l.Failure.String())
}

// discoverAgentAPI performs DNS-based discovery of a peer's API transport.
//  1. URI record at _https._tcp.<identity> → get API endpoint URI and port
//  2. SVCB record at api.<identity> → get ipv4hint/ipv6hint addresses
//  3. TLSA record at _<port>._tcp.api.<identity> → get TLS certificate for verification
func (imr *Imr) discoverAgentAPI(ctx context.Context, identity string, result *DiscoveryResult) {
	if imr == nil || imr.Imr == nil {
		result.Error = fmt.Errorf("IMR engine not initialized")
		result.Partial = true
		return
	}
	identity = dns.Fqdn(identity)

	apiUri, apiHost, apiPort, l, err := imr.lookupAgentAPIEndpoint(ctx, identity)
	result.saw("API", l)
	if err == nil {
		result.APIUri = apiUri
		result.Port = apiPort

		// Look up SVCB at api.<identity> to get IP addresses
		apiServiceName := "api." + identity
		addresses, l, err := imr.lookupServiceAddresses(ctx, apiServiceName)
		result.saw("API", l)
		if err == nil {
			result.APIAddresses = addresses
		} else {
			logLookup("no SVCB record for API service", identity, l)
			result.Partial = true
		}

		// The TLSA RRset at _<port>._tcp.api.<identity>: what the peer's
		// certificate is checked against, at both ends. Without a usable
		// record the API mechanism is not usable.
		result.TLSA.Owner = fmt.Sprintf("_%d._tcp.%s", apiPort, dns.Fqdn(apiServiceName))
		result.tlsaSeq = nextTLSALookup()
		ans, err := imr.lookupTLSA(ctx, result.TLSA.Owner, false)
		switch {
		case err != nil:
			l := failedTLSALookup(result.TLSA.Owner, err)
			result.saw("API", l)
			logLookup("TLSA lookup for API service failed", identity, l)
			result.TLSAFailed = true
			result.Partial = true
		case !ans.Validated && imr.RequireDnssecValidation:
			// Vouches for nothing, and nor does the set held from before:
			// that was validated when it was looked up, and has expired
			// since. Registered as an empty set, so the one held is dropped,
			// as the TLSA checker drops it; the mechanism is refused
			// (DiscoveryResult.refused).
			l := ans.lookup(result.TLSA.Owner, true)
			result.saw("API", l)
			lgTransport().Warn("TLSA for API service not DNSSEC-validated and require-dnssec-validation is set; not used",
				"owner", result.TLSA.Owner, "lookup", l.String())
			result.Partial = true
		default:
			result.saw("API", ans.lookup(result.TLSA.Owner, imr.RequireDnssecValidation))
			result.TLSA.Records = ans.Records
			result.TLSA.Validated = ans.Validated
			if len(ans.Records) == 0 {
				lgTransport().Debug("no usable TLSA record for API service", "owner", result.TLSA.Owner, "denied", ans.Denied)
				result.Partial = true
			}
		}

		lgTransport().Info("found API endpoint", "uri", apiUri, "host", apiHost)
	} else {
		logLookup("no API URI record found", identity, l)
		result.Partial = true
	}
}

// discoverAgentDNS performs DNS-based discovery of a peer's DNS transport.
//  1. URI record at _dns._tcp.<identity> → get DNS endpoint URI and port
//  2. SVCB record at dns.<identity> → get ipv4hint/ipv6hint addresses
//  3. JWK record at dns.<identity> → get the peer's public key (preferred)
//  4. KEY record at dns.<identity> → get SIG(0) public key (legacy fallback if no JWK)
func (imr *Imr) discoverAgentDNS(ctx context.Context, identity string, result *DiscoveryResult) {
	if imr == nil || imr.Imr == nil {
		result.Error = fmt.Errorf("IMR engine not initialized")
		result.Partial = true
		return
	}
	identity = dns.Fqdn(identity)

	dnsUri, dnsHost, dnsPort, l, err := imr.lookupAgentDNSEndpoint(ctx, identity)
	result.saw("DNS", l)
	if err == nil {
		result.DNSUri = dnsUri

		// Look up SVCB at dns.<identity> to get IP addresses
		dnsServiceName := "dns." + identity
		addresses, l, err := imr.lookupServiceAddresses(ctx, dnsServiceName)
		result.saw("DNS", l)
		if err == nil {
			result.DNSAddresses = addresses
		} else {
			lgTransport().Warn("SVCB lookup failed for DNS service", "service", dnsServiceName, "lookup", l.String())
			result.Partial = true
		}

		// Look up JWK at dns.<identity> for the peer's public key
		jwkData, publicKey, algorithm, l, err := imr.lookupAgentJWK(ctx, identity)
		result.saw("DNS", l)
		if err == nil {
			result.JWKData = jwkData
			result.PublicKey = publicKey
			result.KeyAlgorithm = algorithm
			lgTransport().Info("found JWK record", "identity", identity, "algorithm", algorithm)
		} else {
			lgTransport().Warn("JWK lookup failed", "identity", identity, "lookup", l.String())

			// Fallback to KEY record for legacy support
			keyRR, l, err := imr.lookupAgentKEY(ctx, identity)
			result.saw("DNS", l)
			if err == nil {
				result.LegacyKeyRR = keyRR
				lgTransport().Info("using legacy KEY record", "identity", identity, "algorithm", keyRR.Algorithm)
			} else {
				lgTransport().Warn("KEY lookup failed (legacy fallback)", "identity", identity, "lookup", l.String())
				result.Partial = true
			}
		}

		lgTransport().Info("found DNS endpoint", "uri", dnsUri, "host", dnsHost, "port", dnsPort)
	} else {
		logLookup("no DNS URI record found (optional)", identity, l)
	}
}

// discoverAgent performs DNS-based discovery of a peer's contact information,
// but only for transports the LOCAL side supports (apiSupported/dnsSupported)
// — Fix E: probing an unsupported transport emits failing lookups and sets a
// spurious Partial. Each supported leg runs via discoverAgentAPI/DNS.
func (imr *Imr) discoverAgent(ctx context.Context, identity string, apiSupported, dnsSupported bool) *DiscoveryResult {
	result := &DiscoveryResult{
		Identity: identity,
	}

	if imr == nil || imr.Imr == nil {
		result.Error = fmt.Errorf("IMR engine not initialized")
		return result
	}

	if apiSupported {
		imr.discoverAgentAPI(ctx, identity, result)
	}
	if dnsSupported {
		imr.discoverAgentDNS(ctx, identity, result)
	}

	// Check if we have enough information to contact the peer. When not,
	// the error says why, from the URI lookup that tells the most: a URI
	// refused for want of validation is served and signed, and must not
	// read as missing.
	if result.APIUri == "" && result.DNSUri == "" {
		de := &DiscoveryError{Identity: identity, Lookup: DiscoveryLookup{Type: "URI", Owner: dns.Fqdn(identity),
			Failure: FailureNoRecords, Detail: "no API or DNS URI records"}}
		best := -1
		for _, l := range result.Lookups {
			if l.Type == "URI" && l.Failure.rank() > best {
				de.Lookup, best = l, l.Failure.rank()
			}
		}
		result.Error = de
		return result
	}

	lgTransport().Info("discovery complete", "identity", identity, "apiUri", result.APIUri, "dnsUri", result.DNSUri)
	return result
}

// RegisterDiscoveredPeer writes a discovery result onto the canonical
// transport.Peer: addresses/endpoints, per-mechanism crypto slots, wire
// verification keys (SecureWrapper), ContactInfo, and the guarded
// NEEDED→KNOWN promotions. Fires tm.OnPeerDiscovered(peer) on success, so
// the application can materialize its own view of the peer.
func (tm *TransportManager) RegisterDiscoveredPeer(result *DiscoveryResult) (err error) {
	if result.Error != nil {
		return fmt.Errorf("cannot register peer with discovery error: %w", result.Error)
	}

	// The top-level peer State is promoted to KNOWN further down, but ONLY
	// for a mechanism that actually became usable (URI + resolved address);
	// from ERROR too, which a failed discovery before this one leaves (the
	// application's OnDiscoveryFailed), and which EffectiveState shows once
	// no mechanism is active.
	// Setting it unconditionally made EffectiveState() report KNOWN for an
	// unreachable peer — the KNOWN/NEEDED contradiction (Fix C).
	peer := tm.PeerRegistry.GetOrCreate(result.Identity)
	st := result.status(time.Now())
	peer.setDiscoveryStatus(st)
	// A registration that fails further down is a discovery that gave
	// nothing to use: the status says why, and the refresh asks again.
	defer func() {
		if err != nil && st.Failure == FailureNone {
			st.Failure, st.Reason = FailureNoRecords, err.Error()
			peer.setDiscoveryStatus(st)
		}
	}()
	// Before any return: a mechanism refused for want of validation is not
	// used any more, also when the registration fails further down. A
	// refused mechanism is never usable (DiscoveryResult.refused), so no
	// promotion below undoes this.
	tm.demoteRefused(peer, result)

	// Register API transport address
	// Register the JWK public key (preferred) with the payload crypto
	if result.JWKData != "" && result.PublicKey != nil {
		if tm.DNSTransport != nil && tm.DNSTransport.SecureWrapper != nil {
			payloadCrypto := tm.DNSTransport.SecureWrapper.GetCrypto()
			if payloadCrypto != nil && payloadCrypto.Backend != nil {
				// Wrap the stdlib crypto.PublicKey in a backend-specific
				// wrapper; the backend reconstructs its own PublicKey type.
				wrappedKey, err := payloadCrypto.Backend.PublicKeyFromStdlib(result.PublicKey)
				if err != nil {
					lgTransport().Warn("failed to wrap public key", "identity", result.Identity, "err", err)
				} else {
					payloadCrypto.AddPeerKey(result.Identity, wrappedKey)
					payloadCrypto.AddPeerVerificationKey(result.Identity, wrappedKey)
					lgTransport().Info("added JWK public key to PayloadCrypto", "identity", result.Identity, "algorithm", result.KeyAlgorithm)
				}
			} else {
				lgTransport().Warn("cannot add peer key - PayloadCrypto not configured")
			}
		} else {
			lgTransport().Warn("cannot add peer key - SecureWrapper not configured")
		}
	}

	// A usable DNS mechanism needs a payload verification key (JWK or
	// KEY) when payload crypto is configured; without one the peer is
	// unusable for encrypted communication. API-only discovery has no such
	// requirement. Checked here, before any peer field is written, so a
	// failed registration leaves the peer as it was.
	// A mechanism whose data was refused for want of DNSSEC validation is
	// not usable, whatever it held before (DiscoveryResult.refused).
	_, apiRefused := result.refused("API")
	_, dnsRefused := result.refused("DNS")
	dnsUsable := !dnsRefused && result.DNSUri != "" && len(result.DNSAddresses) > 0
	if dnsUsable && tm.DNSTransport != nil && tm.DNSTransport.SecureWrapper != nil {
		hasVerificationKey := false
		if pc := tm.DNSTransport.SecureWrapper.GetCrypto(); pc != nil {
			_, hasVerificationKey = pc.getPeerVerificationKey(result.Identity)
		}
		if !hasVerificationKey {
			return fmt.Errorf("discovery for %s found endpoint but no verification key (JWK/KEY lookup failed)", result.Identity)
		}
	}

	// A refused mechanism's address is not written back: demoteRefused has
	// just dropped it, and nothing of its data is used until it validates.
	if result.APIUri != "" && !apiRefused {
		parsed, err := url.Parse(result.APIUri)
		if err != nil {
			return fmt.Errorf("invalid API URI %q: %w", result.APIUri, err)
		}

		port := uint16(443) // default
		if parsed.Port() != "" {
			p, err := strconv.Atoi(parsed.Port())
			if err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("invalid API URI port %q: %v", parsed.Port(), err)
			}
			port = uint16(p)
		}

		// Use the discovered IP address instead of the hostname. Non-fatal:
		// skip API address registration when SVCB addresses are missing, but
		// continue to the DNS leg.
		if len(result.APIAddresses) == 0 {
			lgTransport().Warn("no SVCB addresses for API transport, skipping API address registration", "identity", result.Identity)
		} else {
			host := result.APIAddresses[0]
			addr := &Address{
				Host:      host,
				Port:      port,
				Transport: "https",
				Path:      parsed.Path,
			}
			peer.SetDiscoveryAddress(addr)
			peer.SetMechanismAddress("API", addr)
			peer.SetAPIEndpoint(result.APIUri)
			peer.SetPreferredTransport("API")

			lgTransport().Info("registered peer with API endpoint", "identity", result.Identity, "endpoint", result.APIUri, "address", host, "port", port)
		}
	}

	// Register DNS transport address (NOT else-if: both can exist)
	if result.DNSUri != "" && !dnsRefused {
		parsed, err := url.Parse(result.DNSUri)
		if err != nil {
			return fmt.Errorf("invalid DNS URI %q: %w", result.DNSUri, err)
		}

		port := uint16(53) // default DNS port
		if parsed.Port() != "" {
			p, err := strconv.Atoi(parsed.Port())
			if err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("invalid DNS URI port %q: %v", parsed.Port(), err)
			}
			port = uint16(p)
		}

		if len(result.DNSAddresses) == 0 {
			lgTransport().Warn("no SVCB addresses for DNS transport, skipping DNS address registration", "identity", result.Identity)
		} else {
			host := result.DNSAddresses[0]
			addr := &Address{
				Host:      host,
				Port:      port,
				Transport: "udp",
			}

			// DiscoveryAddr is the slot the DNS carrier dials; when both
			// mechanisms resolve it holds the DNS address (API sends dial
			// the API slot, with APIEndpoint's name for TLS). The
			// per-mechanism slot keeps each address.
			// API stays the preferred transport when it also resolved,
			// matching Peer.PreferredMechanism and SelectTransport's default.
			peer.SetDiscoveryAddress(addr)
			peer.SetMechanismAddress("DNS", addr)
			peer.SetDNSEndpoint(result.DNSUri) // display/diagnostics (S2)
			peer.setPreferredTransportIfUnset("DNS")

			lgTransport().Info("registered peer with DNS endpoint", "identity", result.Identity, "endpoint", result.DNSUri, "address", host, "port", port)
		}
	}

	// Per-mechanism outcome: ContactInfo + guarded NEEDED→KNOWN promotion +
	// crypto slots. A mechanism is USABLE only with BOTH a URI and a
	// resolved address (Fix C); URI-without-address is recorded as
	// ContactInfo "partial" (the application derives its capability flags
	// from ContactInfo: "complete"/"partial" ⇒ offered, absent ⇒ not).
	// The TLSA: an answer, a denial included, replaces the set held. A
	// lookup that failed says nothing, so the set held stays, unless it is
	// for another name: the endpoint moved, and the old name's records
	// vouch for nothing at the new one. Of two answers the later lookup's
	// is kept (storeMechanismTLSA).
	tlsaGone := false
	if result.APIUri != "" && result.TLSA.Owner != "" {
		seq := result.tlsaSeq
		if seq == 0 {
			seq = nextTLSALookup()
		}
		switch {
		case !result.TLSAFailed:
			prev, stored := peer.storeMechanismTLSA("API", result.TLSA, seq, false)
			tlsaGone = stored && len(prev.Records) > 0 && len(result.TLSA.Records) == 0
		case peer.MechanismTLSA("API").Owner != result.TLSA.Owner:
			prev, stored := peer.storeMechanismTLSA("API", TLSASet{Owner: result.TLSA.Owner}, seq, false)
			tlsaGone = stored && len(prev.Records) > 0
		}
	}
	// HTTPS to a peer needs a TLSA to check its certificate against: without
	// one the API mechanism is not usable, and HTTPS is not attempted.
	// The set held must be for the name discovery found: one for another
	// name vouches for nothing at this endpoint.
	apiUsable := !apiRefused && result.APIUri != "" && len(result.APIAddresses) > 0 && peer.HasMechanismTLSA("API") &&
		peer.MechanismTLSA("API").Owner == result.TLSA.Owner
	if apiUsable {
		peer.SetMechanismContactInfo("API", "complete")
		// Guarded promotion: do not regress an already-established mechanism.
		// This is the per-mechanism discovery-phase write the send gates read.
		if raw, ok := peer.MechanismRawState("API"); !ok || raw <= PeerStateNeeded {
			peer.SetMechanismState("API", PeerStateKnown, "discovered via DNS (API usable)")
		}
		if st := peer.GetState(); st < PeerStateKnown || st == PeerStateError {
			peer.SetState(PeerStateKnown, "discovered via DNS (API usable)")
		}
	} else if result.APIUri != "" {
		// URI found but no resolved address, or no usable TLSA: keep the
		// mechanism NEEDED so the retrier revisits it; do not advertise an
		// unusable URL; never regress an already-established peer.
		peer.SetMechanismContactInfo("API", "partial")
		if tlsaGone && !apiRefused {
			// The TLSA it was used with is gone: the mechanism needs
			// discovery again, which finds a TLSA when one is published.
			peer.SetMechanismState("API", PeerStateNeeded, "TLSA withdrawn")
		}
		raw, _ := peer.MechanismRawState("API")
		if len(result.APIAddresses) > 0 && tm.APITransport != nil && tm.APITransport.TLSA != nil {
			// The retrier comes back every interval: at Warn hourly.
			tm.APITransport.TLSA.NoteNoTLSA(peer, result.TLSA.Owner)
		} else {
			why := "no resolved address"
			if len(result.APIAddresses) > 0 {
				why = "no usable TLSA at " + result.TLSA.Owner
			}
			lgTransport().Warn("API endpoint URI found but not usable; not marking usable",
				"identity", result.Identity, "uri", result.APIUri, "why", why, "state", raw.String())
		}
	}

	if dnsUsable {
		peer.SetMechanismContactInfo("DNS", "complete")
		if raw, ok := peer.MechanismRawState("DNS"); !ok || raw <= PeerStateNeeded {
			peer.SetMechanismState("DNS", PeerStateKnown, "discovered via DNS (DNS usable)")
		}
		if st := peer.GetState(); st < PeerStateKnown || st == PeerStateError {
			peer.SetState(PeerStateKnown, "discovered via DNS (DNS usable)")
		}
		// JWK only when discovered (a partial re-discovery must not wipe a
		// previously discovered key); KEY record replace-style (legacy).
		if result.JWKData != "" {
			peer.SetMechanismJWK("DNS", result.JWKData, result.KeyAlgorithm)
		}
		// KEY record likewise only when discovered: a re-discovery that
		// found a JWK (or nothing) must not wipe a pinned legacy key.
		if result.LegacyKeyRR != nil {
			peer.SetMechanismKeyRR("DNS", result.LegacyKeyRR)
		}
	} else if result.DNSUri != "" {
		peer.SetMechanismContactInfo("DNS", "partial")
		raw, _ := peer.MechanismRawState("DNS")
		lgTransport().Warn("DNS endpoint URI found but no resolved address; not marking usable",
			"identity", result.Identity, "uri", result.DNSUri, "state", raw.String())
	}

	// The process is complete — hand the peer to the application so it can
	// materialize its own view (capability flags, registry entry). This is
	// the OnPeerDiscovered seam going live transport-side, per its docs.
	if tm.OnPeerDiscovered != nil {
		tm.OnPeerDiscovered(peer)
	}

	return nil
}

// DiscoverAndRegisterPeer performs discovery and registration in one step.
// The IMR is late-bound via tm.GetImr (the resolver starts asynchronously).
func (tm *TransportManager) DiscoverAndRegisterPeer(ctx context.Context, identity string) error {
	lgTransport().Info("starting discovery for peer", "identity", identity)

	if tm.GetImr == nil {
		return fmt.Errorf("no IMR accessor configured for discovery")
	}
	imr := tm.GetImr()
	if imr == nil || imr.Imr == nil || imr.Cache == nil {
		return fmt.Errorf("IMR engine not available for discovery (not yet started)")
	}

	// Fix E: only discover transports the local side supports.
	result := imr.discoverAgent(ctx, identity, tm.isTransportSupported("api"), tm.isTransportSupported("dns"))
	if result.Error != nil {
		// Nothing to register, but the peer's status says why, and a
		// mechanism refused for want of validation is not used any more.
		if peer, ok := tm.PeerRegistry.Get(identity); ok {
			peer.setDiscoveryStatus(result.status(time.Now()))
			tm.demoteRefused(peer, result)
		}
		return fmt.Errorf("discovery failed for %s: %w", identity, result.Error)
	}
	if result.Partial {
		lgTransport().Warn("partial discovery (some records missing)", "identity", identity)
	}

	if err := tm.RegisterDiscoveredPeer(result); err != nil {
		return fmt.Errorf("failed to register discovered peer %s: %w", identity, err)
	}

	lgTransport().Info("successfully discovered and registered peer", "identity", identity)
	return nil
}

// demoteRefused makes NEEDED each mechanism of peer whose data the result
// refused for want of DNSSEC validation (DiscoveryResult.refused): it needs
// discovery again, and stays NEEDED until its chain validates.
func (tm *TransportManager) demoteRefused(peer *Peer, result *DiscoveryResult) {
	for _, mech := range []string{"API", "DNS"} {
		l, refused := result.refused(mech)
		if !refused {
			continue
		}
		if was, demoted := peer.demoteMechanism(mech, l.String()); demoted {
			lgTransport().Warn("the peer's DNS data is not DNSSEC-validated any more; the mechanism needs discovery again",
				"peer", peer.ID, "mechanism", mech, "was", was.String(), "lookup", l.String())
		}
	}
}
