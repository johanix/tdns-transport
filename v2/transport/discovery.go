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
	"fmt"
	"net/url"
	"strconv"

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
	TLSA         *dns.TLSA        // TLSA record for TLS verification
	APIAddresses []string         // IP addresses for API service from SVCB
	DNSAddresses []string         // IP addresses for DNS service from SVCB
	Port         uint16           // Port from URI record
	Error        error            // Any error during discovery
	Partial      bool             // True if some records were found but discovery incomplete
}

// DiscoverAgentAPI performs DNS-based discovery of a peer's API transport.
//  1. URI record at _https._tcp.<identity> → get API endpoint URI and port
//  2. SVCB record at api.<identity> → get ipv4hint/ipv6hint addresses
//  3. TLSA record at _<port>._tcp.api.<identity> → get TLS certificate for verification
func (imr *Imr) DiscoverAgentAPI(ctx context.Context, identity string, result *DiscoveryResult) {
	if imr == nil || imr.Imr == nil {
		result.Error = fmt.Errorf("IMR engine not initialized")
		result.Partial = true
		return
	}
	identity = dns.Fqdn(identity)

	apiUri, apiHost, apiPort, err := imr.LookupAgentAPIEndpoint(ctx, identity)
	if err == nil {
		result.APIUri = apiUri
		result.Port = apiPort

		// Look up SVCB at api.<identity> to get IP addresses
		apiServiceName := "api." + identity
		addresses, err := imr.LookupServiceAddresses(ctx, apiServiceName)
		if err == nil {
			result.APIAddresses = addresses
		} else {
			lgTransport().Debug("no SVCB record for API service", "service", apiServiceName, "err", err)
			result.Partial = true
		}

		// Look up TLSA at _<port>._tcp.api.<identity> for TLS verification
		tlsaRR, err := imr.LookupAgentTLSA(ctx, apiServiceName, apiPort)
		if err == nil {
			result.TLSA = tlsaRR
		} else {
			lgTransport().Debug("no TLSA record for API service", "err", err)
			result.Partial = true
		}

		lgTransport().Info("found API endpoint", "uri", apiUri, "host", apiHost)
	} else {
		lgTransport().Debug("no API URI record found", "err", err)
		result.Partial = true
	}
}

// DiscoverAgentDNS performs DNS-based discovery of a peer's DNS transport.
//  1. URI record at _dns._tcp.<identity> → get DNS endpoint URI and port
//  2. SVCB record at dns.<identity> → get ipv4hint/ipv6hint addresses
//  3. JWK record at dns.<identity> → get JOSE/HPKE public key (preferred)
//  4. KEY record at dns.<identity> → get SIG(0) public key (legacy fallback if no JWK)
func (imr *Imr) DiscoverAgentDNS(ctx context.Context, identity string, result *DiscoveryResult) {
	if imr == nil || imr.Imr == nil {
		result.Error = fmt.Errorf("IMR engine not initialized")
		result.Partial = true
		return
	}
	identity = dns.Fqdn(identity)

	dnsUri, dnsHost, dnsPort, err := imr.LookupAgentDNSEndpoint(ctx, identity)
	if err == nil {
		result.DNSUri = dnsUri

		// Look up SVCB at dns.<identity> to get IP addresses
		dnsServiceName := "dns." + identity
		addresses, err := imr.LookupServiceAddresses(ctx, dnsServiceName)
		if err == nil {
			result.DNSAddresses = addresses
		} else {
			lgTransport().Warn("SVCB lookup failed for DNS service", "service", dnsServiceName, "err", err)
			result.Partial = true
		}

		// Look up JWK at dns.<identity> for JOSE/HPKE public key
		jwkData, publicKey, algorithm, err := imr.LookupAgentJWK(ctx, identity)
		if err == nil {
			result.JWKData = jwkData
			result.PublicKey = publicKey
			result.KeyAlgorithm = algorithm
			lgTransport().Info("found JWK record", "identity", identity, "algorithm", algorithm)
		} else {
			lgTransport().Warn("JWK lookup failed", "identity", identity, "err", err)

			// Fallback to KEY record for legacy support
			keyRR, err := imr.LookupAgentKEY(ctx, identity)
			if err == nil {
				result.LegacyKeyRR = keyRR
				lgTransport().Info("using legacy KEY record", "identity", identity, "algorithm", keyRR.Algorithm)
			} else {
				lgTransport().Warn("KEY lookup failed (legacy fallback)", "identity", identity, "err", err)
				result.Partial = true
			}
		}

		lgTransport().Info("found DNS endpoint", "uri", dnsUri, "host", dnsHost, "port", dnsPort)
	} else {
		lgTransport().Debug("no DNS URI record found (optional)", "err", err)
	}
}

// DiscoverAgent performs DNS-based discovery of a peer's contact information,
// but only for transports the LOCAL side supports (apiSupported/dnsSupported)
// — Fix E: probing an unsupported transport emits failing lookups and sets a
// spurious Partial. Each supported leg runs via DiscoverAgentAPI/DNS.
func (imr *Imr) DiscoverAgent(ctx context.Context, identity string, apiSupported, dnsSupported bool) *DiscoveryResult {
	result := &DiscoveryResult{
		Identity: identity,
	}

	if imr == nil || imr.Imr == nil {
		result.Error = fmt.Errorf("IMR engine not initialized")
		return result
	}

	if apiSupported {
		imr.DiscoverAgentAPI(ctx, identity, result)
	}
	if dnsSupported {
		imr.DiscoverAgentDNS(ctx, identity, result)
	}

	// Check if we have enough information to contact the peer
	if result.APIUri == "" && result.DNSUri == "" {
		result.Error = fmt.Errorf("no contact endpoints found (no API or DNS URI records)")
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
func (tm *TransportManager) RegisterDiscoveredPeer(result *DiscoveryResult) error {
	if result.Error != nil {
		return fmt.Errorf("cannot register peer with discovery error: %w", result.Error)
	}

	// The top-level peer State is promoted to KNOWN further down, but ONLY
	// for a mechanism that actually became usable (URI + resolved address).
	// Setting it unconditionally made EffectiveState() report KNOWN for an
	// unreachable peer — the KNOWN/NEEDED contradiction (Fix C).
	peer := tm.PeerRegistry.GetOrCreate(result.Identity)

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
	dnsUsable := result.DNSUri != "" && len(result.DNSAddresses) > 0
	if dnsUsable && tm.DNSTransport != nil && tm.DNSTransport.SecureWrapper != nil {
		hasVerificationKey := false
		if pc := tm.DNSTransport.SecureWrapper.GetCrypto(); pc != nil {
			_, hasVerificationKey = pc.GetPeerVerificationKey(result.Identity)
		}
		if !hasVerificationKey {
			return fmt.Errorf("discovery for %s found endpoint but no verification key (JWK/KEY lookup failed)", result.Identity)
		}
	}

	if result.APIUri != "" {
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
			peer.APIEndpoint = result.APIUri
			peer.PreferredTransport = "API"

			lgTransport().Info("registered peer with API endpoint", "identity", result.Identity, "endpoint", result.APIUri, "address", host, "port", port)
		}
	}

	// Register DNS transport address (NOT else-if: both can exist)
	if result.DNSUri != "" {
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
			// mechanisms resolve it holds the DNS address (API sends use
			// APIEndpoint). The per-mechanism slot keeps each address.
			// API stays the preferred transport when it also resolved,
			// matching Peer.PreferredMechanism and SelectTransport's default.
			peer.SetDiscoveryAddress(addr)
			peer.SetMechanismAddress("DNS", addr)
			peer.DNSEndpoint = result.DNSUri // display/diagnostics (S2)
			if peer.PreferredTransport == "" {
				peer.PreferredTransport = "DNS"
			}

			lgTransport().Info("registered peer with DNS endpoint", "identity", result.Identity, "endpoint", result.DNSUri, "address", host, "port", port)
		}
	}

	// Store TLSA for TLS verification (legacy top-level bytes; the typed
	// record lands in the per-mechanism crypto slot below)
	if result.TLSA != nil {
		peer.TLSARecord = []byte(result.TLSA.Certificate)
	}

	// Per-mechanism outcome: ContactInfo + guarded NEEDED→KNOWN promotion +
	// crypto slots. A mechanism is USABLE only with BOTH a URI and a
	// resolved address (Fix C); URI-without-address is recorded as
	// ContactInfo "partial" (the application derives its capability flags
	// from ContactInfo: "complete"/"partial" ⇒ offered, absent ⇒ not).
	apiUsable := result.APIUri != "" && len(result.APIAddresses) > 0
	if apiUsable {
		peer.SetMechanismContactInfo("API", "complete")
		// Guarded promotion: do not regress an already-established mechanism.
		// This is the per-mechanism discovery-phase write the send gates read.
		if raw, ok := peer.MechanismRawState("API"); !ok || raw <= PeerStateNeeded {
			peer.SetMechanismState("API", PeerStateKnown, "discovered via DNS (API usable)")
		}
		if peer.GetState() < PeerStateKnown {
			peer.SetState(PeerStateKnown, "discovered via DNS (API usable)")
		}
		// TLSA only when discovered: a partial re-discovery must not wipe a
		// previously pinned certificate (2026-08-25 review, finding 4;
		// mirrors the JWK rule below).
		if result.TLSA != nil {
			peer.SetMechanismTLSA("API", result.TLSA)
		}
	} else if result.APIUri != "" {
		// URI found but no resolved address: keep the mechanism NEEDED so
		// the retrier revisits it; do not advertise an unusable URL; never
		// regress an already-established peer.
		peer.SetMechanismContactInfo("API", "partial")
		raw, _ := peer.MechanismRawState("API")
		lgTransport().Warn("API endpoint URI found but no resolved address; not marking usable",
			"identity", result.Identity, "uri", result.APIUri, "state", raw.String())
	}

	if dnsUsable {
		peer.SetMechanismContactInfo("DNS", "complete")
		if raw, ok := peer.MechanismRawState("DNS"); !ok || raw <= PeerStateNeeded {
			peer.SetMechanismState("DNS", PeerStateKnown, "discovered via DNS (DNS usable)")
		}
		if peer.GetState() < PeerStateKnown {
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
	result := imr.DiscoverAgent(ctx, identity, tm.IsTransportSupported("api"), tm.IsTransportSupported("dns"))
	if result.Error != nil {
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
