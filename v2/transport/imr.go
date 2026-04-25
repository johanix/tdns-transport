/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Transport-side IMR wrapper and DNS lookup helpers.
 *
 * Imr embeds *tdns.Imr so transport code can call core IMR methods
 * (e.g. ImrQuery) via promotion AND attach transport-specific
 * receiver methods (the Lookup* helpers below) without modifying
 * the tdns package.
 *
 * IMPORTANT: there must be exactly one *tdns.Imr per process. The
 * tdns.InitImrEngine guard (Bite 0 of the transport refactor
 * early-bites plan) makes this hold by construction. Constructing
 * a transport.Imr with a different *tdns.Imr than the one held by
 * tdnsmp.Imr would defeat the priming cache and validation state.
 *
 * The Lookup* helpers below are parallel copies of the same helpers
 * on *tdnsmp.Imr — both wrappers wrap the same underlying singleton.
 * The duplication is intentional and will be resolved when MP
 * migrates its callers to use *transport.Imr or when the helpers
 * move to a shared location.
 *
 * See tdns-mp/docs/2026-04-25-transport-refactor-early-bites.md
 * (Bite 6) and the main plan's item J resolution for the embedding
 * decision.
 */

package transport

import (
	"context"
	"crypto"
	"fmt"
	"net/url"
	"strconv"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Imr embeds *tdns.Imr to allow transport code to attach its own
// receiver methods (the Lookup* helpers below) while preserving
// access to all core Imr methods via promotion.
type Imr struct {
	*tdns.Imr
}

// LookupAgentJWK looks up the JWK record for an agent identity.
// Returns: (jwk-data, public-key, algorithm, error)
//
// The JWK record contains a base64url-encoded JSON Web Key per RFC 7517.
// This function decodes the JWK to a crypto.PublicKey for immediate use.
//
// JWK records are published at dns.<identity> following DNS transport
// naming conventions.
func (imr *Imr) LookupAgentJWK(ctx context.Context, identity string) (string, crypto.PublicKey, string, error) {
	identity = dns.Fqdn(identity)

	jwkQname := "dns." + identity
	lgTransport().Debug("looking up JWK", "qname", jwkQname)

	resp, err := imr.ImrQuery(ctx, jwkQname, core.TypeJWK, dns.ClassINET, nil)
	if err != nil {
		return "", nil, "", fmt.Errorf("JWK query failed for %s: %w", jwkQname, err)
	}

	if resp.Error {
		return "", nil, "", fmt.Errorf("JWK query error for %s: %s", jwkQname, resp.ErrorMsg)
	}

	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return "", nil, "", fmt.Errorf("no JWK record found at %s", jwkQname)
	}

	for _, rr := range resp.RRset.RRs {
		if privateRR, ok := rr.(*dns.PrivateRR); ok {
			if jwk, ok := privateRR.Data.(*core.JWK); ok {
				if err := core.ValidateJWK(jwk.JWKData); err != nil {
					lgTransport().Warn("invalid JWK data", "qname", jwkQname, "err", err)
					continue
				}

				publicKey, algorithm, err := core.DecodeJWKToPublicKey(jwk.JWKData)
				if err != nil {
					lgTransport().Warn("failed to decode JWK", "qname", jwkQname, "err", err)
					continue
				}

				lgTransport().Debug("found JWK record", "qname", jwkQname, "algorithm", algorithm)
				return jwk.JWKData, publicKey, algorithm, nil
			}
		}
	}

	return "", nil, "", fmt.Errorf("no valid JWK record found at %s", jwkQname)
}

// LookupAgentKEY looks up the KEY record for an agent identity
// (legacy fallback when JWK is unavailable).
func (imr *Imr) LookupAgentKEY(ctx context.Context, identity string) (*dns.KEY, error) {
	identity = dns.Fqdn(identity)

	lgTransport().Debug("looking up KEY (legacy fallback)", "identity", identity)

	resp, err := imr.ImrQuery(ctx, identity, dns.TypeKEY, dns.ClassINET, nil)
	if err != nil {
		return nil, fmt.Errorf("KEY query failed for %s: %w", identity, err)
	}

	if resp.Error {
		return nil, fmt.Errorf("KEY query error for %s: %s", identity, resp.ErrorMsg)
	}

	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return nil, fmt.Errorf("no KEY record found for %s", identity)
	}

	for _, rr := range resp.RRset.RRs {
		if keyRR, ok := rr.(*dns.KEY); ok {
			lgTransport().Debug("found KEY record", "identity", identity, "algorithm", keyRR.Algorithm)
			return keyRR, nil
		}
	}

	return nil, fmt.Errorf("no valid KEY record found for %s", identity)
}

// LookupAgentAPIEndpoint looks up the API endpoint URI for an agent.
// Queries: _https._tcp.<identity> URI
// Returns: (uri, host, port, error)
func (imr *Imr) LookupAgentAPIEndpoint(ctx context.Context, identity string) (string, string, uint16, error) {
	identity = dns.Fqdn(identity)

	apiQname := "_https._tcp." + identity
	lgTransport().Debug("looking up API URI", "qname", apiQname)

	resp, err := imr.ImrQuery(ctx, apiQname, dns.TypeURI, dns.ClassINET, nil)
	if err != nil {
		return "", "", 0, fmt.Errorf("API URI query failed for %s: %w", apiQname, err)
	}

	if resp.Error {
		return "", "", 0, fmt.Errorf("API URI query error for %s: %s", apiQname, resp.ErrorMsg)
	}

	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return "", "", 0, fmt.Errorf("no API URI record found at %s", apiQname)
	}

	for _, rr := range resp.RRset.RRs {
		if uriRR, ok := rr.(*dns.URI); ok {
			parsed, err := url.Parse(uriRR.Target)
			if err != nil {
				lgTransport().Warn("invalid API URI", "uri", uriRR.Target, "err", err)
				continue
			}

			host := parsed.Hostname()
			port := uint16(443)
			if parsed.Port() != "" {
				p, err := strconv.Atoi(parsed.Port())
				if err != nil || p < 1 || p > 65535 {
					lgTransport().Warn("invalid port in API URI, skipping", "uri", uriRR.Target, "port", parsed.Port())
					continue
				}
				port = uint16(p)
			}

			lgTransport().Debug("found API URI", "uri", uriRR.Target, "host", host, "port", port)
			return uriRR.Target, host, port, nil
		}
	}

	return "", "", 0, fmt.Errorf("no valid API URI record found at %s", apiQname)
}

// LookupAgentDNSEndpoint looks up the DNS endpoint URI for an agent (optional).
// Queries: _dns._tcp.<identity> URI
// Returns: (uri, host, port, error)
func (imr *Imr) LookupAgentDNSEndpoint(ctx context.Context, identity string) (string, string, uint16, error) {
	identity = dns.Fqdn(identity)

	dnsQname := "_dns._tcp." + identity
	lgTransport().Debug("looking up DNS URI", "qname", dnsQname)

	resp, err := imr.ImrQuery(ctx, dnsQname, dns.TypeURI, dns.ClassINET, nil)
	if err != nil {
		return "", "", 0, fmt.Errorf("DNS URI query failed for %s: %w", dnsQname, err)
	}

	if resp.Error {
		return "", "", 0, fmt.Errorf("DNS URI query error for %s: %s", dnsQname, resp.ErrorMsg)
	}

	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return "", "", 0, fmt.Errorf("no DNS URI record found at %s", dnsQname)
	}

	for _, rr := range resp.RRset.RRs {
		if uriRR, ok := rr.(*dns.URI); ok {
			parsed, err := url.Parse(uriRR.Target)
			if err != nil {
				lgTransport().Warn("invalid DNS URI", "uri", uriRR.Target, "err", err)
				continue
			}

			host := parsed.Hostname()
			port := uint16(53)
			if parsed.Port() != "" {
				p, err := strconv.Atoi(parsed.Port())
				if err != nil || p < 1 || p > 65535 {
					lgTransport().Warn("invalid port in DNS URI, skipping", "uri", uriRR.Target, "port", parsed.Port())
					continue
				}
				port = uint16(p)
			}

			lgTransport().Debug("found DNS URI", "uri", uriRR.Target, "host", host, "port", port)
			return uriRR.Target, host, port, nil
		}
	}

	return "", "", 0, fmt.Errorf("no valid DNS URI record found at %s", dnsQname)
}

// LookupAgentTLSA looks up the TLSA record for an agent's HTTPS service.
// Queries: _<port>._tcp.<identity> TLSA
func (imr *Imr) LookupAgentTLSA(ctx context.Context, identity string, port uint16) (*dns.TLSA, error) {
	identity = dns.Fqdn(identity)

	tlsaQname := fmt.Sprintf("_%d._tcp.%s", port, identity)
	lgTransport().Debug("looking up TLSA", "qname", tlsaQname)

	resp, err := imr.ImrQuery(ctx, tlsaQname, dns.TypeTLSA, dns.ClassINET, nil)
	if err != nil {
		return nil, fmt.Errorf("TLSA query failed for %s: %w", tlsaQname, err)
	}

	if resp.Error {
		return nil, fmt.Errorf("TLSA query error for %s: %s", tlsaQname, resp.ErrorMsg)
	}

	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return nil, fmt.Errorf("no TLSA record found at %s", tlsaQname)
	}

	for _, rr := range resp.RRset.RRs {
		if tlsaRR, ok := rr.(*dns.TLSA); ok {
			lgTransport().Debug("found TLSA record", "qname", tlsaQname,
				"usage", tlsaRR.Usage, "selector", tlsaRR.Selector,
				"matchingType", tlsaRR.MatchingType, "validated", resp.Validated)
			if imr.RequireDnssecValidation && !resp.Validated {
				return nil, fmt.Errorf("TLSA record at %s has unvalidated DNSSEC state (require_dnssec_validation=true)", tlsaQname)
			}
			return tlsaRR, nil
		}
	}

	return nil, fmt.Errorf("no valid TLSA record found at %s", tlsaQname)
}

// LookupServiceAddresses looks up SVCB record for a service name.
// Queries SVCB at the service name (e.g., dns.<identity> or
// api.<identity>). Returns addresses extracted from ipv4hint and
// ipv6hint parameters.
func (imr *Imr) LookupServiceAddresses(ctx context.Context, serviceName string) ([]string, error) {
	serviceName = dns.Fqdn(serviceName)

	var addresses []string

	lgTransport().Debug("looking up SVCB", "service", serviceName)

	resp, err := imr.ImrQuery(ctx, serviceName, dns.TypeSVCB, dns.ClassINET, nil)
	if err != nil {
		return nil, fmt.Errorf("SVCB query failed for %s: %w", serviceName, err)
	}

	if resp.Error {
		return nil, fmt.Errorf("SVCB query error for %s: %s", serviceName, resp.ErrorMsg)
	}

	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return nil, fmt.Errorf("no SVCB record found at %s", serviceName)
	}

	for _, rr := range resp.RRset.RRs {
		if svcbRR, ok := rr.(*dns.SVCB); ok {
			for _, kv := range svcbRR.Value {
				if kv.Key() == dns.SVCB_IPV4HINT {
					if ipv4hint, ok := kv.(*dns.SVCBIPv4Hint); ok {
						for _, ip := range ipv4hint.Hint {
							addresses = append(addresses, ip.String())
						}
					}
				}
				if kv.Key() == dns.SVCB_IPV6HINT {
					if ipv6hint, ok := kv.(*dns.SVCBIPv6Hint); ok {
						for _, ip := range ipv6hint.Hint {
							addresses = append(addresses, ip.String())
						}
					}
				}
			}
		}
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no IP hints found in SVCB record at %s", serviceName)
	}

	lgTransport().Debug("found addresses from SVCB", "count", len(addresses), "service", serviceName, "addresses", addresses)
	return addresses, nil
}
