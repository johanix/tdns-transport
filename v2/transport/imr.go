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
	"strings"

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

// requireValidated refuses an answer the resolver did not DNSSEC-validate
// when the IMR is set to require validation (imrengine
// require-dnssec-validation). Every discovery lookup is a security-sensitive
// one: what a peer's identity zone says about its keys and endpoints is what
// the transport then trusts, so an Insecure or Bogus answer is not a weaker
// answer, it is none. Without the setting the lookups take what the resolver
// gives, as they always did.
func (imr *Imr) requireValidated(resp *tdns.ImrResponse, rrtype, qname string) error {
	if imr == nil || imr.Imr == nil || !imr.RequireDnssecValidation || resp == nil || resp.Validated {
		return nil
	}
	return fmt.Errorf("%s at %s is not DNSSEC-validated and require-dnssec-validation is set", rrtype, qname)
}

// lookupAgentJWK looks up the JWK record for an agent identity.
// Returns: (jwk-data, public-key, algorithm, error)
//
// The JWK record contains a base64url-encoded JSON Web Key per RFC 7517.
// This function decodes the JWK to a crypto.PublicKey for immediate use.
//
// JWK records are published at dns.<identity> following DNS transport
// naming conventions.
func (imr *Imr) lookupAgentJWK(ctx context.Context, identity string) (string, crypto.PublicKey, string, error) {
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
	if err := imr.requireValidated(resp, "JWK", jwkQname); err != nil {
		return "", nil, "", err
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

// lookupAgentKEY looks up the KEY record for an agent identity
// (legacy fallback when JWK is unavailable).
func (imr *Imr) lookupAgentKEY(ctx context.Context, identity string) (*dns.KEY, error) {
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
	if err := imr.requireValidated(resp, "KEY", identity); err != nil {
		return nil, err
	}

	for _, rr := range resp.RRset.RRs {
		if keyRR, ok := rr.(*dns.KEY); ok {
			lgTransport().Debug("found KEY record", "identity", identity, "algorithm", keyRR.Algorithm)
			return keyRR, nil
		}
	}

	return nil, fmt.Errorf("no valid KEY record found for %s", identity)
}

// lookupAgentAPIEndpoint looks up the API endpoint URI for an agent.
// Queries: _https._tcp.<identity> URI
// Returns: (uri, host, port, error)
func (imr *Imr) lookupAgentAPIEndpoint(ctx context.Context, identity string) (string, string, uint16, error) {
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
	if err := imr.requireValidated(resp, "URI", apiQname); err != nil {
		return "", "", 0, err
	}

	for _, rr := range resp.RRset.RRs {
		if uriRR, ok := rr.(*dns.URI); ok {
			parsed, err := url.Parse(uriRR.Target)
			if err != nil {
				lgTransport().Warn("invalid API URI", "uri", uriRR.Target, "err", err)
				continue
			}
			if !strings.EqualFold(parsed.Scheme, "https") {
				lgTransport().Warn("API URI is not https, skipping", "uri", uriRR.Target)
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

// lookupAgentDNSEndpoint looks up the DNS endpoint URI for an agent (optional).
// Queries: _dns._tcp.<identity> URI
// Returns: (uri, host, port, error)
func (imr *Imr) lookupAgentDNSEndpoint(ctx context.Context, identity string) (string, string, uint16, error) {
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
	if err := imr.requireValidated(resp, "URI", dnsQname); err != nil {
		return "", "", 0, err
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

// tlsaAnswer is what the resolver said about a TLSA name: the usable
// records there, or that the name or the type does not exist, and whether
// the answer was DNSSEC-validated.
type tlsaAnswer struct {
	Records   []*dns.TLSA // usable records only (usableTLSA)
	Denied    bool        // NXDOMAIN or NODATA: there is no TLSA at the name
	Validated bool
}

// requireValidation reports whether the resolver is set to require DNSSEC
// validation (require-dnssec-validation).
func (imr *Imr) requireValidation() bool {
	return imr != nil && imr.Imr != nil && imr.RequireDnssecValidation
}

// usableTLSA reports whether a TLSA record can vouch for an agent's
// self-signed certificate: DANE-EE (usage 3), over the full certificate or
// its SubjectPublicKeyInfo (selector 0 or 1), as a SHA-256 or SHA-512 digest
// (matching type 1 or 2). That is what VerifyCertAgainstTlsaRR checks; an
// agent publishes 3 1 1.
func usableTLSA(rr *dns.TLSA) bool {
	return rr != nil && rr.Usage == 3 && rr.Selector <= 1 && (rr.MatchingType == 1 || rr.MatchingType == 2)
}

// lookupTLSA asks the resolver for the TLSA RRset at owner, through its
// cache, which answers within the TTL; fresh asks past the cached answer.
// An error is a failed lookup (a timeout, a SERVFAIL): it says nothing about
// the set. A denial is an answer.
func (imr *Imr) lookupTLSA(ctx context.Context, owner string, fresh bool) (tlsaAnswer, error) {
	owner = dns.Fqdn(owner)
	var resp *tdns.ImrResponse
	var err error
	if fresh {
		resp, err = imr.ImrQueryFresh(ctx, owner, dns.TypeTLSA, dns.ClassINET)
	} else {
		resp, err = imr.ImrQuery(ctx, owner, dns.TypeTLSA, dns.ClassINET, nil)
	}
	if err != nil {
		return tlsaAnswer{}, fmt.Errorf("TLSA query for %s failed: %w", owner, err)
	}
	ans, err := tlsaAnswerFrom(owner, resp)
	if err != nil {
		return tlsaAnswer{}, err
	}
	lgTransport().Debug("TLSA lookup", "owner", owner, "fresh", fresh, "records", len(ans.Records), "validated", ans.Validated)
	return ans, nil
}

// tlsaAnswerFrom reads the resolver's response for the TLSA name owner. A
// failure is checked first, so it is never read as a withdrawal. A denial
// (NXDOMAIN or NODATA) is an answer; Validated is then the verdict on its
// proof.
func tlsaAnswerFrom(owner string, resp *tdns.ImrResponse) (tlsaAnswer, error) {
	if resp == nil {
		return tlsaAnswer{}, fmt.Errorf("TLSA query for %s: no response", owner)
	}
	if resp.Error {
		return tlsaAnswer{}, fmt.Errorf("TLSA query for %s failed: %s", owner, resp.ErrorMsg)
	}
	// Denial is NXDOMAIN or NODATA, and zero for an answer.
	if resp.Denial != 0 {
		return tlsaAnswer{Denied: true, Validated: resp.Validated}, nil
	}
	ans := tlsaAnswer{Validated: resp.Validated}
	if resp.RRset != nil {
		for _, rr := range resp.RRset.RRs {
			if t, ok := rr.(*dns.TLSA); ok && usableTLSA(t) {
				ans.Records = append(ans.Records, t)
			}
		}
	}
	return ans, nil
}

// lookupServiceAddresses looks up SVCB record for a service name.
// Queries SVCB at the service name (e.g., dns.<identity> or
// api.<identity>). Returns addresses extracted from ipv4hint and
// ipv6hint parameters.
func (imr *Imr) lookupServiceAddresses(ctx context.Context, serviceName string) ([]string, error) {
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
	if err := imr.requireValidated(resp, "SVCB", serviceName); err != nil {
		return nil, err
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
