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
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/cache"
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

// discoveryQuery asks the resolver for <qname, qtype> on discovery's behalf,
// typ naming the type for the operator. It returns the records when there
// are some to use, and in every case what the lookup saw: the verdict on the
// answer or the denial, when it expires from the cache, and why it gave
// nothing to use. A lookup that gives nothing to use also returns an error
// that carries its lookup (lookupOf).
//
// Validation is judged before the records are looked for. With validation
// required, a denial that was not validated is no proof that the records do
// not exist, and is refused as an answer would be: a forged denial of the
// API's URI would otherwise pass as "no API".
func (imr *Imr) discoveryQuery(ctx context.Context, qname string, qtype uint16, typ string) (*core.RRset, DiscoveryLookup, error) {
	l := DiscoveryLookup{Type: typ, Owner: qname}
	fail := func(f DiscoveryFailure, detail string) (*core.RRset, DiscoveryLookup, error) {
		l.Failure, l.Detail = f, detail
		return nil, l, &lookupError{lookup: l}
	}
	resp, err := imr.ImrQuery(ctx, qname, qtype, dns.ClassINET, nil)
	if err != nil {
		msg := ""
		if resp != nil {
			msg = resp.ErrorMsg
		}
		return fail(failureOf(err, msg), fmt.Sprintf("query failed: %v", err))
	}
	if resp == nil {
		return fail(FailureQuery, "query failed: no response")
	}
	if resp.Error {
		return fail(failureOf(nil, resp.ErrorMsg), "query failed: "+resp.ErrorMsg)
	}
	l.Chain = chainOf(resp)
	l.Expires = resp.Expiration
	found := resp.RRset != nil && len(resp.RRset.RRs) > 0
	what := "answer"
	if !found {
		what = "denial"
	}
	if imr.requireValidated(resp, typ, qname) != nil {
		// Refused for want of a validated chain: not secure, whatever the
		// resolver could tell about it.
		if l.Chain < ChainInsecure {
			l.Chain = ChainInsecure
		}
		return fail(FailureNotValidated, verdictDetail(what, l.Chain, true))
	}
	if !found {
		detail := "no " + typ + " record"
		if resp.Denial == cache.ContextNXDOMAIN {
			detail = "no such name"
		}
		return fail(FailureNoRecords, detail)
	}
	if l.Chain != ChainSecure {
		l.Detail = verdictDetail(what, l.Chain, false)
	}
	return resp.RRset, l, nil
}

// unusable makes l the lookup of records none of which can be used.
func unusable(l DiscoveryLookup, detail string) (DiscoveryLookup, error) {
	l.Failure, l.Detail = FailureNoRecords, detail
	return l, &lookupError{lookup: l}
}

// lookupAgentJWK looks up the JWK record for an agent identity.
// Returns: (jwk-data, public-key, algorithm, the lookup, error)
//
// The JWK record contains a base64url-encoded JSON Web Key per RFC 7517.
// This function decodes the JWK to a crypto.PublicKey for immediate use.
//
// JWK records are published at dns.<identity> following DNS transport
// naming conventions.
func (imr *Imr) lookupAgentJWK(ctx context.Context, identity string) (string, crypto.PublicKey, string, DiscoveryLookup, error) {
	identity = dns.Fqdn(identity)

	jwkQname := "dns." + identity
	lgTransport().Debug("looking up JWK", "qname", jwkQname)

	rrset, l, err := imr.discoveryQuery(ctx, jwkQname, core.TypeJWK, "JWK")
	if err != nil {
		return "", nil, "", l, err
	}

	for _, rr := range rrset.RRs {
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
				return jwk.JWKData, publicKey, algorithm, l, nil
			}
		}
	}

	l, err = unusable(l, "no valid JWK record")
	return "", nil, "", l, err
}

// lookupAgentKEY looks up the KEY record for an agent identity
// (legacy fallback when JWK is unavailable).
func (imr *Imr) lookupAgentKEY(ctx context.Context, identity string) (*dns.KEY, DiscoveryLookup, error) {
	identity = dns.Fqdn(identity)

	lgTransport().Debug("looking up KEY (legacy fallback)", "identity", identity)

	rrset, l, err := imr.discoveryQuery(ctx, identity, dns.TypeKEY, "KEY")
	if err != nil {
		return nil, l, err
	}

	for _, rr := range rrset.RRs {
		if keyRR, ok := rr.(*dns.KEY); ok {
			lgTransport().Debug("found KEY record", "identity", identity, "algorithm", keyRR.Algorithm)
			return keyRR, l, nil
		}
	}

	l, err = unusable(l, "no valid KEY record")
	return nil, l, err
}

// lookupAgentAPIEndpoint looks up the API endpoint URI for an agent.
// Queries: _https._tcp.<identity> URI
// Returns: (uri, host, port, the lookup, error)
func (imr *Imr) lookupAgentAPIEndpoint(ctx context.Context, identity string) (string, string, uint16, DiscoveryLookup, error) {
	identity = dns.Fqdn(identity)

	apiQname := "_https._tcp." + identity
	lgTransport().Debug("looking up API URI", "qname", apiQname)

	rrset, l, err := imr.discoveryQuery(ctx, apiQname, dns.TypeURI, "URI")
	if err != nil {
		return "", "", 0, l, err
	}

	for _, rr := range rrset.RRs {
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
			return uriRR.Target, host, port, l, nil
		}
	}

	l, err = unusable(l, "no valid API URI record")
	return "", "", 0, l, err
}

// lookupAgentDNSEndpoint looks up the DNS endpoint URI for an agent (optional).
// Queries: _dns._tcp.<identity> URI
// Returns: (uri, host, port, the lookup, error)
func (imr *Imr) lookupAgentDNSEndpoint(ctx context.Context, identity string) (string, string, uint16, DiscoveryLookup, error) {
	identity = dns.Fqdn(identity)

	dnsQname := "_dns._tcp." + identity
	lgTransport().Debug("looking up DNS URI", "qname", dnsQname)

	rrset, l, err := imr.discoveryQuery(ctx, dnsQname, dns.TypeURI, "URI")
	if err != nil {
		return "", "", 0, l, err
	}

	for _, rr := range rrset.RRs {
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
			return uriRR.Target, host, port, l, nil
		}
	}

	l, err = unusable(l, "no valid DNS URI record")
	return "", "", 0, l, err
}

// tlsaAnswer is what the resolver said about a TLSA name: the usable
// records there, or that the name or the type does not exist, whether
// the answer was DNSSEC-validated, the verdict on it, and when it expires
// from the cache.
type tlsaAnswer struct {
	Records   []*dns.TLSA // usable records only (usableTLSA)
	Denied    bool        // NXDOMAIN or NODATA: there is no TLSA at the name
	Validated bool
	Chain     ChainStatus
	Expires   time.Time // zero when not known
}

// lookup is the answer as one of the peer's discovery lookups, required
// telling whether validation is required.
func (a tlsaAnswer) lookup(owner string, required bool) DiscoveryLookup {
	l := DiscoveryLookup{Mechanism: "API", Type: "TLSA", Owner: owner, Chain: a.Chain, Expires: a.Expires}
	what := "answer"
	if a.Denied {
		what = "denial"
	}
	switch {
	case !a.Validated && required:
		if l.Chain < ChainInsecure {
			l.Chain = ChainInsecure
		}
		l.Failure, l.Detail = FailureNotValidated, verdictDetail(what, l.Chain, true)
	case len(a.Records) == 0:
		l.Failure, l.Detail = FailureNoRecords, "no usable TLSA record"
	case l.Chain != ChainSecure:
		l.Detail = verdictDetail(what, l.Chain, false)
	}
	return l
}

// failedTLSALookup is the TLSA lookup at owner that failed with err.
func failedTLSALookup(owner string, err error) DiscoveryLookup {
	return DiscoveryLookup{Mechanism: "API", Type: "TLSA", Owner: owner,
		Failure: failureOf(err, ""), Detail: fmt.Sprintf("query failed: %v", err)}
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
		return tlsaAnswer{Denied: true, Validated: resp.Validated, Chain: chainOf(resp), Expires: resp.Expiration}, nil
	}
	ans := tlsaAnswer{Validated: resp.Validated, Chain: chainOf(resp), Expires: resp.Expiration}
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
// ipv6hint parameters, and the lookup.
func (imr *Imr) lookupServiceAddresses(ctx context.Context, serviceName string) ([]string, DiscoveryLookup, error) {
	serviceName = dns.Fqdn(serviceName)

	var addresses []string

	lgTransport().Debug("looking up SVCB", "service", serviceName)

	rrset, l, err := imr.discoveryQuery(ctx, serviceName, dns.TypeSVCB, "SVCB")
	if err != nil {
		return nil, l, err
	}

	for _, rr := range rrset.RRs {
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
		l, err = unusable(l, "no IP hints in the SVCB record")
		return nil, l, err
	}

	lgTransport().Debug("found addresses from SVCB", "count", len(addresses), "service", serviceName, "addresses", addresses)
	return addresses, l, nil
}
