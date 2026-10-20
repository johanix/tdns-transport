/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A peer's certificate is checked against the peer's TLSA RRset, at both
 * ends of an HTTPS connection (docs/2026-10-20-https-peer-tlsa-verification.md).
 * Agents' certificates are self-signed; what vouches for one is the TLSA
 * record its identity zone publishes (DANE-EE), found through the node's own
 * resolver, under DNSSEC.
 */

package transport

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

var (
	// ErrNoTLSA: there is no usable TLSA record for the peer, so its
	// certificate cannot be checked and HTTPS to it is not attempted.
	ErrNoTLSA = errors.New("no usable TLSA record for the peer")
	// ErrTLSAMismatch: the certificate the peer presented matches none of
	// its TLSA records: an impostor, or a record the peer has not updated.
	ErrTLSAMismatch = errors.New("the certificate matches none of the peer's TLSA records")
	// ErrTLSALookup: the TLSA could not be looked up, or the answer was not
	// DNSSEC-validated where validation is required. It says nothing about
	// the set, which stays as it was.
	ErrTLSALookup = errors.New("the peer's TLSA could not be looked up")
)

const (
	defaultTLSALookupTimeout   = 3 * time.Second
	defaultTLSARecheckInterval = 5 * time.Minute
	tlsaMismatchLogInterval    = 10 * time.Minute
	tlsaWarnLogInterval        = time.Hour
)

// TLSAChecker checks a peer's certificate against the peer's TLSA RRset. One
// checker serves both ends: the HTTPS client checks the receiver with it, and
// the receiving application checks the client's certificate with it.
type TLSAChecker struct {
	// GetImr is the node's resolver. Each check asks it for the TLSA RRset,
	// and its cache answers within the TTL, so a rotated certificate or a
	// withdrawn record is seen within a TTL. Nil (or a nil result) checks
	// against the set discovery stored on the peer.
	GetImr func() *Imr
	// LookupTimeout bounds the lookup inside a check; zero means 3 s.
	LookupTimeout time.Duration
	// RecheckInterval is the least time between two lookups of one TLSA
	// name past the cache after a mismatch; zero means 5 minutes.
	RecheckInterval time.Duration

	// source, when set, answers the lookups in place of the resolver (tests).
	source tlsaSource

	mu        sync.Mutex
	rechecked map[string]time.Time // by TLSA name
	logged    map[string]time.Time // by kind and peer
}

// tlsaSource answers TLSA lookups: the node's resolver (*Imr), or a test's.
type tlsaSource interface {
	lookupTLSA(ctx context.Context, owner string, fresh bool) (tlsaAnswer, error)
	requireValidation() bool
}

// NewTLSAChecker returns a checker that asks getImr's resolver.
func NewTLSAChecker(getImr func() *Imr) *TLSAChecker {
	return &TLSAChecker{GetImr: getImr}
}

// Check checks cert against the TLSA RRset of peer's mechanism ("API"). It
// passes when cert matches any usable record. A mismatch is looked at once
// more past the resolver's cache, which may hold a set from before a
// rotation, at most once per RecheckInterval for that name.
//
// The errors are ErrNoTLSA, ErrTLSAMismatch and ErrTLSALookup, wrapped. A
// failed lookup is retryable and changes nothing; an answer replaces the set
// held on the peer, and a denial (no TLSA at the name) empties it.
func (c *TLSAChecker) Check(ctx context.Context, peer *Peer, mechanism string, cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("%w: %s presented no certificate", ErrTLSAMismatch, peer.ID)
	}
	set, err := c.current(ctx, peer, mechanism, false)
	if err != nil {
		return err
	}
	if len(set.Records) == 0 {
		c.NoteNoTLSA(peer, set.Owner)
		return fmt.Errorf("%w: %s (%s)", ErrNoTLSA, peer.ID, ownerOrUnknown(set.Owner))
	}
	if tlsaMatches(set.Records, cert) {
		return nil
	}
	if set.Owner != "" && c.recheckDue(set.Owner) {
		if fresh, err := c.current(ctx, peer, mechanism, true); err == nil {
			if tlsaMatches(fresh.Records, cert) {
				lgTransport().Info("TLSA recheck after a mismatch: the certificate matches the peer's current TLSA",
					"peer", peer.ID, "owner", set.Owner)
				return nil
			}
			set = fresh
		}
	}
	c.noteMismatch(peer, set, cert)
	return fmt.Errorf("%w: %s (%s): presented SPKI SHA-256 %s", ErrTLSAMismatch, peer.ID, ownerOrUnknown(set.Owner), spkiSHA256Hex(cert))
}

// current is the TLSA set of peer's mechanism as the resolver has it now
// (fresh: past its cache), stored on the peer. Without a resolver, or a name
// to ask, it is the set discovery stored.
func (c *TLSAChecker) current(ctx context.Context, peer *Peer, mechanism string, fresh bool) (TLSASet, error) {
	set := peer.MechanismTLSA(mechanism)
	src := c.lookupSource()
	if src == nil || set.Owner == "" {
		return set, nil
	}
	lctx, cancel := context.WithTimeout(ctx, c.lookupTimeout())
	defer cancel()
	ans, err := src.lookupTLSA(lctx, set.Owner, fresh)
	if err != nil {
		return TLSASet{}, fmt.Errorf("%w: %s (%s): %v", ErrTLSALookup, peer.ID, set.Owner, err)
	}
	if !ans.Validated {
		if src.requireValidation() {
			return TLSASet{}, fmt.Errorf("%w: %s (%s): the answer is not DNSSEC-validated and validation is required",
				ErrTLSALookup, peer.ID, set.Owner)
		}
		c.logOnce("unvalidated|"+peer.ID, tlsaWarnLogInterval, func() {
			lgTransport().Warn("accepting a TLSA RRset that is not DNSSEC-validated, as require-dnssec-validation is off",
				"peer", peer.ID, "owner", set.Owner)
		})
	}
	withdrawn := ans.Denied && len(set.Records) > 0
	set.Records = ans.Records
	set.Validated = ans.Validated
	peer.SetMechanismTLSA(mechanism, set)
	if withdrawn {
		// Nothing to check a certificate against: the mechanism needs
		// discovery again, which finds a TLSA when one is published.
		lgTransport().Warn("the peer's TLSA is withdrawn; HTTPS to it stops until one is published",
			"peer", peer.ID, "owner", set.Owner)
		peer.SetMechanismContactInfo(mechanism, "partial")
		peer.SetMechanismState(mechanism, PeerStateNeeded, "TLSA withdrawn")
	}
	return set, nil
}

// NoteNoTLSA logs that HTTPS to peer is not attempted for want of a TLSA:
// at Warn, at most hourly per peer.
func (c *TLSAChecker) NoteNoTLSA(peer *Peer, owner string) {
	c.logOnce("notlsa|"+peer.ID, tlsaWarnLogInterval, func() {
		lgTransport().Warn("no usable TLSA for the peer; HTTPS to it is not attempted (logged again in an hour)",
			"peer", peer.ID, "owner", ownerOrUnknown(owner))
	})
}

// noteMismatch logs a certificate that matches none of the peer's TLSA
// records: at Error, at once, then at most every ten minutes per peer.
func (c *TLSAChecker) noteMismatch(peer *Peer, set TLSASet, cert *x509.Certificate) {
	c.logOnce("mismatch|"+peer.ID, tlsaMismatchLogInterval, func() {
		lgTransport().Error("the peer's certificate matches none of its TLSA records; HTTPS to it refused",
			"peer", peer.ID, "owner", ownerOrUnknown(set.Owner), "held", tlsaDigests(set.Records),
			"presented_spki_sha256", spkiSHA256Hex(cert))
	})
}

// logOnce runs log the first time for key and then at most once per every.
func (c *TLSAChecker) logOnce(key string, every time.Duration, log func()) {
	now := time.Now()
	c.mu.Lock()
	last, seen := c.logged[key]
	due := !seen || now.Sub(last) >= every
	if due {
		if c.logged == nil {
			c.logged = make(map[string]time.Time)
		}
		c.logged[key] = now
	}
	c.mu.Unlock()
	if due {
		log()
	}
}

// recheckDue reports whether a lookup of owner past the cache may run now,
// and books it.
func (c *TLSAChecker) recheckDue(owner string) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if last, ok := c.rechecked[owner]; ok && now.Sub(last) < c.recheckInterval() {
		return false
	}
	if c.rechecked == nil {
		c.rechecked = make(map[string]time.Time)
	}
	c.rechecked[owner] = now
	return true
}

// lookupSource is where the lookups go: the resolver GetImr gives, or nil
// (check against what discovery stored).
func (c *TLSAChecker) lookupSource() tlsaSource {
	if c.source != nil {
		return c.source
	}
	if c.GetImr == nil {
		return nil
	}
	if imr := c.GetImr(); imr != nil && imr.Imr != nil {
		return imr
	}
	return nil
}

func (c *TLSAChecker) lookupTimeout() time.Duration {
	if c.LookupTimeout > 0 {
		return c.LookupTimeout
	}
	return defaultTLSALookupTimeout
}

func (c *TLSAChecker) recheckInterval() time.Duration {
	if c.RecheckInterval > 0 {
		return c.RecheckInterval
	}
	return defaultTLSARecheckInterval
}

// tlsaMatches reports whether cert matches any of records.
func tlsaMatches(records []*dns.TLSA, cert *x509.Certificate) bool {
	for _, rr := range records {
		if usableTLSA(rr) && tdns.VerifyCertAgainstTlsaRR(rr, cert) == nil {
			return true
		}
	}
	return false
}

// spkiSHA256Hex is the SHA-256 of cert's SubjectPublicKeyInfo in hex: the
// association data of the 3 1 1 TLSA record that would match it.
func spkiSHA256Hex(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// tlsaDigests is records as "usage selector type data", for the log.
func tlsaDigests(records []*dns.TLSA) string {
	parts := make([]string, 0, len(records))
	for _, rr := range records {
		parts = append(parts, fmt.Sprintf("%d %d %d %s", rr.Usage, rr.Selector, rr.MatchingType, strings.ToLower(rr.Certificate)))
	}
	return strings.Join(parts, ", ")
}

// tlsaKey is a set's records as one comparable string.
func tlsaKey(records []*dns.TLSA) string {
	return tlsaDigests(records)
}

func ownerOrUnknown(owner string) string {
	if owner == "" {
		return "no TLSA name known"
	}
	return owner
}
