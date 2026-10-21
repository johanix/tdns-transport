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
	"sort"
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
	tlsaLookupLogInterval      = 10 * time.Minute
	tlsaWarnLogInterval        = time.Hour
)

// tlsaEnd is one end of an HTTPS connection, as the checker logs it: the
// client checks the server it sends to, the server checks the client it
// takes requests from. Each end logs in its own words and under keys of its
// own, so an impostor at one end does not mute the other's report.
type tlsaEnd struct {
	key      string
	mismatch string
	noTLSA   string
}

var (
	sendingEnd = tlsaEnd{
		key:      "send",
		mismatch: "the peer's certificate matches none of its TLSA records; HTTPS to it is refused",
		noTLSA:   "no usable TLSA for the peer; HTTPS to it is not attempted (logged again in an hour)",
	}
	receivingEnd = tlsaEnd{
		key:      "recv",
		mismatch: "the client certificate presented for the peer matches none of its TLSA records; its HTTPS requests are refused",
		noTLSA:   "no usable TLSA for the peer; its HTTPS requests are refused (logged again in an hour)",
	}
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

// Check checks the certificate of the server the HTTPS client is sending to
// against the TLSA RRset of peer's mechanism ("API"). It passes when cert
// matches any usable record. A mismatch is looked at once more past the
// resolver's cache, which may hold a set from before a rotation, at most
// once per RecheckInterval for that name.
//
// The errors are ErrNoTLSA, ErrTLSAMismatch and ErrTLSALookup, wrapped. A
// failed lookup is retryable and changes nothing; an answer replaces the set
// held on the peer, and a denial (no TLSA at the name) empties it.
func (c *TLSAChecker) Check(ctx context.Context, peer *Peer, mechanism string, cert *x509.Certificate) error {
	return c.check(ctx, peer, mechanism, cert, sendingEnd)
}

// CheckClient is Check for the receiving end: cert is the client
// certificate presented for peer. It logs as the receiving end.
func (c *TLSAChecker) CheckClient(ctx context.Context, peer *Peer, mechanism string, cert *x509.Certificate) error {
	return c.check(ctx, peer, mechanism, cert, receivingEnd)
}

func (c *TLSAChecker) check(ctx context.Context, peer *Peer, mechanism string, cert *x509.Certificate, end tlsaEnd) error {
	if cert == nil {
		return fmt.Errorf("%w: %s presented no certificate", ErrTLSAMismatch, peer.ID)
	}
	set, err := c.current(ctx, peer, mechanism, false)
	if err != nil {
		return err
	}
	if len(set.Records) == 0 {
		c.noteNoTLSA(peer, set.Owner, end)
		return fmt.Errorf("%w: %s (%s)", ErrNoTLSA, peer.ID, ownerOrUnknown(set.Owner))
	}
	if tlsaMatches(set.Records, cert) {
		return nil
	}
	if set.Owner != "" && c.recheckDue(set.Owner) {
		fresh, err := c.current(ctx, peer, mechanism, true)
		if err != nil {
			// A lookup that failed looked at nothing: the next mismatch
			// may look again. One the caller gave up on keeps the
			// booking, or a client that hangs up mid-lookup could have
			// the name looked up past the cache as often as it likes.
			if ctx.Err() == nil {
				c.recheckUndo(set.Owner)
			}
		} else {
			if tlsaMatches(fresh.Records, cert) {
				lgTransport().Info("TLSA recheck after a mismatch: the certificate matches the peer's current TLSA",
					"peer", peer.ID, "owner", set.Owner)
				return nil
			}
			set = fresh
		}
	}
	c.noteMismatch(peer, set, cert, end)
	return fmt.Errorf("%w: %s (%s): presented SPKI SHA-256 %s", ErrTLSAMismatch, peer.ID, ownerOrUnknown(set.Owner), spkiSHA256Hex(cert))
}

// Refresh brings the TLSA set of peer's mechanism up to date through the
// resolver's cache, and returns it. The HTTPS client calls it before each
// request: a kept-alive connection does no handshake, so without it the set
// it was checked against could outlive its TTL. A changed set retires the
// peer's connections (APITransport.clientFor). The errors are as Check's.
func (c *TLSAChecker) Refresh(ctx context.Context, peer *Peer, mechanism string) (TLSASet, error) {
	return c.current(ctx, peer, mechanism, false)
}

// current is the TLSA set of peer's mechanism as the resolver has it now
// (fresh: past its cache), stored on the peer. Without a resolver, or a name
// to ask, it is the set discovery stored.
func (c *TLSAChecker) current(ctx context.Context, peer *Peer, mechanism string, fresh bool) (TLSASet, error) {
	set := peer.MechanismTLSA(mechanism)
	src := c.lookupSource()
	if src == nil && set.Owner != "" {
		c.logOnce("noresolver", tlsaWarnLogInterval, func() {
			lgTransport().Warn("no resolver for the TLSA lookup (not started yet, or none given): checking against the TLSA discovery stored, which is not looked up again within its TTL",
				"peer", peer.ID, "owner", set.Owner)
		})
	}
	if src == nil || set.Owner == "" {
		return set, nil
	}
	mine := nextTLSALookup()
	lctx, cancel := context.WithTimeout(ctx, c.lookupTimeout())
	defer cancel()
	ans, err := src.lookupTLSA(lctx, set.Owner, fresh)
	if err != nil {
		c.noteLookupFailed(peer, set.Owner, err)
		return TLSASet{}, fmt.Errorf("%w: %s (%s): %v", ErrTLSALookup, peer.ID, set.Owner, err)
	}
	// What the answer says about the peer's chain goes on its discovery
	// status, whether the answer is used or refused. A failed lookup says
	// nothing, and leaves the status as it was.
	l := ans.lookup(set.Owner, src.requireValidation())
	l.Mechanism = mechanism
	peer.noteLookup(l)
	if !ans.Validated {
		if src.requireValidation() {
			err := errors.New("the answer is not DNSSEC-validated and validation is required")
			c.noteLookupFailed(peer, set.Owner, err)
			return TLSASet{}, fmt.Errorf("%w: %s (%s): %v", ErrTLSALookup, peer.ID, set.Owner, err)
		}
		c.logOnce("unvalidated|"+peer.ID, tlsaWarnLogInterval, func() {
			lgTransport().Warn("accepting a TLSA RRset that is not DNSSEC-validated, as require-dnssec-validation is off",
				"peer", peer.ID, "owner", set.Owner)
		})
	}
	// Lookups of one peer may overlap, the checker's and discovery's. An
	// answer is stored only if no later lookup's answer is, and only for
	// the name still held: an older answer stored after a newer withdrawal
	// would put back the records it withdrew.
	set.Records = ans.Records
	set.Validated = ans.Validated
	held, stored := peer.storeMechanismTLSA(mechanism, set, mine, true)
	if !stored {
		return peer.MechanismTLSA(mechanism), nil
	}
	// No usable record is a withdrawal too, whether the name is gone or
	// holds only records that cannot vouch for an agent.
	withdrawn := len(ans.Records) == 0 && len(held.Records) > 0
	if withdrawn {
		// Nothing to check a certificate against: the mechanism needs
		// discovery again, which finds a TLSA when one is published.
		lgTransport().Warn("the peer has no usable TLSA any more; HTTPS to it stops until one is published",
			"peer", peer.ID, "owner", set.Owner, "denied", ans.Denied)
		peer.SetMechanismContactInfo(mechanism, "partial")
		peer.SetMechanismState(mechanism, PeerStateNeeded, "TLSA withdrawn")
	}
	return set, nil
}

// NoteNoTLSA logs that HTTPS to peer is not attempted for want of a TLSA:
// at Warn, at most hourly per peer.
func (c *TLSAChecker) NoteNoTLSA(peer *Peer, owner string) {
	c.noteNoTLSA(peer, owner, sendingEnd)
}

func (c *TLSAChecker) noteNoTLSA(peer *Peer, owner string, end tlsaEnd) {
	c.logOnce("notlsa|"+end.key+"|"+peer.ID, tlsaWarnLogInterval, func() {
		lgTransport().Warn(end.noTLSA, "peer", peer.ID, "owner", ownerOrUnknown(owner))
	})
}

// noteMismatch logs a certificate that matches none of the peer's TLSA
// records: at Error, at once, then at most every ten minutes per peer and
// end.
func (c *TLSAChecker) noteMismatch(peer *Peer, set TLSASet, cert *x509.Certificate, end tlsaEnd) {
	c.logOnce("mismatch|"+end.key+"|"+peer.ID, tlsaMismatchLogInterval, func() {
		lgTransport().Error(end.mismatch,
			"peer", peer.ID, "owner", ownerOrUnknown(set.Owner), "held", tlsaDigests(set.Records),
			"presented_spki_sha256", spkiSHA256Hex(cert))
	})
}

// noteLookupFailed logs a TLSA lookup that gave no usable answer: at Warn,
// at most every ten minutes per peer. Each check it fails is refused.
func (c *TLSAChecker) noteLookupFailed(peer *Peer, owner string, err error) {
	c.logOnce("lookup|"+peer.ID, tlsaLookupLogInterval, func() {
		lgTransport().Warn("the peer's TLSA could not be looked up; HTTPS with it fails until it can (logged again in ten minutes)",
			"peer", peer.ID, "owner", owner, "err", err)
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

// recheckUndo releases the booking recheckDue made for owner.
func (c *TLSAChecker) recheckUndo(owner string) {
	c.mu.Lock()
	delete(c.rechecked, owner)
	c.mu.Unlock()
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

// tlsaKey is a set's records as one comparable string, in an order of its
// own: the same RRset in another order is the same set.
func tlsaKey(records []*dns.TLSA) string {
	parts := strings.Split(tlsaDigests(records), ", ")
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func ownerOrUnknown(owner string) string {
	if owner == "" {
		return "no TLSA name known"
	}
	return owner
}
