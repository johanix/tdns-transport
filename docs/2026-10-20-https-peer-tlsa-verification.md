# HTTPS between peers: each end validates the other against its TLSA

Date: 2026-10-20. Status: being implemented (tdns-transport, then tdns-mp, then a small tdns change).
Tracking: johanix/tdns-mp#234.

## The rule

HTTPS between agents is mutual TLS, and each end validates the other's
certificate. The certificates are self-signed. What vouches for one is the
peer's TLSA record (DANE-EE), found through the node's own resolver, under
DNSSEC. A connection whose certificate is not checked is not an option.

The receiving end already checks the client's certificate against the
sender's TLSA (tdns-mp's TLSA middleware). The sending end does not check
the receiver at all: the client sets `InsecureSkipVerify` and installs no
check of its own. This note covers both ends, since they rely on the same
TLSA, and the receiving end's check has the same gaps.

## What the check relies on

A certificate check is only as good as the TLSA it checks against. Five
things about that TLSA:

1. **The whole RRset, not one record.** During a rollover the old and the
   new TLSA are published together. A certificate passes when it matches
   any usable record (RFC 6698 2.1, RFC 7671 5). Usable here means usage 3
   (DANE-EE), selector 0 or 1, matching type 1 or 2. Discovery used to keep
   the first record of any usage.
2. **Fresh, bounded by the TTL.** A TLSA learned once and kept for good lets
   a peer whose certificate changed fall back to DNS for good, and keeps a
   withdrawn or compromised TLSA trusted. The check therefore asks the
   resolver for the RRset at every handshake. The resolver's cache answers
   within the TTL, so this costs a lookup only when the TTL has run out.
3. **Validated.** An answer that DNSSEC has not validated vouches for
   nothing: whoever can answer the peer's identity lookups could answer
   with their own TLSA. Over HTTPS the body is plain JSON, so TLS is all
   that protects it. An unvalidated answer is refused. Only with the
   resolver's `require-dnssec-validation` off (a lab setting) is it
   accepted, with a warning per peer (ruled 2026-10-20). That is the same
   escape hatch tdns's XoT uses. The guarantee therefore holds only with
   validated discovery.
4. **A withdrawal counts.** A validated NXDOMAIN or NODATA for the TLSA name
   empties the set. Nothing else does: a timeout or a SERVFAIL is a failed
   check of this connection, retryable, and it keeps the set.
5. **A mismatch is looked at once more.** When a certificate matches none
   of the records, the resolver may hold a set from before a rotation. The
   check then asks again past the cache, at most once per rediscovery
   interval for that name, and matches against what comes back.

## The sending end

- **Every peer gets an HTTPS client of its own,** cloned from the shared
  one. Its TLS config adds a `VerifyConnection` that runs the check above
  against the leaf certificate, and chains any `VerifyConnection` the
  caller set. `VerifyConnection` runs on resumed sessions too, and with
  `InsecureSkipVerify` it gives DANE-EE semantics: no CA, no expiry and no
  name check, only the key.
- **The check is always on.** It does not depend on `InsecureSkipVerify`:
  a client that also verifies by CA gets both checks. Turning DANE into
  plain WebPKI by dropping a flag is not possible.
- **No fall-through to a shared client.** Where the check cannot be
  installed (a `Proxy`, a `DialTLS`, a transport that is not an
  `*http.Transport`), the send is refused with a retryable error.
- **A peer with no TLSA is not attempted.** Discovery leaves the API
  mechanism NEEDED when it finds no usable TLSA, as it does for an endpoint
  without an address, so the discovery retrier looks again. Until then the
  transport picks DNS, and an HTTPS send to that peer is refused before any
  dial.
- **Typed errors.** `ErrNoTLSA` (none known, or the set is empty) and
  `ErrTLSAMismatch` (no record matches), reachable with `errors.Is` through
  `TransportError`. Both are retryable: the caller's fallback sends over
  DNS.
- **Logging.** A mismatch is logged at Error at once, with the TLSA records
  held and the SPKI SHA-256 of the certificate presented, then at most once
  every ten minutes per peer. A missing TLSA is logged at Warn, at most
  hourly per peer. A recovery after a mismatch is logged at Info.
- **The per-peer clients** are keyed on the peer, and dropped with it.

## The receiving end (tdns-mp)

The TLSA middleware calls the same check, so both ends follow the five
points above. It runs once per TLS connection: a burst of requests on one
connection does not mean one resolver lookup each.

## What a failed check never does

A failed check never leads to an HTTPS send. The fallback is the DNS
mechanism, whose payloads are signed and encrypted (JOSE) end to end.

## Out of scope

- `/hello`: the receiving end takes a hello before it knows the sender's
  TLSA. That is tdns-mp#56.
- Management API clients, and tdns's own DoT, DoH and DoQ clients.
- Peers configured with an endpoint and no discovery (a combiner's or a
  signer's): they have no TLSA, so HTTPS to them cannot pass. tdns-mp
  refuses to configure one.

## Tests

- A certificate that matches no record is refused, and the server sees no
  request.
- A certificate that matches the second record of two passes.
- With no TLSA, the transport does not dial, and the error is `ErrNoTLSA`.
- An unvalidated TLSA is refused, and accepted with a warning when
  validation is not required.
- A validated denial empties the set. A failed lookup keeps it, and the
  connection fails retryably.
- After a mismatch, a fresh lookup that finds the new record lets the
  connection through.
- A client that verifies by CA checks the TLSA too.
- Where the check cannot be installed, the send is refused.
