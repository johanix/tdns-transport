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
   resolver for the RRset at every handshake, and the client asks again
   before every request, since a kept-alive connection does no handshake.
   The resolver's cache answers within the TTL, so this costs a lookup only
   when the TTL has run out.
3. **Validated.** An answer that DNSSEC has not validated vouches for
   nothing: whoever can answer the peer's identity lookups could answer
   with their own TLSA. Over HTTPS the body is plain JSON, so TLS is all
   that protects it. An unvalidated answer is refused. Only with the
   resolver's `require-dnssec-validation` off (a lab setting) is it
   accepted, with a warning per peer (ruled 2026-10-20). That is the same
   escape hatch tdns's XoT uses, and like XoT it then takes a bogus answer
   too. The guarantee therefore holds only with validated discovery.
4. **A withdrawal counts.** An answer with no usable record empties the
   set: a validated NXDOMAIN or NODATA for the TLSA name, or a set holding
   only records that cannot vouch for an agent. The API mechanism then goes
   back to NEEDED, so discovery looks again. Nothing else empties the set:
   a timeout or a SERVFAIL is a failed check of this request, retryable,
   and it keeps the set (see the invariant below for a moved endpoint).
5. **A mismatch is looked at once more.** When a certificate matches none
   of the records, the resolver may hold a set from before a rotation. The
   check then asks again past the cache, at most once every five minutes
   for that name, and matches against what comes back. A look that fails
   does not count.

## The invariant: who holds a peer's TLSA set

Two writers store a peer's TLSA set, and their lookups may overlap:
discovery, which also sets the API endpoint, and the check, which only
refreshes the set it holds. The set held is always for the name of
discovery's last registration, as the endpoint is: a registration for
another name replaces it (with an empty set when that lookup failed), and an
answer for any name but the one held is dropped. For that name, the answer
of the lookup that started last wins, whichever is stored last, and a failed
lookup changes nothing. API counts as usable only when the set held is for
that name and has a usable record. `TestTLSASetInvariantHoldsInEveryInterleaving`
runs every interleaving of two discoveries (the old name and a new one) and
two checks, each answering found, withdrawn or failed, against it.

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
- **Redirects are refused** on every per-peer client, whatever the shared
  client was given.
- **No resolver** for a check that has a TLSA name to ask is logged at
  Warn, at most hourly: the check then has only the set discovery stored.
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
  hourly per peer. A failed lookup is logged at Warn, at most every ten
  minutes per peer. A recovery after a mismatch is logged at Info. Each end
  logs in its own words and under keys of its own (`Check` for the sending
  end, `CheckClient` for the receiving end), so an impostor client claiming
  a peer does not mute the sending end's report of a mismatch with it.
- **A look past the cache that the caller gave up on** keeps its booking:
  a client that hangs up mid-lookup cannot have the name looked up past
  the cache as often as it likes.
- **The per-peer clients** are keyed on the peer, and dropped with it.

## The receiving end (tdns-mp)

The TLSA middleware calls the same checker (`CheckClient`), so both ends
follow the five points above. A passed check holds for a minute for that
peer and certificate, across connections: a burst of requests does not mean
one resolver lookup each, and a kept-alive connection outlives a withdrawal
found by a lookup of its own by at most a minute past the TTL. A peer whose
set is already empty is refused at once, whatever verdict is held.

## What a failed check never does

A failed check never leads to an HTTPS send. The fallback is the DNS
mechanism, whose payloads are signed and encrypted (JOSE) end to end.

## Out of scope

- `/hello`: the receiving end takes a hello before it knows the sender's
  TLSA. That is tdns-mp#56.
- Management API clients, and tdns's own DoT, DoH and DoQ clients.
- Peers configured with an endpoint and no discovery (a combiner's or a
  signer's): they have no TLSA, so their certificate cannot be checked and
  HTTPS to them cannot be authenticated. tdns-mp ignores such an endpoint,
  with a warning at load that says so.

## Tests

- A certificate that matches no record is refused, and the server sees no
  request.
- A certificate that matches the second record of two passes.
- With no TLSA, the transport does not dial, and the error is `ErrNoTLSA`.
- An unvalidated TLSA is refused, and accepted with a warning when
  validation is not required.
- A validated denial empties the set, and so does an answer with no usable
  record. A failed lookup keeps it, and the request fails retryably.
- A kept-alive connection: after a withdrawal or a rotation the next
  request is refused, and the receiver sees no more.
- After a mismatch, a fresh lookup that finds the new record lets the
  connection through.
- A client that verifies by CA checks the TLSA too. One with
  `InsecureSkipVerify`, as agents run, refuses a key the TLSA does not name.
- Where the check cannot be installed, the send is refused.
