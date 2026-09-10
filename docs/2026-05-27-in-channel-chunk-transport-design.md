# In-Channel CHUNK Transport: Design Notes

**Date:** 2026-05-27
**Status:** Design discussion. No code changes yet.
**Topic:** Carrying CHUNK-framed payloads inside an end-to-end secure
channel (DoT/DoQ), with DANE-anchored mutual authentication, primarily
to support high-volume DNSSEC private-key distribution from KDC to
"edge" KRS instances.

This document records a design discussion. It is not a specification.
It identifies the constraints, the design space, the parts of the
existing CHUNK machinery that should be reused, and the small set of
genuinely new pieces needed.

---

## 1. Problem and motivation

### 1.1 Origin of CHUNK

CHUNK was originally invented as the transport for **DNSSEC private
key distribution** from a Key Distribution Center (KDC) to a set of
Key Receiving Servers (KRS) at "the edge". It was later generalized
into the underlying comms framework for multi-provider DNS
(HSYNC-coordinated agents, combiner, signer).

Why "keys at the edge" matters:

- **Dynamic responses:** signed answers generated per query (geo,
  ECS-tailored, synthesized records) require the private key at the
  responder, not at a central signer.
- **Compact Denial of Existence:** on-the-fly NSEC/NSEC3 synthesis
  requires private key material at the answering server.
- **Local resigning under partition:** an edge POP that loses
  connectivity to the central signer can still serve fresh, validly
  signed data instead of going stale/bogus.

This use case is fundamentally about **moving private key material to
many recipients**, not about agents communicating with each other.

### 1.2 The two regimes

The multi-provider use case (agents, combiner, signer) is
**low-volume, low-cardinality, low-frequency**: a handful of HSYNC
peers, periodic gossip beats, occasional SYNC/UPDATE messages. CHUNK
+ JOSE over DNS-over-UDP works fine here; the per-message overhead is
not a bottleneck.

Private-key distribution to the edge is a different regime entirely:

- Cardinality: O(10^3) to O(10^5) recipients (edge POPs, replicas).
- Per-event payload: small (kilobytes of key material per key) but
  numerous (potentially many keys per event).
- Urgency: rollover windows are tight; compromise response wants
  *minutes*, not hours.
- Steady-state traffic is non-trivial (KSK rolls, ZSK rolls,
  scheduled rotations, emergency revocations).
- Slow recipient = partition risk for that POP's dynamic responses.

The current JOSE/CHUNK-over-Do53 path was designed and tuned for the
low-volume regime. It has overhead the high-volume regime cannot
amortize:

- Per-recipient JWE encryption (sender CPU scales O(N)).
- Per-recipient ACK/retry over UDP.
- No persistent session: every event re-pays envelope crypto + framing
  setup.
- Base64/JSON expansion in the on-wire bytes.
- Manifest+query-series pull dance round-trips even for in-network
  recipients.

This document considers an alternative transport — DoT/DoQ between
KDC and KRS, authenticated via DNSSEC-signed TLSA records — for the
high-volume regime, while keeping the existing UDP+JOSE+CHUNK path for
the multi-provider regime.

---

## 2. Threat model and security framing

Two distinct layers of crypto, often conflated:

- **Channel-level** (TLS, QUIC): protects the bytes *between two
  endpoints on one connection*. Confidentiality, integrity, replay
  protection within the session. Goes away when the connection
  closes; does not survive relay or store-and-forward.
- **Message-level** (JOSE, COSE, HPKE envelopes): protects the
  *payload itself* regardless of transport. Survives hops, can be
  audited later, recipient-specific. Pays per-message overhead.

These are complements, not alternatives:

- **Direct KDC↔KRS over DoT/DoQ:** channel crypto is sufficient. No
  intermediate hop sees plaintext. JOSE envelope is redundant.
- **Multi-hop (KDC → regional aggregator → local KRS):** channel
  crypto only protects each hop. If the regional aggregator must not
  see plaintext keys, message-level envelope is still required.
- **Audit / non-repudiation:** "prove this key came from this KDC
  three months later" needs a durable signature on the message
  itself, not a transient TLS session. JWS-style signatures, if
  retained, provide that.

The clean architectural rule: **channel crypto for transport
efficiency; envelope crypto for end-to-end secrecy across hops and
for durable provenance**. They coexist; the routing rule (when to use
which) is what needs design.

Authentication: DANE (TLSA + DNSSEC) gives mutual auth between KDC
and KRS without a CA. Expected usage 3 1 1 (DANE-EE,
SubjectPublicKeyInfo SHA-256), key rotation via TLSA rotation.
Authorization remains application-layer (KDC checks "is this KRS
authorized for these zones?"); identity-via-TLSA is *who*, not *what
they're allowed to do*.

---

## 3. Why DoT/DoQ is the right shape for high-volume key delivery

The KDC↔KRS workload (many recipients, many deliveries per recipient,
urgency, churn) matches DoT/DoQ's strengths:

- **Long-lived sessions:** KDC opens connections to each KRS once,
  keeps them warm. Crypto setup amortized across all deliveries.
- **0-RTT resumption (DoQ):** brief disconnections don't add
  handshake latency to the next delivery.
- **Stream multiplexing (DoQ specifically):** N simultaneous
  deliveries to one peer = N independent streams in one connection,
  no head-of-line blocking. DoT can't do this.
- **Flow control / backpressure:** built into TCP and QUIC.
- **No per-message envelope tax** when channel crypto suffices.
- **DANE authentication** aligns with how the rest of this ecosystem
  authenticates (everything else is already DNSSEC-rooted).

Trade-offs worth noting:

- **TLSA lookup latency on first connection:** DNSSEC chain
  validation plus TLS handshake. Mitigated by connection caching and
  long-lived sessions.
- **DoQ portability for C-language KRS:** mature C QUIC stacks (ngtcp2,
  quiche, lsquic) exist but are heavier than mature C TLS stacks. For
  resource-constrained KRS targets, DoT may be the pragmatic call even
  with reduced parallelism.
- **Replay/freshness moves layers:** JOSE had explicit nonces; TLS
  has implicit ordering within a session. Application-layer replay
  defenses still needed for idempotency-sensitive operations.

---

## 4. The right framing inside the secure channel

### 4.1 Constraint: both endpoints are DNS nameservers

Even inside a DoT/DoQ connection, the inner protocol is DNS. Message
types are query, NOTIFY, UPDATE, etc. We are not free to invent
arbitrary framing — the unit on the wire is a DNS message.

This means:

- Whatever payload we ship must be carried by an existing DNS message
  type.
- The 64KB DNS message ceiling (uint16 length prefix in the
  TCP/TLS/QUIC framing) applies inside the channel. **DoQ does not
  let you send one larger-than-64KB DNS message.**

The 64KB ceiling is a wire-format constraint of DNS itself, not of
any specific transport.

### 4.2 Why CHUNK is the right serialization (not just a workaround)

The original framing question — "what DNS message type carries the
key payload?" — misses the point. **CHUNK is a serialization, not a
transport workaround.** It is the DNS-shaped equivalent of "here is a
binary blob, treat it as a single RR".

Without CHUNK, supporting arbitrary payload shapes (key delivery,
config, revocation list, status report, ...) requires a new RRtype
per payload shape, with all the IANA, parsing, and reassembly cost
that implies. CHUNK gives you **one RRtype, opaque payload**, with
structure living *in* the payload (via the `metadata` map in the
manifest) rather than in the wire format.

That property is independent of transport. CHUNK is just as useful
inside DoT/DoQ as on bare Do53 — it lets the sender ship arbitrary Go
structs without inventing new RRtypes.

### 4.3 What CHUNK looks like today (ground truth)

From `tdns/v2/core/rr_chunk.go` and `tdns/v2/core/chunk_utilities.go`:

```
type CHUNK struct {
    Format     uint8   // FormatJSON=1, FormatJWT=2 today
    HMACLen    uint16
    HMAC       []byte  // SHA-256 over Format+Data, only on manifest
    Sequence   uint16  // 0 = manifest, 1..N = data chunks
    Total      uint16  // number of data chunks (manifest) / same value (data)
    DataLength uint16  // -- this is the wire-format cap on Data
    Data       []byte  // JSON manifest, or raw chunk bytes
}
```

Two roles:

- **Manifest** (Sequence=0): `Data` is a JSON-encoded `ManifestData`
  struct with `ChunkCount`, `ChunkSize`, free-form `Metadata
  map[string]interface{}`, and an optional inline `Payload []byte`.
- **Data chunk** (Sequence≥1): `Data` is raw chunk bytes; HMAC is
  empty (HMAC lives on the manifest).

Two carriers exist today:

- **CHUNK RR RDATA** — carries the above struct in answer/additional
  sections of DNS messages. Used as query responses in the
  manifest+query-series path.
- **EDNS(0) ChunkOption** — same format **minus Sequence/Total**, in
  `tdns/v2/edns0/edns0_chunk.go`. Used to piggyback small payloads on
  NOTIFY. Intentionally non-fragmentable (the file's header comment
  says so explicitly).

Three transport patterns exist today:

- **NOTIFY + EDNS(0) CHUNK option (inline path):** payload travels in
  the EDNS(0) option. Atomic, single DNS message, ≤64KB total. No
  fragmentation. Used for small payloads.
- **NOTIFY(CHUNK) + query series (pull path):** an empty NOTIFY of
  TypeCHUNK signals "something to fetch". Receiver pulls a manifest
  CHUNK via query, then pulls each data CHUNK via subsequent queries.
  This is where the manifest+sequence fragmentation lives.
- **JOSE envelope (orthogonal):** payload bytes can be wrapped with
  `JWS(JWE(payload))` via `SecurePayloadWrapper` in
  `tdns-transport/v2/transport/crypto.go`. The wrap is a separate
  layer — CHUNK doesn't know about it. The receiver heuristically
  detects encryption with `IsPayloadEncrypted()`, which is fragile
  (will mis-classify plain CBOR as encrypted; see §6).

### 4.4 Why CHUNK's machinery is the right thing to keep

The temptation is to "strip down" CHUNK for in-channel use: drop
Sequence/Total (no fragmentation inside the stream), drop HMAC (TLS
covers integrity), drop JOSE wrap (channel covers confidentiality).

This is the wrong optimization. The savings are <1% of bandwidth (a
few bytes per ~64KB message). The cost is forked formats, branching
code, parallel test matrices, and operator confusion ("which CHUNK
variant is on the wire?"). **Complexity is its own cost; small
on-wire savings do not justify it.**

Better: **keep CHUNK exactly as-is, including manifest+chunks
fragmentation. Adjust *usage*, not *format*.**

---

## 5. What the in-channel pattern actually looks like

### 5.1 Sizes and patterns

- **Payload ≤ ~64KB** (which covers a single key, a small batch of
  keys, most config blobs, status reports): one CHUNK with inline
  Payload (`ChunkCount=0`, Payload in the manifest's `Payload`
  field), carried as one NOTIFY+EDNS(0)+CHUNK-option DNS message.
  Single round-trip, no fragmentation.
- **Payload > 64KB** (large batches, full snapshots): manifest +
  sequenced data chunks. Each chunk fits in its own DNS message.
  Sent as a sequence of NOTIFYs on one DoQ stream (or pipelined on a
  TLS connection for DoT).

The 64KB ceiling is the DNS wire format itself, not a per-transport
property. DoQ doesn't help; both ends still speak DNS messages
framed by a uint16 length prefix.

### 5.2 Middlebox hostility on Do53 (and its absence inside the channel)

The reason today's design has **two** transport patterns
(EDNS(0)-option-inline and NOTIFY+query-series) is middlebox
hostility on Do53:

- EDNS(0) options in private code-point ranges get stripped or
  FORMERR'd by some middleboxes.
- Novel RRtypes confuse caching resolvers and DPI.
- Oversized UDP messages get truncated even when EDNS(0) advertises
  larger buffers.

Inside DoT/DoQ this entire class of problem vanishes. TLS makes the
inner DNS messages opaque to anything between the endpoints.
NOTIFY+EDNS(0)+CHUNK-option **always works** in-channel: a single
end-to-end TCP/QUIC connection, no UDP retransmit guessing, no DPI in
the path.

That means the NOTIFY+query-series fallback path can be **skipped
entirely on the in-channel transport adapter**. It still exists in
the codebase for the Do53 path; the in-channel adapter just doesn't
exercise it. No fallback negotiation, no probing, no fallback state
to manage.

This is *qualitatively* simpler — removing a fallback path is a
different class of simplification from removing a few bytes of
header.

### 5.3 The needed new piece: fragmented EDNS(0) CHUNK option

Today's EDNS(0) ChunkOption deliberately has **no Sequence/Total
fields**. The header comment says so explicitly: "EDNS options cannot
be fragmented". One option = one atomic payload = ≤64KB.

For in-channel use we want: **send a sequence of NOTIFYs on the
stream, each carrying one CHUNK in its EDNS(0) option, with manifest
+ data-chunks semantics across them, so payloads >64KB work without
falling back to the query-series pull pattern.**

That requires extending the EDNS(0) ChunkOption to carry Sequence/Total
(or introducing a fragmentable variant). Either way it is a
backward-incompatible wire-format change to that option encoding.
Under the project's "no backwards compatibility" rule that is fine,
provided both sides ship together.

The receive-side change: a new "stream consumer" that reads NOTIFYs
in order off a DoQ/DoT stream, feeds the carried EDNS(0)-CHUNK pieces
into the existing manifest/reassembly logic, and dispatches the
assembled payload — instead of waiting for queries from the
receiver. The reassembly logic itself does not change.

This is the **only** genuinely new piece of CHUNK-layer functionality.

### 5.4 DoQ-specific opportunity: stream-per-CHUNK

DoQ allows multiple independent streams in one connection. For very
large deliveries (e.g. a 20MB blob fragmented into ~300 chunks), each
chunk could ride its own QUIC stream, completing in parallel with
independent flow control.

This is an optimization, not a requirement, and is not where the
initial design should live. The simple case — one stream per logical
delivery, NOTIFYs in order, reassembly via existing manifest logic —
is the right starting point. Per-chunk parallelism can be revisited
once measurements justify it.

---

## 6. The envelope-optional question

CHUNK carries a payload. Today that payload is implicitly
JOSE-wrapped (`JWS(JWE(payload))`) on the secure path, and the
receiver heuristically detects encryption by trying to JSON-parse the
bytes (`IsPayloadEncrypted()` in `crypto.go`). This is fragile in two
ways:

1. **CBOR payloads break the heuristic.** Plain CBOR doesn't start
   with `{`, so it false-positives as encrypted. Adding any non-JSON
   payload format kills the heuristic.
2. **No explicit indicator of envelope mode.** Sender and receiver
   share an implicit assumption about whether the bytes are wrapped.

For in-channel use we want **envelope = "none"** (channel does
confidentiality + auth, no JOSE wrap). For Do53 we want **envelope =
"jose"**. Future: **envelope = "cose"** as a third option, see §7.

Cleanest fix: explicit envelope indicator. Three placements:

**(a) Inside `ManifestData.Metadata` as a convention.** Zero wire
change. Receiver reads `metadata["envelope"]`. Fine for a small
discriminator but `metadata` is `map[string]interface{}` — loosely
typed for a load-bearing dispatch key.

**(b) As a typed field on `ManifestData`.** First-class `Envelope
string` field next to `ChunkCount`, `ChunkSize`, `Payload`. JSON-compatible
schema change. Strong-typed. Tiny wire impact.

**(c) As a new value of the `Format` byte** (`FormatJSON`,
`FormatJWT`, `FormatJSONRaw`, `FormatCOSE`, ...). Uses the existing
one-byte field but conflates *serialization format* (JSON vs CBOR vs
binary) with *envelope mode* (wrapped vs raw). Probably the wrong
axis.

Leaning toward **(b)** — typed field on `ManifestData`, explicit,
JSON-compatible, kills the heuristic.

Whichever placement, the rule on the wire becomes: receiver looks at
the envelope indicator, dispatches to the matching unwrap (no-op for
"none", JOSE unwrap for "jose", COSE unwrap for "cose"). One code
path, parameterized on envelope mode. `IsPayloadEncrypted()`
disappears.

JOSE's standard `alg: "none"` for JWS is an alternative indicator
mechanism, but it pushes the dispatch into the JOSE library — which
correctly refuses `alg: none` in security-critical contexts (good
default!). Better to have the dispatch happen *before* the JOSE
library is invoked. Argues for an explicit field outside the JWS
envelope.

---

## 7. COSE as a future third backend

Separate from the channel discussion: COSE (RFC 8152 / 9052-53) as a
binary CBOR analogue of JOSE makes sense as a third backend
alongside HPKE and JOSE, especially for KRS targets where C library
support matters.

Properties:

- ~30–50% smaller envelopes than JOSE (CBOR int-keyed maps, no
  base64, length-prefixed framing).
- Faster parse, no JSON round-trips.
- Same conceptual structure (sign/encrypt with recipient keys).
- C library maturity (`t_cose`, libcose) is meaningful for embedded
  KRS.

Open questions captured from the discussion:

- **Replace JOSE or coexist?** KRS was the original reason JOSE was
  added (better C library support than HPKE). If C COSE is now
  competitive, COSE may be the *better* C target — and the question
  becomes whether COSE replaces JOSE rather than joining it. KRS
  modernization is currently waiting on the tdns-transport
  re-architecting work and was not addressed in this discussion.
- **Per-node backend selection** already exists in the design — adding
  COSE is a third entry, not an architectural change.
- **Discovery via shared JWKs:** intended approach is the same JWKs
  used for JOSE today; COSE_Key is isomorphic to JWK and can be
  derived on demand. No separate COSE_Key publication.
- **Negotiation:** sender attempts COSE encapsulation; on FORMERR
  falls back to JOSE. Cheap and self-healing.

COSE is **not** in scope for the in-channel CHUNK work directly, but
the envelope-indicator design in §6 should accommodate it as a
first-class value from the start.

---

## 8. Summary: what changes, what doesn't

**Does not change:**

- CHUNK RR wire format (`rr_chunk.go`).
- Manifest + sequenced data chunks fragmentation (`chunk_utilities.go`).
- HMAC computation on manifests.
- Existing Do53 transport patterns (EDNS(0)-option-inline +
  NOTIFY+query-series fallback for middlebox-hostile paths).
- JOSE wrapping (`SecurePayloadWrapper`).
- Reassembly state machine.

**Changes:**

- **EDNS(0) ChunkOption gains Sequence/Total fields** (or a
  fragmentable sibling option). Backward-incompatible wire-format
  change to that one option, acceptable under "no backwards
  compatibility".
- **`ManifestData` gains an explicit `Envelope` field** (or
  equivalent indicator at chosen placement, leaning §6 (b)). JSON-
  compatible additive schema change. Receiver dispatches on this
  instead of using `IsPayloadEncrypted()`. Heuristic detection goes
  away.

**Adds:**

- **In-channel transport adapter:** opens DoT/DoQ to peer (TLSA
  lookup, DANE validation, TLS/QUIC handshake), manages a long-lived
  session, writes NOTIFYs onto a stream, reads NOTIFYs off a stream.
  Hard-codes `envelope=none`, skips middlebox-fallback negotiation,
  uses fragmented EDNS(0)+CHUNK-option for all payloads regardless of
  size.
- **Stream consumer:** receive-side state for "read NOTIFYs in order
  off this stream, feed their EDNS(0)+CHUNK pieces into the existing
  reassembly logic". Replaces the query-driven pull pattern for the
  in-channel path. Reuses the existing reassembly logic.

**Does not add** (despite being considered and rejected):

- A new RRtype for key delivery (rejected — that's what CHUNK is for).
- A stripped-down "channel CHUNK" format variant (rejected — <1%
  savings, not worth the complexity).
- "Stream-as-fragmentation" replacing manifest+chunks (rejected —
  parallel concept for the same end result, the existing fragmentation
  already works and is transport-agnostic).

---

## 9. Open questions

These were raised but not resolved during the discussion. They block
implementation and need decisions.

(One additional question — "does adding DoQ require re-doing the
manual KDC↔KRS enrollment?" — was raised and resolved during the
discussion; see §10.)

1. **Envelope indicator placement.** §6 (a) vs (b) vs (c). Leaning
   (b) — typed `Envelope` field on `ManifestData`.

2. **EDNS(0) ChunkOption v2 wire format.** Add Sequence/Total to the
   existing struct (and tolerate the one-time break), or define a
   separate fragmentable option code so the inline-only version
   still exists for Do53?

3. **Push vs pull in the channel.** Long-lived KDC→KRS connection
   with KDC pushing is simplest. A pull mode (KRS asks "any new keys
   for zone Z?") may still be useful for reconnection ("send me
   anything I missed during my downtime"). Out of scope here, but
   worth designing alongside the push path so the channel can carry
   both.

4. **Fanout pattern at scale.** Star (one KDC → N KRS), tree
   (regional aggregators), or gossip. Star is simplest but
   bottlenecks at high N. Tree adds latency + a trust hop where
   envelope crypto becomes mandatory again. Gossip is hard for
   *private* data. Tied to (5).

5. **Multi-hop key delivery.** If a regional aggregator forwards
   keys to local KRS, channel-only crypto leaks plaintext to the
   aggregator. That re-introduces JOSE/COSE envelope crypto *over*
   the channel transport. Worth designing the layering explicitly
   rather than discovering it later.

6. **DoT vs DoQ choice per peer.** DoQ is technically superior for
   high-fanout, multiplexed delivery. DoT may be the only practical
   target for constrained-C KRS for a while. Should peers advertise
   support (via TLSA params, SVCB, or session-establishment
   negotiation)?

7. **Application-layer replay defense.** Channel crypto provides
   in-session replay protection only. Cross-session replay (an
   attacker who recorded a prior session's plaintext-equivalent
   bytes) is out of scope of the channel. Need to confirm what
   application-layer freshness the existing key-delivery flow
   already has.

8. **COSE backend timing and scope.** Not in the in-channel CHUNK
   work directly, but the envelope-indicator design should not
   foreclose COSE. See §7.

---

## 10. Credential lifecycle: adding DoQ without re-enrollment

This section answers an open question that came up during the
discussion: given that the manual KDC↔KRS enrollment process was
designed for HPKE (and works equally well for JOSE/JWK), how do we
add DoT/DoQ as a transport without forcing a re-bootstrap?

### 10.1 Context

The existing enrollment process establishes a mutually authenticated
cryptographic identity between KDC and KRS:

- KDC generates an enrollment package containing the KDC public key,
  address details, and a unique enrollment token.
- KRS generates its own keypair, sends an enrollment request to KDC
  containing its public key, address details, signed by its private
  key and encrypted with the KDC public key.
- After enrollment, KDC has `node_id → {KRS_pub, address, ...}` and
  KRS has the KDC's public key bound to its identity.

Edge KRS nodes cannot, in general, publish their own JWK or TLSA in
a globally secure DNSSEC-signed zone — that's the entire reason
manual enrollment exists. Any DoT/DoQ design must respect that
constraint.

### 10.2 The bootstrap-once principle

**Once an authenticated channel exists, additional credentials can
be added under the same identity without re-bootstrapping, provided
the new credential is attested by the existing one.**

This is the same pattern used elsewhere: TLS cert rotation
authenticated by the old cert, SSH host-key rotation signed by the
old host key, etc. The new artifact is trusted because the
already-authenticated identity vouches for it.

For our case: KRS generates a TLS keypair and a self-signed cert (or
just the key material and its DANE matching value), then sends a
"credential attestation" message over the existing JOSE/CHUNK
channel, signed by its enrolled JOSE key and encrypted to the KDC's
enrolled JOSE key.

KDC processing:

1. Decrypt with KDC's enrolled private key (proves message was
   intended for this KDC).
2. Verify JOSE signature with the **enrolled** KRS_pub (proves the
   bound-at-enrollment KRS is the attester).
3. Record the TLSA value, address, and validity bound to the KRS's
   enrolled identity.

After this, the KDC's peer registry holds:
`node_id → {JOSE_pub (enrolled), TLSA_hash (attested), DoQ_address (attested), ...}`.
Both credentials trace to the same enrollment ceremony.

**Integrity is preserved** because the new credential was attested by
the old one over the already-authenticated channel.
**Authenticity is preserved** because the message is signed by the
enrolled key. No new trust anchor is introduced; no security
guarantee is lowered.

### 10.3 Why this is stronger than DNSSEC-published TLSA for this use case

For edge KRS nodes specifically, **explicit attestation to the KDC**
has properties that DNSSEC-published TLSA does not:

- **No dependency on DNS infrastructure for the KRS's identity.**
  KDC's record of `node_id → TLSA_hash` is self-contained. Matches
  the existing enrollment property.
- **No reliance on a third party's DNSSEC operations.** TLSA-via-
  DNSSEC depends on whoever runs the KRS's zone maintaining DNSSEC
  correctness.
- **Tighter binding.** DNSSEC-TLSA says "the controller of this DNS
  name authorizes this cert". Direct attestation says "the specific
  enrolled-at-time-T entity with this private key authorizes this
  cert". The latter is more specific.
- **Easier rotation.** KRS rotates its TLS cert: signs a new
  attestation, sends over the existing channel, done. With
  DNSSEC-published TLSA: DNS changes + re-signing + TTL waits.

The KDC becomes the authority on which TLSA values are trusted for
which KRS. This is consistent with the existing model — global DNS
is not relied on for KRS identity at any point.

### 10.4 Attestation message contents

The credential-add message carries at minimum:

- KRS's TLS cert (or just the SubjectPublicKeyInfo hash, if the cert
  is self-signed and only used for DANE-EE matching).
- DANE matching parameters in explicit form (e.g. usage=3 / DANE-EE,
  selector=1 / SPKI, matching-type=1 / SHA-256). Putting the literal
  bytes in the attestation avoids ambiguity later.
- DoQ/DoT listener address (host:port).
- Optional validity period / NotBefore / NotAfter.
- Nonce or sequence number (replay defense — see §10.6).

Wrapped as `JWS(JWE(attestation))` using the enrolled keys, carried
in a CHUNK over the existing JOSE/CHUNK transport.

### 10.5 KDC TLS credential: symmetric question, asymmetric answer

The KRS also needs to validate the KDC's TLS cert when initiating a
DoQ connection. Two options:

- **(a) Include the KDC's TLSA in the original enrollment package.**
  One-time additive change to the enrollment payload format. KRS
  has it from day 0; the first DoQ session works without a
  prerequisite handshake.

- **(b) KDC self-attests later** over the JOSE channel, using the
  same pattern as the KRS attestation in §10.4.

These are not mutually exclusive, but the recommendation is
**(a) for the KDC, (b) for the KRS** — matching the existing
asymmetry of enrollment, where KDC keys are known up front and KRS
keys are sent in. (a) avoids a chicken-and-egg problem on the very
first DoQ session.

This does mean a one-time additive change to the enrollment package
format. Under the project's "no backwards compatibility" rule, this
is acceptable.

### 10.6 Subtleties to nail down

1. **DANE selector/matching in the attestation.** Be explicit
   (`3 1 1` is the natural choice for self-signed certs). Including
   the literal selector/matching/usage bytes in the attestation
   makes the receiver's verification logic unambiguous.

2. **Replay defense.** Include a nonce or sequence number in the
   attestation message so an attacker who recorded a prior
   attestation can't replay an old (possibly revoked) credential
   after compromise. JOSE supports this in the protected header; the
   attestation handler must actually check it.

3. **Revocation flow.** If KRS's TLS key is compromised but its
   enrolled JOSE key is not, KRS sends a "revoke TLSA X" message
   signed by the still-good enrolled key. If the enrolled key
   itself is compromised, manual re-enrollment is required — which
   is the same risk that exists today with HPKE/JOSE compromise.
   No regression.

4. **Audit / forensics.** The KDC should log credential-add events
   with full provenance: when, signed-by-which-enrolled-key,
   attesting-which-TLSA-value, source address. Forensic value is
   high if a compromise is discovered later.

5. **Credential expiry and renewal.** If TLS certs have a NotAfter,
   the KRS needs to attest a new cert before the old one expires.
   This is a routine renewal flow over the existing channel, not a
   re-bootstrap.

### 10.7 Summary

**No re-enrollment is required to add DoT/DoQ as a transport.** The
KRS attests its self-generated TLSA over the existing JOSE-protected
channel, signed by its enrolled key. The KDC's TLSA is added to the
enrollment package format (one-time additive change). Both
transports descend from the same enrollment ceremony.

This is a comms-portfolio enrichment, not a re-bootstrap. Integrity
and authenticity of KDC↔KRS comms are unchanged.

---

## 11. References

- `tdns/v2/core/rr_chunk.go` — CHUNK RR wire format.
- `tdns/v2/core/chunk_utilities.go` — manifest + HMAC.
- `tdns/v2/edns0/edns0_chunk.go` — EDNS(0) ChunkOption (today, not
  fragmentable).
- `tdns-transport/v2/transport/crypto.go` — JOSE wrap/unwrap,
  `SecurePayloadWrapper`, `IsPayloadEncrypted()`.
- `tdns-transport/v2/transport/chunk_notify_handler.go` — NOTIFY(CHUNK)
  receive path.
- `tdns/docs/2026-01-25-adding-jose-support-to-chunk.md` — original
  JOSE-added-to-CHUNK plan.
- `tdns/docs/2026-01-27-generalize-chunk-comms-framework.md` —
  extraction of CHUNK framework from tdns-nm into tdns.
- `tdns/docs/2026-02-04-jwk-discovery-implementation-plan.md` —
  JWK-based agent discovery.
- `tdns/docs/2026-02-26-chunk-implementation-review.md` — review of
  the current CHUNK + JOSE integration.
- `tdns/docs/2026-02-26-chunk-transport-fragmentation-and-framing.md`
  — fragmentation + framing details.
