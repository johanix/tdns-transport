# The DNS carrier dials only a DNS address

Date: 2026-10-27. Status: reviewed twice; both decisions settled by
Johan on 2026-10-27 (the check, and the rename). Implemented in this PR,
#42, after #43 and #270 merged. The tdns-mp half is johanix/tdns-mp#282.
Follows tdns-transport #39. Follow-up: tdns-transport #44. Refs johanix/tdns-mp#260.

## The problem

A peer has four address slots:

| Slot | Written by | Read by |
|---|---|---|
| `Mechanisms["API"].Address`, with `APIEndpoint` | discovery's API leg | the HTTPS mechanism (`clientFor`), `APIUsable`, `HasMechanism` |
| `Mechanisms["DNS"].Address` | discovery's DNS leg | `HasMechanism`, `PreferredMechanism` |
| `DiscoveryAddr` | in tdns-mp: config, a static peer, the signer's address; discovery's DNS leg; **discovery's API leg, as a fallback** | `CurrentAddress` |
| `OperationalAddr` | a relocate (tdns-mp) | `CurrentAddress`, before `DiscoveryAddr` |

A hello writes none of them. A hello from a peer with no address starts a
discovery, and discovery writes the slots.

`CurrentAddress()` is what the DNS carrier dials (`dns.go`,
`app_message.go`). `SelectTransport` and `reaches` test it before they
choose DNS. tdns-mp also reads it to ask a different question: whether
there is anywhere at all to send to the peer (table below).

The fallback is what gives a peer that offers only the API an answer to
that second question. Discovery puts the API's address in `DiscoveryAddr`,
so `CurrentAddress()` is not nil for it. Two tdns-mp checks depend on that:
the deliverer check and ping. But the DNS carrier dials that slot, so it
sends DNS to the HTTPS port.

#39 closed four ways to that, one at a time. The fallback is now written:
- only once API is usable,
- only for a peer that offers no DNS,
- not when the DNS URI was refused.

And refusing API takes the fallback with it, but leaves an address that is
not the API's.

Two more remain on main at 860bae6. Both are on a peer that offers only the
API, with the DNS transport on:

- **TLSA withdrawn.** A validated denial of the TLSA makes API NEEDED, and
  `APIUsable()` false. `demoteMechanism` is not called, as nothing was
  refused, so the fallback stays. `SelectTransport` then chooses DNS, which
  dials the HTTPS address.
- **API address moved.** The SVCB names a new address, and no TLSA is held
  for it yet. The API slot gets the new address. The fallback keeps the old
  one, which the DNS carrier dials.

Each fix so far had to work out whose address `DiscoveryAddr` holds.
The slot should not have two owners.

This is not a safety fault. A DNS send to the HTTPS port fails. What it
costs is a delay and a failure counted against the mechanism.

## The rule

1. **The DNS slots hold only DNS addresses.** `DiscoveryAddr` and
   `OperationalAddr` hold only addresses the DNS carrier dials. The fallback
   goes. The setters check the rule: an address whose `Transport` is not
   `udp` or `tcp`, or that has a `Path`, is refused with an error, and the
   slot keeps what it had. An address with no `Transport` is refused too,
   and the error names the peer and the address. The DNS carrier dials over
   TCP either way, so the check is in effect "not https, and no path".
2. **The API's address lives only in its mechanism slot.** It stays there
   with `APIEndpoint`, as now. Only the HTTPS mechanism dials it.
3. **`SelectTransport` and `reaches` are unchanged.** They choose DNS when
   the DNS transport is on and the peer has a DNS address, and API when
   `APIUsable()`. They read no mechanism state, and need none: the setters
   let no other kind of address reach the DNS carrier.
4. **A new `Peer.Addressable()` answers the other question.** It reports
   whether there is somewhere to send to the peer:
   `p.DNSCarrierAddress() != nil || p.APIUsable()` (`DNSCarrierAddress()`
   is today's `CurrentAddress()`, renamed below). It does not take
   `p.mu` itself, since both calls take it, and a second read lock can
   deadlock behind a waiting writer. That makes it non-atomic, which is
   fine for this question.

What each event does to the slots:

| Event | API slot, endpoint | DNS slot | `DiscoveryAddr` | `OperationalAddr` |
|---|---|---|---|---|
| Discovery, API not refused, an address found (usable or not) | set | – | – | – |
| Discovery, DNS usable | – | set | set | – |
| DNS refused | – | cleared | cleared | cleared |
| API refused | cleared | – | – | – |
| TLSA withdrawn | (state NEEDED) | – | – | – |
| Relocate to a DNS address | – | – | – | set |
| Relocate to any other address | – | – | – | refused, kept |
| Config, static peer, signer address | – | – | set | – |

`demoteMechanism` gets simpler: refusing API clears the API slot and its
endpoint, and looks at nothing else. Refusing DNS is as in #39.

## What changes in behaviour

- **No DNS address for an API-only peer.** A peer that offers only the API
  has no DNS address. `CurrentAddress()` is nil for it, and
  `Addressable()` is true while its API is usable.
- **Decision 1, settled 2026-10-27: a relocate to an HTTPS address is
  refused.**
  - In #39, a relocate equal to the API's address went with API when API
    was refused.
  - Address equality compares host, port, transport and path. So such a
    relocate can only be an `https` address with the API's path.
  - Keeping it would put an HTTPS address back where the DNS carrier dials.
    The setter check refuses it when it arrives instead, so refusing API
    never has to look at `OperationalAddr`.
  - Nothing in tdns-mp sends a relocate today; only the handler exists. So
    no sender breaks.
- **Unchanged: refusing DNS still clears a configured address** that
  discovery's DNS leg has not overwritten. Which of a configured and a
  discovered DNS address should win is tdns-transport #44.

## What callers in tdns-mp rely on

The line numbers are at tdns-mp d2cc1d8. In the "Means" column, "DNS"
means the caller wants the DNS carrier's address, and "addressable" means
it asks whether there is anywhere to send.

| Site | Reads | Means | Change |
|---|---|---|---|
| `hsync_transport.go:647` `OnDiscoveryFailed` | `(st >= Known && st != Error) \|\| CurrentAddress() != nil` | addressable | `Addressable()` replaces the address clause only; the state clause stays. The state clause already passes a registered API-only peer. |
| `hsync_transport.go:1123` the deliverer has an address | `CurrentAddress() == nil` | addressable | `!Addressable()`. Without it, every message from an API-only deliverer starts a discovery. |
| `apihandler_agent_distrib.go:185` ping | `CurrentAddress() == nil` | the transport named | Ping over the transport the operator names, and only that one: `--dns` (the default) or `--api`, as `peer ping` and `peer apiping` do. The other is not tried, and the reply names the transport. `Addressable()` does not apply: over DNS, an API-only peer has no address, and the ping fails without dialling its HTTPS address. Today this operation calls `SendPing`, which takes the preferred mechanism and falls back. It honours `--dns`/`--api` only for the combiner, and its reply at `:203` says "dnsping ok" over either. `peer ping` also calls `SendPing`, while saying "dns transport". |
| `hsync_bridge.go:58` `rearmFailedDiscovery` | `CurrentAddress() != nil` | addressable | `Addressable()`. Where main holds a stale fallback (an ERROR peer whose API went back to NEEDED after a TLSA withdrawal), main returns early and never re-arms. Under the rule the peer is re-armed, which is right. |
| `apihandler_agent_distrib.go:263` discovery display | `CurrentAddress()` | either | Show the DNS address and the API's separately. |
| `apihandler_agent_distrib.go:385` API display | `CurrentAddress()` | API | `MechanismAddress("API")`. Today a peer with both mechanisms shows its DNS address as the API's. |
| `apihandler_agent_distrib.go:471` DNS display | `CurrentAddress()` | DNS | None. It becomes correct for an API-only peer once the fallback is gone. |
| `hsync_transport.go:1746` `otherConfirmTransport` | `CurrentAddress() != nil` | DNS | None. Today a confirmation to an API-only peer falls back to DNS at the HTTPS address. |
| `hsync_transport.go:3172` `peerAddressLookup` | `CurrentAddress()` | DNS | None. |
| `apihandler_signer_routes.go:80` | `CurrentAddress()` | DNS | None. |
| `SetDiscoveryAddress` in `combiner_peer.go:75,163`, `signer_peer.go:77,157`, `main_init.go:303,426`, `apihandler_peer.go:273`, `hsync_transport.go:3075,3110,3191` | – | DNS (udp) | Handle the setter's error. None of them can trip it. |
| `SetOperationalAddress` in `hsync_transport.go:1533` (`routeRelocateMessage`) | – | DNS | Refuse a relocate the setter refuses, and log why. `ParseRelocatePayload` is a bare `json.Unmarshal`, and the handler copies `Transport` and `Path` unchecked. |
| A comment at `start_agent.go:99` | – | – | Names `DiscoveryAddress`; update it. |

The tdns-mp tests that call these accessors:
- `api_confirm_test.go`
- `api_tlsa_test.go`
- `https_answer_test.go`
- `peer_ipv6_test.go`
- `sender_rule_test.go`
- `transport_dispatch_test.go`
- `transport_integ_test.go`

tdns-nm and tdns use none of these accessors.

## Naming

**Decision 2, settled 2026-10-27: rename.**

- `CurrentAddress()` becomes `DNSCarrierAddress()`.
- `SetDiscoveryAddress` becomes `SetDNSCarrierAddress`.
- `DiscoveryAddr` becomes `DNSCarrierAddr`.
- "DNS carrier" keeps these apart from `Mechanisms["DNS"].Address`. The two
  can differ: config writes one, and discovery writes both.
- `OperationalAddr` keeps its name. Its comment states the rule, and its
  setter checks it.

The compiler then finds every caller in tdns-mp, and each one chooses
`DNSCarrierAddress()` or `Addressable()`. Keeping the names would have let
tdns-mp build unchanged after the re-pin, with its "addressable" sites
changing behaviour silently until someone edited them. There is no
shim: tdns-mp pins tdns-transport.

The comments that describe the slots change too:
- `peer.go:76-80`: its field comment, "Address discovered via DNS", is
  already wrong, since config writes the slot too;
- `SetMechanismAddress`'s comment;
- `api.go:108`;
- the package doc's transport-selection example at `init.go:118`;
- the comments in `discovery.go` and `demoteMechanism`.

## Plan

This comes after the work in flight on the same files. tdns-transport #43
edits `manager.go`, and once the rename is on transport main, tdns-mp does not
build against it until its callers change.

1. tdns-transport #43 merges. Then tdns-mp #270 re-pins to it and merges.
2. This PR, #42, with:
   - the fallback removed;
   - the setter check;
   - `demoteMechanism`'s API case reduced to its own slot;
   - `Addressable()`;
   - the rename;
   - the comment sweep;
   - the tests below.
3. One tdns-mp PR with:
   - the re-pin;
   - the call-site changes above;
   - the relocate check;
   - the ping over the named transport, and the two displays;
   - its tests.

   After it, run the end-to-end tests that exercise TLSA and API
   confirmations. Where they have a peer that offers only the API, add a
   TLSA withdrawal and check that nothing goes over DNS to its HTTPS port.

## Tests

### tdns-transport

These cover every case #39's tests cover, plus the two remaining faults and
the check. The new ones are in `dns_carrier_address_test.go`. The two faults
are tested through discovery and its refresh; with the old fallback put
back, both fail.

| Case | Test | Outcome under the rule |
|---|---|---|
| API-only peer refused at the refresh, DNS transport on | `TestARefusedMechanismCannotBeSelected` | Nothing selected, as now. |
| Demoting one mechanism drops only its addresses | `TestDemotingAMechanismDropsOnlyItsAddresses` | As now. |
| A refused DNS address is not written back | `TestARegistrationWritesNoRefusedDNSAddressBack` | As now. |
| An unusable API is no DNS address | `TestAnUnusableAPIIsNoAddressForTheDNSCarrier` | As now. Its second half changes: a usable API-only peer has no DNS address, is `Addressable()`, and gets API even when it prefers DNS. |
| DNS refused (its key or its URI), API usable, DNS preferred | `TestRefusedDNSWithAUsableAPISelectsAPI` | API, as now. |
| Refusing API keeps a configured DNS address and a relocate | `TestRefusingAPIKeepsAConfiguredCarrierAddress` | As now. |
| Refusing API keeps a relocate | `TestRefusingAPIKeepsTheRelocateOfAnAPIOnlyPeer` | Set up by discovery, not by hand. A relocate to a DNS address is kept. One to the API's address is refused by the setter, so it never arises. |
| TLSA withdrawn from an API-only peer | new | Nothing selected. Fails on main. |
| API address moved, no TLSA for it yet | new | No DNS address, and the old one is not dialled. Fails on main. |
| The setters refuse a non-DNS address | new | An `https` address, or one with a `Path`, returns an error, and the slot keeps the old address. |
| Registration never writes a non-DNS address for the DNS carrier | new: a table of the registration cases above, the TLSA withdrawn and the API moved each in two steps | `DiscoveryAddr` is nil or a DNS address. |
| `Addressable()` | new | Covers a peer with a DNS address only, a usable API only, an unusable API only, and nothing. |

### tdns-mp

| Case | Outcome |
|---|---|
| Each of the three "addressable" sites, with an API-only peer whose API is usable | It counts as addressable, as it does today. At the deliverer that comes through the fallback today. |
| The same three sites, with that peer's TLSA withdrawn | It no longer counts as addressable. The deliverer starts a discovery, and `rearmFailedDiscovery` re-arms the peer. |
| A DNS ping to an API-only peer, its API usable or not | No DNS address: it fails without dialling the HTTPS address, and the API is not tried. |
| An API ping with the TLSA withdrawn | Not dialled. |
| A DNS ping that fails | The API is not tried. |
| A relocate naming an `https` address | Refused. The old address is kept. |
| The API display for a peer with both mechanisms | It shows the API's address. |
