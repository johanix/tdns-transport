# The DNS carrier dials only a DNS address

Date: 2026-10-27. Status: proposed, waiting on a decision (below).
Follows tdns-transport #39. Refs johanix/tdns-mp#260.

## The problem

A peer has four address slots:

| Slot | Written by | Read by |
|---|---|---|
| `Mechanisms["API"].Address`, with `APIEndpoint` | discovery's API leg | the HTTPS mechanism (`clientFor`), `APIUsable`, `HasMechanism` |
| `Mechanisms["DNS"].Address` | discovery's DNS leg | `HasMechanism`, `PreferredMechanism` |
| `DiscoveryAddr` | config, a hello, the signer's address (tdns-mp); discovery's DNS leg; **discovery's API leg, as a fallback** | `CurrentAddress` |
| `OperationalAddr` | a relocate (tdns-mp) | `CurrentAddress`, before `DiscoveryAddr` |

`CurrentAddress()` is what the DNS carrier dials (`dns.go`,
`app_message.go`), and what `SelectTransport` and `reaches` test before
they choose DNS. tdns-mp also reads it to ask whether the peer is known
anywhere at all: `OnDiscoveryFailed`'s "already established" check, among
others (table below).

The fallback serves that second question. A peer that offers only the API
gets the API's address in `DiscoveryAddr`, so `CurrentAddress()` is not nil
for it. But the DNS carrier dials that slot, and the DNS carrier sends DNS to
the HTTPS port. #39 closed four ways to that, one at a time: the fallback is
written only once API is usable, only for a peer that offers no DNS, not
when the DNS URI was refused, and refusing API takes the fallback with it
but leaves an address that is not the API's.

Two more remain on main at 860bae6, both on a peer that offers only the API,
with the DNS transport on:

- **TLSA withdrawn.** A validated denial of the TLSA makes API NEEDED, and
  `APIUsable()` false. The fallback stays, so `SelectTransport` chooses DNS,
  which dials the HTTPS address.
- **API address moved.** The SVCB names a new address and no TLSA is held
  for the endpoint yet. The API slot gets the new address; the fallback keeps
  the old one, which the DNS carrier dials.

Each fix so far has had to work out whose address `DiscoveryAddr` holds.
The slot should not have two owners.

## The rule

1. `DiscoveryAddr` and `OperationalAddr` hold only addresses the DNS carrier
   dials: from config, a hello, discovery's DNS leg, or a relocate. Nothing
   puts the API's address there. The fallback goes.
2. The API's address lives in its mechanism slot, with `APIEndpoint`, as
   now. Only the HTTPS mechanism dials it.
3. `SelectTransport` and `reaches` are unchanged: DNS when the DNS transport
   is on and the peer has a DNS address; API when `APIUsable()`. They read
   no mechanism state and need none, since every address the DNS carrier
   can see is a DNS address.
4. A new `Peer.Reachable()` answers the other question: the peer has a DNS
   address, or a usable API mechanism. It is `reaches` without the
   manager's transports.

What each event does to the slots:

| Event | API slot, endpoint | DNS slot | `DiscoveryAddr` | `OperationalAddr` |
|---|---|---|---|---|
| Discovery: API usable or not | set | – | – | – |
| Discovery: DNS usable | – | set | set | – |
| DNS refused | – | cleared | cleared | cleared |
| API refused | cleared | – | – | – |
| TLSA withdrawn | (state NEEDED) | – | – | – |
| Relocate | – | – | – | set |
| Config, hello | – | – | set | – |

`demoteMechanism` gets simpler: refusing API clears the API slot and
endpoint, and compares nothing with `DiscoveryAddr` or `OperationalAddr`.
Refusing DNS is as in #39.

## What changes in behaviour

- A peer that offers only the API has no DNS address. `CurrentAddress()`
  is nil for it, and `Reachable()` is true while its API is usable.
- **Decision for Johan, 1.** A relocate that names the API's own address
  is kept when API is refused. In #39 it went with API, because the slot
  could not say whose it was. Under the rule it is the peer's word on where
  the DNS carrier dials, which the API's refusal says nothing about.
- Unchanged: refusing DNS still clears an address that came from config or
  a hello, when discovery's DNS leg has not overwritten it. Which of a
  configured and a discovered DNS address wins is a separate question, not
  taken up here.

## What callers in tdns-mp rely on

At tdns-mp b921a94. "DNS" means the caller wants the DNS carrier's address;
"reachable" means it asks whether the peer is known anywhere.

| Site | Reads | Means | Change |
|---|---|---|---|
| `hsync_transport.go:643` `OnDiscoveryFailed` | `CurrentAddress() != nil` | reachable | `Reachable()`. Today an API-only peer passes through the fallback |
| `hsync_transport.go:1107` the deliverer has an address | `CurrentAddress() == nil` | reachable | `!Reachable()`; else every message from an API-only deliverer starts a discovery |
| `apihandler_agent_distrib.go:185` ping | `CurrentAddress() == nil` | reachable | `!Reachable()`; else a ping to an API-only peer is refused |
| `hsync_bridge.go:58` `rearmFailedDiscovery` | `CurrentAddress() != nil` | reachable | `Reachable()`; same outcome, as the mechanism loop after it covers API |
| `apihandler_agent_distrib.go:263` discovery display | `CurrentAddress()` | either | show the DNS address and the API's separately |
| `apihandler_agent_distrib.go:385` API display | `CurrentAddress()` | API | `MechanismAddress("API")`; today a peer with both shows its DNS address as the API's |
| `apihandler_agent_distrib.go:470` DNS display | `CurrentAddress()` | DNS | none; correct for an API-only peer once the fallback is gone |
| `hsync_transport.go:1730` `otherConfirmTransport` | `CurrentAddress() != nil` | DNS | none; today a confirmation to an API-only peer falls back to DNS at the HTTPS address |
| `hsync_transport.go:3156` `peerAddressLookup` | `CurrentAddress()` | DNS | none |
| `apihandler_signer_routes.go:80` | `CurrentAddress()` | DNS | none |
| `SetDiscoveryAddress` in `combiner_peer.go`, `signer_peer.go`, `main_init.go`, `apihandler_peer.go`, `hsync_transport.go:3059/3094/3175` | – | DNS (udp) | none |
| `SetOperationalAddress` in `hsync_transport.go:1517` (relocate) | – | DNS | none |

tdns-nm and tdns use none of these.

## Naming

**Decision for Johan, 2.**

- (a) Keep the names; the doc comments carry the rule. Smaller diff, and
  tdns-mp builds unchanged after the re-pin, but its four "reachable" sites
  then change behaviour silently until they are edited.
- (b) Rename `CurrentAddress()` to `DNSAddress()`, `SetDiscoveryAddress` to
  `SetDNSAddress` and `DiscoveryAddr` to `DNSAddr`; `OperationalAddr` keeps
  its name. The compiler finds every caller in tdns-mp, and each one chooses
  `DNSAddress()` or `Reachable()`. No shim: tdns-mp pins tdns-transport.

Recommended: (b). The two meanings shared a slot because the name did not
say which one it was.

## Plan

1. tdns-transport PR: the fallback goes, `demoteMechanism`'s API case
   loses its comparisons, `Reachable()` is added, (b) if chosen, and the
   tests below.
2. tdns-mp re-pin PR, after #263: the four "reachable" sites and the two
   displays. With (b) the re-pin needs this to build.

## Tests

Every case #39's tests cover, and the two above.

| Case | Test | Outcome under the rule |
|---|---|---|
| API-only peer refused at the refresh, DNS transport on | `TestARefusedMechanismCannotBeSelected` | nothing selected, as now |
| Demoting one mechanism drops only its addresses | `TestDemotingAMechanismDropsOnlyItsAddresses` | as now |
| A refused DNS address is not written back | `TestARegistrationWritesNoRefusedDNSAddressBack` | as now |
| An unusable API is no DNS address | `TestAnUnusableAPIIsNoAddressForTheDNSCarrier` | as now; its second half changes: a usable API-only peer has no DNS address, is `Reachable()`, and gets API even when it prefers DNS |
| DNS refused (its key or its URI), API usable, DNS preferred | `TestRefusedDNSWithAUsableAPISelectsAPI` | API, as now |
| Refusing API keeps a configured DNS address and a relocate | `TestRefusingAPIKeepsAConfiguredCarrierAddress` | as now |
| Refusing API keeps a relocate | `TestRefusingAPIKeepsTheRelocateOfAnAPIOnlyPeer` | set up by discovery, not by hand; the relocate to the API's address is kept (decision 1) |
| TLSA withdrawn from an API-only peer | new | nothing selected; fails on main |
| API address moved, no TLSA for it yet | new | no DNS address, the old one not dialled; fails on main |
| Registration never writes an HTTPS address for the DNS carrier | new, over every registration case above | `DiscoveryAddr` is nil or a DNS address |
| `Reachable()` | new | DNS address only, usable API only, unusable API only, nothing |
