/*
Package transport moves messages between the agents of a multi-provider DNS
setup over two mechanisms, DNS and HTTPS, and knows nothing about what the
messages mean.

# Vocabulary

Transport's own verbs are hello, beat, ping and confirm, plus the chunk
machinery that carries a payload. Everything the application says on top of
that travels as one opaque carrier, AppMessage: a scope, a verb token and a
payload transport never reads. The application registers a handler per verb
on the router and installs the parser that reads its own payload
conventions (ChunkNotifyHandler.ParseApp).

# Sending

TransportManager owns the mechanisms a node supports, selects one per peer
and falls back to the other (Send), fans hello and beat out over every
eligible mechanism (SendAll), and retries an application message through the
ReliableMessageQueue until the receiver's inline confirmation clears it
(Enqueue, MarkDeliveryConfirmed).

The DNS mechanism (DNSTransport) sends a NOTIFY for the CHUNK type with the
payload in an EDNS0 CHUNK option, or in query mode serves the payload as
CHUNK records the receiver fetches. The receiver's inline confirmation comes
back in the NOTIFY response. The HTTPS mechanism (APITransport) posts JSON
and carries hello, beat, ping, confirm and the sync family only.

# Receiving

ChunkNotifyHandler.RouteViaRouter is the receive pipeline for a NOTIFY(CHUNK).
It is registered with tdns for the CHUNK type and, in this order: reads the
distribution id and the sender from the query name; asks the application
whether that sender may talk to this node at all, before any cryptography;
fetches the payload from the EDNS0 option or by CHUNK query; checks the
envelope label; verifies and decrypts with the named sender's key and no
other; has the application parse the payload; asks the application again,
now with the zone; and only then enters the router. The router runs the
statistics and logging middleware and the verb's handler; the response
wrapper sends the DNS response with the handler's inline confirmation; the
callback wrapper hands the parsed message to the application.

What the pipeline and the handlers exchange rides on MessageContext, through
the typed accessors in message_context.go.

# Payload crypto

PayloadCrypto holds the local key pair and the peers' keys and produces and
consumes the wire form of an encrypted payload, base64(JWS(JWE(payload)))
with the JOSE backend. The envelope label in the CHUNK Format byte tells a
receiver how the bytes are wrapped (envelope.go). Backends implement
crypto.Backend and register by name.

# Peers and discovery

Peer carries a peer's identity, its per-mechanism address, state and keys,
and its liveness; PeerRegistry holds them. Discovery (discovery.go, imr.go)
resolves an identity's URI, SVCB, TLSA and JWK records through the tdns
resolver and installs what it finds on the peer and in PayloadCrypto. The
application decides when to discover; transport does the lookups.

# Consumers

The multi-provider application in tdns-mp is the production consumer.
cmd/transport-exercise drives the public surface without it and is the
proof that a second consumer can.
*/
package transport
