/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Serving query-mode CHUNK (F2b, cleanup plan step 4): the receiver of a
 * NOTIFY without an EDNS0 payload asks the sender for the distribution's
 * records by query name, <sequence>.<receiver>.<distid>.<sender>, and the
 * sender answers from its ChunkStore. Moved here from tdns-mp; the DNS
 * transport owns both ends of the chunk chain.
 */

package transport

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// ServeChunkQueries registers, with tdns's query dispatcher, a handler that
// answers CHUNK queries for the distributions this transport has stored.
// Call it once, on a transport in query mode; it is what makes a node a
// query-mode sender.
func (t *DNSTransport) ServeChunkQueries() error {
	if t.chunkStore == nil {
		return fmt.Errorf("ServeChunkQueries: the transport is not in query mode (no chunk store)")
	}
	store := t.chunkStore
	return tdns.RegisterQueryHandler(core.TypeCHUNK, func(ctx context.Context, req *tdns.DnsQueryRequest) error {
		return serveChunkQuery(req, store)
	})
}

// serveChunkQuery answers one CHUNK query from the store. The first label
// of the query name is the sequence number; the rest is the key.
func serveChunkQuery(req *tdns.DnsQueryRequest, store ChunkStore) error {
	if req.Qtype != core.TypeCHUNK {
		return tdns.ErrNotHandled
	}
	qname := dns.Fqdn(req.Qname)

	labels := dns.SplitDomainName(qname)
	if len(labels) < 4 {
		return tdns.ErrNotHandled
	}
	seq, err := strconv.ParseUint(labels[0], 10, 16)
	if err != nil {
		return tdns.ErrNotHandled
	}
	baseQname := dns.Fqdn(strings.Join(labels[1:], "."))
	chunk, ok := store.GetChunk(baseQname, uint16(seq))
	if !ok {
		return tdns.ErrNotHandled
	}
	lgTransport().Debug("serving chunk", "qname", qname, "seq", seq, "base", baseQname, "dataLen", len(chunk.Data))

	chunkRR := &dns.PrivateRR{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: core.TypeCHUNK,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Data: chunk,
	}
	m := new(dns.Msg)
	m.SetReply(req.Msg)
	m.Authoritative = true
	m.Answer = append(m.Answer, chunkRR)
	if err := req.ResponseWriter.WriteMsg(m); err != nil {
		lgTransport().Error("failed to write chunk response", "qname", qname, "err", err)
		return err
	}
	return nil
}

// manifestEnvelopeKey is the manifest metadata field that carries the
// payload's envelope label in query mode (the CHUNK records themselves are
// stamped with the splitter's format, not the payload's envelope).
const manifestEnvelopeKey = "envelope"

// envelopeFromManifest reads the payload's envelope label from a manifest's
// metadata; EnvelopeUnknown when the sender did not write one (a sender from
// before F2b), in which case the receiver falls back to the byte sniff.
func envelopeFromManifest(md *core.ManifestData) uint8 {
	if md == nil || md.Metadata == nil {
		return EnvelopeUnknown
	}
	switch v := md.Metadata[manifestEnvelopeKey].(type) {
	case float64: // JSON numbers decode as float64
		if v >= 0 && v <= 255 && v == float64(uint8(v)) {
			return uint8(v)
		}
	case uint8:
		return v
	case int:
		if v >= 0 && v <= 255 {
			return uint8(v)
		}
	}
	return EnvelopeUnknown
}
