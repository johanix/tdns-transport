/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Inline, or by query (tdns #987). A payload rides in its message's EDNS0
 * CHUNK option while the option can hold it and the message fits one DNS
 * message. A NOTIFY whose payload does not is sent in query mode instead:
 * the transport keeps the payload's CHUNK records and the receiver asks for
 * them, as it does of a sender in query mode. A reply cannot be fetched
 * that way; one that does not fit is refused.
 */

package transport

import (
	"errors"
	"fmt"

	"github.com/johanix/tdns-transport/v2/distrib"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// edns0Of is m's OPT RR, made with a 4096-byte UDP size and the DO bit when
// m has none.
func edns0Of(m *dns.Msg) *dns.OPT {
	if opt := m.IsEdns0(); opt != nil {
		return opt
	}
	m.SetEdns0(4096, true)
	return m.IsEdns0()
}

// attachChunkPayload adds payload to m as a CHUNK option and reports
// whether m then fits one DNS message. When the option cannot hold the
// payload (edns0.ErrChunkOptionTooLarge), or m with it would pass
// dns.MaxMsgSize, m is left without it and fits is false. Any other error
// is returned. m gets an OPT RR if it has none.
func attachChunkPayload(m *dns.Msg, format uint8, payload []byte) (fits bool, err error) {
	chunk, err := edns0.CreateChunkOption(format, nil, payload)
	if errors.Is(err, edns0.ErrChunkOptionTooLarge) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	opt := edns0Of(m)
	opt.Option = append(opt.Option, chunk)
	if m.Len() > dns.MaxMsgSize {
		opt.Option = opt.Option[:len(opt.Option)-1]
		return false, nil
	}
	return true, nil
}

// sendByQuery readies this transport to send a payload by query when it is
// not in query mode: the handler that answers CHUNK queries for its stored
// records, registered once (ServeChunkQueries).
func (t *DNSTransport) sendByQuery(peerID, opType string, size int) error {
	if err := t.ServeChunkQueries(); err != nil {
		return err
	}
	lgTransport().Info("a payload too large for one DNS message is sent by query",
		"peer", peerID, "op", opType, "bytes", size)
	return nil
}

// placeChunkPayload puts payload into m, a NOTIFY to peerID: inline, in a
// CHUNK option, when inlineFirst and it fits one DNS message; otherwise by
// query, its CHUNK records stored under the receiver's query name for the
// receiver to ask for. The CHUNK query endpoint goes into m when configured
// and either configured into NOTIFYs or forced, and always when the payload
// goes by query only because it does not fit.
func (t *DNSTransport) placeChunkPayload(m *dns.Msg, peerID, opType, distributionID string, format uint8, payload []byte, inlineFirst, forceEndpoint bool) error {
	if inlineFirst {
		fits, err := attachChunkPayload(m, format, payload)
		if err != nil {
			return fmt.Errorf("the CHUNK option: %w", err)
		}
		if fits {
			return nil
		}
		if err := t.sendByQuery(peerID, opType, len(payload)); err != nil {
			return fmt.Errorf("a payload of %d bytes does not fit one DNS message and cannot be sent by query: %w", len(payload), err)
		}
		forceEndpoint = true
	}
	// The manifest names the payload's envelope.
	chunks, err := distrib.PrepareDistributionChunks(payload, opType, distributionID, peerID, nil, t.chunkMaxSize,
		map[string]interface{}{manifestEnvelopeKey: format})
	if err != nil {
		return fmt.Errorf("failed to prepare distribution chunks: %w", err)
	}
	t.chunkStore.SetChunks(buildChunkQueryQname(peerID, distributionID, t.ControlZone), chunks)
	if t.chunkQueryEndpoint != "" && (t.chunkQueryEndpointInNotify || forceEndpoint) {
		opt := edns0Of(m)
		opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
			Code: edns0.EDNS0_CHUNK_QUERY_ENDPOINT_CODE,
			Data: []byte(t.chunkQueryEndpoint),
		})
	}
	return nil
}
