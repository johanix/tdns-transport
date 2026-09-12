/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Where the receive pipeline's answer goes (cleanup plan, step 5). The
 * pipeline is the same for both mechanisms; only the sink differs: a DNS
 * response with the inline confirmation in an EDNS0 CHUNK option, or an
 * HTTP response body the application shapes.
 */

package transport

import (
	"encoding/json"
	"time"

	"github.com/miekg/dns"
)

// ReplySink receives the pipeline's answer to one message.
type ReplySink interface {
	// Reply answers a routed message: payload is the handler's inline
	// confirmation (or the default one) as plaintext JSON, rcode the DNS
	// rcode the pipeline settled on (NOERROR, REFUSED for an unsupported
	// verb, SERVFAIL for a handler error).
	Reply(ctx *MessageContext, payload []byte, rcode int) error
	// Fail answers a message the pipeline refused before routing it
	// (FORMERR, REFUSED, SERVFAIL); there is no context and no payload.
	Fail(rcode int) error
}

// dnsReply answers a NOTIFY(CHUNK) on its dns.ResponseWriter, encrypting
// the inline confirmation for the sender when payload crypto is on.
type dnsReply struct {
	w   dns.ResponseWriter
	msg *dns.Msg
}

func (r dnsReply) Reply(ctx *MessageContext, payload []byte, rcode int) error {
	if payload == nil {
		return sendStandardResponse(r.w, r.msg, rcode)
	}
	payload, format := encryptResponsePayload(ctx, payload)
	return sendChunkResponse(r.w, r.msg, payload, format, rcode)
}

func (r dnsReply) Fail(rcode int) error {
	return sendStandardResponse(r.w, r.msg, rcode)
}

// replyMiddleware runs the handler chain and hands the answer to the sink.
// It is the outermost middleware: the handlers' inline confirmation, or
// the default one for a verb whose handler prepared none, goes out after
// everything else has run.
func replyMiddleware(sink ReplySink) MiddlewareFunc {
	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		err := next(ctx)

		rcode := dns.RcodeSuccess
		if err != nil {
			lgTransport().Error("handler error", "err", err)
			rcode = dns.RcodeServerFailure
		}

		// An explicit rcode (set by the default handler, etc.) wins
		if rc, ok := ctx.responseRcode(); ok {
			rcode = rc
		}

		// The handler's own response payload (the inline confirmation)
		if payload, ok := ctx.responsePayload(); ok {
			return sink.Reply(ctx, payload, rcode)
		}

		// A generic confirmation for every other successfully handled
		// message: the sender requires one to distinguish "received and
		// processed" from a bare DNS ACK, which any DNS server could give.
		if rcode == dns.RcodeSuccess {
			confirmPayload := struct {
				Type           string `json:"type"`
				DistributionID string `json:"distribution_id"`
				Status         string `json:"status"`
				Message        string `json:"message"`
				Timestamp      int64  `json:"timestamp"`
			}{
				Type:           "confirm",
				DistributionID: ctx.DistributionID,
				Status:         "ok",
				Message:        "received",
				Timestamp:      time.Now().Unix(),
			}
			if payloadBytes, marshalErr := json.Marshal(confirmPayload); marshalErr == nil {
				return sink.Reply(ctx, payloadBytes, rcode)
			}
		}
		return sink.Reply(ctx, nil, rcode)
	}
}

// SendResponseMiddleware is replyMiddleware with the DNS sink: it sends the
// DNS response after all handlers complete.
func SendResponseMiddleware(w dns.ResponseWriter, msg *dns.Msg) MiddlewareFunc {
	return replyMiddleware(dnsReply{w: w, msg: msg})
}
