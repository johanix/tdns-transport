package transport

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/distrib"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// notifySeen is what a peer saw in one NOTIFY: its CHUNK payload, if it had
// one, and its CHUNK query endpoint, if it named one.
type notifySeen struct {
	payload  []byte
	inline   bool
	endpoint string
}

// notifyPeer answers every NOTIFY with NOERROR and keeps what it saw.
type notifyPeer struct {
	addr *Address
	mu   sync.Mutex
	seen []notifySeen
}

func newNotifyPeer(t *testing.T) *notifyPeer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &notifyPeer{addr: &Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp"}}
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		var s notifySeen
		if opt := r.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				local, ok := o.(*dns.EDNS0_LOCAL)
				if !ok {
					continue
				}
				switch local.Code {
				case edns0.EDNS0_CHUNK_OPTION_CODE:
					if chunk, err := edns0.ParseChunkOption(local); err == nil {
						s.payload, s.inline = chunk.Data, true
					}
				case edns0.EDNS0_CHUNK_QUERY_ENDPOINT_CODE:
					s.endpoint = string(local.Data)
				}
			}
		}
		p.mu.Lock()
		p.seen = append(p.seen, s)
		p.mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})
	return p
}

func (p *notifyPeer) last(t *testing.T) notifySeen {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.seen) == 0 {
		t.Fatal("the peer saw no NOTIFY")
	}
	return p.seen[len(p.seen)-1]
}

// stored is the payload the transport keeps for peerID and distributionID,
// put together from its CHUNK records as a receiver does (fetchChunkViaQuery).
func stored(t *testing.T, dt *DNSTransport, peerID, distributionID string) []byte {
	t.Helper()
	key := buildChunkQueryQname(peerID, distributionID, dt.ControlZone)
	manifest, ok := dt.ChunkStore().GetChunk(key, 0)
	if !ok {
		t.Fatalf("no manifest stored under %s", key)
	}
	md, err := core.ExtractManifestData(manifest)
	if err != nil {
		t.Fatalf("the manifest: %v", err)
	}
	if md.ChunkCount == 0 {
		return md.Payload
	}
	var chunks []*core.CHUNK
	for i := uint16(1); i <= md.ChunkCount; i++ {
		c, ok := dt.ChunkStore().GetChunk(key, i)
		if !ok {
			t.Fatalf("chunk %d of %d is not stored", i, md.ChunkCount)
		}
		chunks = append(chunks, c)
	}
	payload, err := distrib.ReassembleCHUNKs(chunks)
	if err != nil {
		t.Fatalf("reassembling the chunks: %v", err)
	}
	return payload
}

func payloadOf(n int) []byte {
	return bytes.Repeat([]byte("x"), n)
}

// A NOTIFY payload rides inline while it fits one DNS message, and goes by
// query when it does not: when the CHUNK option cannot hold it (70,000
// bytes, #987), and when the option can but the NOTIFY with it would pass
// 65,535 bytes (65,520). The receiver finds the payload in the sender's
// CHUNK records, and the NOTIFY names the sender's query endpoint.
func TestAPayloadThatDoesNotFitOneDNSMessageIsSentByQuery(t *testing.T) {
	const endpoint = "127.0.0.1:5399"
	for _, c := range []struct {
		size    int
		byQuery bool
	}{
		{65000, false},
		{65520, true},
		{70000, true},
	} {
		peer := newNotifyPeer(t)
		p := NewPeer("b.example.")
		setDNSCarrier(t, p, peer.addr)
		dt := NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example.",
			Timeout: 2 * time.Second, ChunkQueryEndpoint: endpoint})
		id := GenerateDistributionID()
		payload := payloadOf(c.size)
		if err := dt.sendNotifyUnconfirmed(context.Background(), p, peer.addr, dt.buildNotifyQNAME(id), id, "status", payload); err != nil {
			t.Fatalf("%d bytes: %v", c.size, err)
		}
		seen := peer.last(t)
		if !c.byQuery {
			if !seen.inline || !bytes.Equal(seen.payload, payload) {
				t.Errorf("%d bytes: not inline and whole (inline %v, %d bytes)", c.size, seen.inline, len(seen.payload))
			}
			continue
		}
		if seen.inline {
			t.Errorf("%d bytes: sent inline (%d bytes), want by query", c.size, len(seen.payload))
		}
		if seen.endpoint != endpoint {
			t.Errorf("%d bytes: the NOTIFY names endpoint %q, want %q", c.size, seen.endpoint, endpoint)
		}
		if got := stored(t, dt, p.ID, id); !bytes.Equal(got, payload) {
			t.Errorf("%d bytes: the stored records hold %d bytes", c.size, len(got))
		}
	}
}

// A confirmation that does not fit one DNS message goes by query too, with
// every applied record in it.
func TestAConfirmationTooLargeForOneMessageIsSentByQuery(t *testing.T) {
	peer := newNotifyPeer(t)
	p := NewPeer("b.example.")
	setDNSCarrier(t, p, peer.addr)
	dt := NewDNSTransport(&DNSTransportConfig{LocalID: "a.example.", ControlZone: "control.example.", Timeout: 2 * time.Second})
	req := testConfirmRequest()
	const many = 3000
	for range many {
		req.AppliedRecords = append(req.AppliedRecords, "applied.example. 3600 IN TXT \"a record applied, one of many\"")
	}
	if err := dt.Confirm(context.Background(), p, req); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if seen := peer.last(t); seen.inline {
		t.Fatalf("a %d-byte confirmation was sent inline", len(seen.payload))
	}
	got := stored(t, dt, p.ID, req.DistributionID)
	if n := bytes.Count(got, []byte("one of many")); n != many {
		t.Errorf("the stored confirmation has %d of the %d applied records", n, many)
	}
}

// A reply cannot be fetched by query: one that does not fit one DNS message
// is answered with SERVFAIL, not sent cut.
func TestAReplyTooLargeForOneMessageIsRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		_ = sendChunkResponse(w, r, payloadOf(70000), EnvelopeNone, dns.RcodeSuccess)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	m := new(dns.Msg)
	m.SetNotify("reply.example.")
	c := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	res, _, err := c.Exchange(m, ln.Addr().String())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if res.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode %s, want SERVFAIL", dns.RcodeToString[res.Rcode])
	}
	if opt := res.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if l, ok := o.(*dns.EDNS0_LOCAL); ok && l.Code == edns0.EDNS0_CHUNK_OPTION_CODE {
				t.Errorf("the refusal carries a CHUNK option of %d bytes", len(l.Data))
			}
		}
	}
}
