/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The invariant on a peer's TLSA set (docs/2026-10-20-https-peer-tlsa-
 * verification.md), against every interleaving of its two writers'
 * lookups: discovery of the name held and of a new one (a moved endpoint),
 * and two checks, each answering found, withdrawn or failed.
 */

package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const (
	answerFound = iota
	answerWithdrawn
	answerFailed
)

var answerNames = []string{"found", "withdrawn", "failed"}

// tlsaWriter is one of the processes: a discovery of name, or a check.
type tlsaWriter struct {
	discovery bool
	name      string // a discovery's name; a check looks up the name held
	answer    int
}

func (w tlsaWriter) String() string {
	if w.discovery {
		return fmt.Sprintf("discovery(%s)=%s", w.name[:strings.Index(w.name, ".")], answerNames[w.answer])
	}
	return "check=" + answerNames[w.answer]
}

// tlsaLookupLog is what the spec needs of one lookup.
type tlsaLookupLog struct {
	writer  tlsaWriter
	name    string // the name looked up
	seq     uint64 // its number, taken when it started
	records []*dns.TLSA
	storeAt int // the event at which its answer was stored, or refused
}

// interleavings returns every order of n processes' two events each, as
// process indices: a process's first event is its start, its second its end.
func interleavings(n int) [][]int {
	var out [][]int
	left := make([]int, n)
	for i := range left {
		left[i] = 2
	}
	var walk func(prefix []int)
	walk = func(prefix []int) {
		if len(prefix) == 2*n {
			out = append(out, append([]int(nil), prefix...))
			return
		}
		for p := range left {
			if left[p] > 0 {
				left[p]--
				walk(append(prefix, p))
				left[p]++
			}
		}
	}
	walk(nil)
	return out
}

func tlsaRecordN(n int) *dns.TLSA {
	return &dns.TLSA{Hdr: dns.RR_Header{Rrtype: dns.TypeTLSA, Class: dns.ClassINET},
		Usage: 3, Selector: 1, MatchingType: 1, Certificate: fmt.Sprintf("%064x", n)}
}

func tlsaRecordsKey(records []*dns.TLSA) string {
	return tlsaKey(records)
}

// runTLSAInterleaving runs writers in order from a peer discovery left at
// the old name, and returns a description of how the end state breaks the
// invariant, or "".
func runTLSAInterleaving(writers []tlsaWriter, order []int, oldName, newName string) string {
	uri := map[string]string{
		oldName: "https://api.b.example.:443/api/v1",
		newName: "https://api.b.example.:8443/api/v1",
	}
	src := &stepTLSA{calls: make(chan chan fakeAnswer)}
	c := NewTLSAChecker(nil)
	c.source = src
	tm := &TransportManager{PeerRegistry: NewPeerRegistry()}
	result := func(name string, records []*dns.TLSA, failed bool, seq uint64) *DiscoveryResult {
		return &DiscoveryResult{Identity: "b.example.", APIUri: uri[name], APIAddresses: []string{"192.0.2.1"},
			TLSA: TLSASet{Owner: name, Records: records, Validated: true}, TLSAFailed: failed, tlsaSeq: seq}
	}
	initial := tlsaLookupLog{writer: tlsaWriter{discovery: true, name: oldName}, name: oldName,
		seq: nextTLSALookup(), records: []*dns.TLSA{tlsaRecordN(0)}, storeAt: -1}
	if err := tm.RegisterDiscoveredPeer(result(oldName, initial.records, false, initial.seq)); err != nil {
		return "initial registration: " + err.Error()
	}
	peer, _ := tm.PeerRegistry.Get("b.example.")

	logs := make([]tlsaLookupLog, len(writers))
	pending := make([]chan fakeAnswer, len(writers))
	done := make([]chan struct{}, len(writers))
	started := make([]bool, len(writers))
	for at, p := range order {
		w := writers[p]
		if !started[p] {
			started[p] = true
			logs[p].writer = w
			if w.discovery {
				logs[p].name = w.name
				logs[p].seq = nextTLSALookup()
				continue
			}
			logs[p].name = peer.MechanismTLSA("API").Owner
			done[p] = make(chan struct{})
			go func(d chan struct{}) {
				_, _ = c.Refresh(context.Background(), peer, "API")
				close(d)
			}(done[p])
			pending[p] = <-src.calls // the check has read the name and taken its number
			logs[p].seq = tlsaLookups.Load()
			continue
		}
		logs[p].storeAt = at
		var records []*dns.TLSA
		if w.answer == answerFound {
			records = []*dns.TLSA{tlsaRecordN(p + 1)}
			logs[p].records = records
		}
		if w.discovery {
			if err := tm.RegisterDiscoveredPeer(result(w.name, records, w.answer == answerFailed, logs[p].seq)); err != nil {
				return "registration: " + err.Error()
			}
			continue
		}
		switch w.answer {
		case answerFound:
			pending[p] <- fakeAnswer{ans: tlsaAnswer{Records: records, Validated: true}}
		case answerWithdrawn:
			pending[p] <- fakeAnswer{ans: tlsaAnswer{Denied: true, Validated: true}}
		default:
			pending[p] <- fakeAnswer{err: errors.New("SERVFAIL")}
		}
		<-done[p]
	}

	// The spec. Names change only at registrations: the name is the last
	// registration's, and the set is the move into it, or the answer of a
	// lookup of that name stored after the move that started later, whichever
	// started last. A failed lookup is no answer.
	name, move := oldName, initial
	var stores []tlsaLookupLog
	for at, p := range order {
		if logs[p].storeAt != at {
			continue
		}
		if logs[p].writer.discovery && logs[p].name != name {
			name, move, stores = logs[p].name, logs[p], nil
			continue
		}
		stores = append(stores, logs[p])
	}
	want := move
	for _, l := range stores {
		if l.name == name && l.writer.answer != answerFailed && l.seq > want.seq {
			want = l
		}
	}
	held := peer.MechanismTLSA("API")
	var broken []string
	if held.Owner != name {
		broken = append(broken, fmt.Sprintf("holds the set for %s, want %s", held.Owner, name))
	}
	if tlsaRecordsKey(held.Records) != tlsaRecordsKey(want.records) {
		broken = append(broken, fmt.Sprintf("holds records [%s], want [%s] (from %v)",
			tlsaRecordsKey(held.Records), tlsaRecordsKey(want.records), want.writer))
	}
	if got := peer.GetAPIEndpoint(); got != uri[name] {
		broken = append(broken, fmt.Sprintf("endpoint %s, want %s", got, uri[name]))
	}
	if usable := peer.APIUsable(); usable != (len(want.records) > 0) {
		broken = append(broken, fmt.Sprintf("API usable %v, want %v", usable, len(want.records) > 0))
	}
	return strings.Join(broken, "; ")
}

// The invariant holds in every interleaving of a discovery of the name
// held, a discovery of a new name, and two checks, each answering found,
// withdrawn or failed (3^4 answers × 2520 orders).
func TestTLSASetInvariantHoldsInEveryInterleaving(t *testing.T) {
	const oldName, newName = "_443._tcp.api.b.example.", "_8443._tcp.api.b.example."
	// Every withdrawal and failed lookup logs; 200,000 runs would drown
	// the test's output.
	defer slog.SetDefault(slog.Default())
	slog.SetDefault(slog.New(slog.DiscardHandler))
	orders := interleavings(4)
	runs, failures := 0, 0
	for a := 0; a < 81; a++ {
		writers := []tlsaWriter{
			{discovery: true, name: oldName, answer: a % 3},
			{discovery: true, name: newName, answer: a / 3 % 3},
			{answer: a / 9 % 3},
			{answer: a / 27 % 3},
		}
		for _, order := range orders {
			runs++
			if broken := runTLSAInterleaving(writers, order, oldName, newName); broken != "" {
				failures++
				if failures <= 5 {
					t.Errorf("%v in order %v: %s", writers, order, broken)
				}
			}
		}
	}
	if failures > 0 {
		t.Errorf("%d of %d interleavings break the invariant", failures, runs)
	}
}
