/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The reliable queue sends to each recipient on its own: a recipient
 * that does not answer holds back only its own messages, and each
 * recipient gets its messages one at a time, in the order they were
 * queued.
 */
package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func enqueueTo(t *testing.T, q *ReliableMessageQueue, distID, recipient string) {
	t.Helper()
	if err := q.Enqueue(&OutgoingMessage{DistributionID: distID, RecipientID: recipient, Zone: "example."}); err != nil {
		t.Fatal(err)
	}
}

// laneRecorder records, per recipient, the order of the sends and how
// many were in flight at once, for the recipient and over all.
type laneRecorder struct {
	mu          sync.Mutex
	order       map[string][]string
	inflight    map[string]int
	maxPerPeer  int
	total       int
	maxTotal    int
	sendLatency time.Duration
}

func newLaneRecorder(latency time.Duration) *laneRecorder {
	return &laneRecorder{order: map[string][]string{}, inflight: map[string]int{}, sendLatency: latency}
}

func (r *laneRecorder) send(_ context.Context, msg *OutgoingMessage) error {
	r.mu.Lock()
	r.order[msg.RecipientID] = append(r.order[msg.RecipientID], msg.DistributionID)
	r.inflight[msg.RecipientID]++
	r.maxPerPeer = max(r.maxPerPeer, r.inflight[msg.RecipientID])
	r.total++
	r.maxTotal = max(r.maxTotal, r.total)
	r.mu.Unlock()

	time.Sleep(r.sendLatency)

	r.mu.Lock()
	r.inflight[msg.RecipientID]--
	r.total--
	r.mu.Unlock()
	return nil
}

func (r *laneRecorder) sentTo(recipient string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.order[recipient]...)
}

func TestAFrozenRecipientDoesNotHoldBackTheOthers(t *testing.T) {
	const frozen = "auditor.example."
	others := []string{"combiner.example.", "agent2.example.", "agent3.example."}

	cfg := testQueueConfig()
	cfg.ProcessInterval = 50 * time.Millisecond
	cfg.ConfirmTimeout = time.Minute // no resends during the test
	cfg.MaxConfirmWait = time.Minute

	frozenStarted := make(chan struct{}, 1)
	thaw := make(chan struct{})
	var frozenSends atomic.Int32
	var mu sync.Mutex
	sentAt := map[string]time.Time{}

	send := func(ctx context.Context, msg *OutgoingMessage) error {
		if msg.RecipientID == frozen {
			frozenSends.Add(1)
			select {
			case frozenStarted <- struct{}{}:
			default:
			}
			select {
			case <-thaw:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		mu.Lock()
		sentAt[msg.DistributionID] = time.Now()
		mu.Unlock()
		return nil
	}
	q := startQueue(t, cfg, send)

	enqueueTo(t, q, "frozen-1", frozen)
	select {
	case <-frozenStarted:
	case <-time.After(time.Second):
		t.Fatal("the send to the frozen recipient never started")
	}

	// The frozen recipient's send is now in flight. A second message for
	// it waits behind the first; the other recipients' messages do not.
	enqueueTo(t, q, "frozen-2", frozen)
	queued := time.Now()
	for i, r := range others {
		enqueueTo(t, q, fmt.Sprintf("other-%d", i), r)
	}

	// The next tick sends them. The limit leaves room for a slow
	// scheduler; the frozen send stays blocked throughout.
	limit := 5 * cfg.ProcessInterval
	waitFor(t, "the other recipients' messages", limit, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sentAt) == len(others)
	})
	mu.Lock()
	for id, at := range sentAt {
		if d := at.Sub(queued); d > limit {
			t.Errorf("%s went %v after it was queued", id, d)
		}
	}
	mu.Unlock()

	// Meanwhile the frozen recipient is still on its first message.
	time.Sleep(2 * cfg.ProcessInterval)
	if n := frozenSends.Load(); n != 1 {
		t.Fatalf("%d sends started to the frozen recipient while its first was in flight", n)
	}

	// Thawed, it gets its second message.
	close(thaw)
	waitFor(t, "the frozen recipient's second message", time.Second, func() bool { return frozenSends.Load() == 2 })
}

func TestARecipientsMessagesGoOneAtATimeInTheOrderTheyWereQueued(t *testing.T) {
	recipients := []string{"combiner.example.", "agent2.example.", "agent3.example."}
	const perWave = 10

	cfg := testQueueConfig()
	cfg.ConfirmTimeout = time.Minute // no resends during the test
	cfg.MaxConfirmWait = time.Minute
	rec := newLaneRecorder(time.Millisecond)
	q := startQueue(t, cfg, rec.send)

	want := map[string][]string{}
	wave := func(w int) {
		for i := 0; i < perWave; i++ {
			for _, r := range recipients {
				id := fmt.Sprintf("%s-w%d-%02d", r, w, i)
				want[r] = append(want[r], id)
				enqueueTo(t, q, id, r)
			}
		}
	}
	wave(1)
	// The second wave arrives while the first is still going out.
	waitFor(t, "the first sends", time.Second, func() bool { return len(rec.sentTo(recipients[0])) > 0 })
	wave(2)

	for _, r := range recipients {
		waitFor(t, "all of "+r+"'s messages", 2*time.Second, func() bool { return len(rec.sentTo(r)) == len(want[r]) })
	}
	for _, r := range recipients {
		got := rec.sentTo(r)
		for i := range want[r] {
			if got[i] != want[r][i] {
				t.Fatalf("%s got its messages out of order: send %d was %s, want %s\n got  %v\n want %v", r, i, got[i], want[r][i], got, want[r])
			}
		}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.maxPerPeer != 1 {
		t.Errorf("up to %d sends were in flight to one recipient at once, want 1", rec.maxPerPeer)
	}
	if rec.maxTotal < 2 {
		t.Errorf("no two recipients were ever sent to at once (max in flight %d)", rec.maxTotal)
	}
}

func TestTheNumberOfSendsInFlightIsBounded(t *testing.T) {
	const bound = 2
	recipients := []string{"r1.example.", "r2.example.", "r3.example.", "r4.example.", "r5.example."}

	cfg := testQueueConfig()
	cfg.ConfirmTimeout = time.Minute
	cfg.MaxConfirmWait = time.Minute
	cfg.MaxConcurrentSends = bound

	thaw := make(chan struct{})
	var inflight, maxInflight, started atomic.Int32
	send := func(ctx context.Context, msg *OutgoingMessage) error {
		started.Add(1)
		n := inflight.Add(1)
		for {
			m := maxInflight.Load()
			if n <= m || maxInflight.CompareAndSwap(m, n) {
				break
			}
		}
		defer inflight.Add(-1)
		select {
		case <-thaw:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	q := startQueue(t, cfg, send)
	for i, r := range recipients {
		enqueueTo(t, q, fmt.Sprintf("d%d", i), r)
	}

	waitFor(t, "the first sends", time.Second, func() bool { return started.Load() == bound })
	time.Sleep(10 * cfg.ProcessInterval) // ticks enough to start more, were more allowed
	if n := started.Load(); n != bound {
		t.Fatalf("%d sends started with a bound of %d", n, bound)
	}

	close(thaw)
	waitFor(t, "every recipient's send", time.Second, func() bool { return started.Load() == int32(len(recipients)) })
	if m := maxInflight.Load(); m > bound {
		t.Fatalf("%d sends were in flight at once with a bound of %d", m, bound)
	}
	waitFor(t, "every message delivered", time.Second, func() bool {
		return q.GetStats().ByState[MessageAwaitingConfirm.String()] == len(recipients)
	})
}

func TestANonPositiveSendBoundGetsTheDefault(t *testing.T) {
	for _, n := range []int{0, -1} {
		q := NewReliableMessageQueue(&ReliableMessageQueueConfig{MaxConcurrentSends: n})
		if q.maxConcurrent != 16 || cap(q.sendSlots) != 16 {
			t.Errorf("MaxConcurrentSends %d: bound %d, %d slots, want the default 16", n, q.maxConcurrent, cap(q.sendSlots))
		}
	}
}

func TestShutdownWaitsForTheSendsInFlightAndStartsNoMore(t *testing.T) {
	recipients := []string{"r1.example.", "r2.example.", "r3.example."}

	cfg := testQueueConfig()
	cfg.ConfirmTimeout = time.Minute
	cfg.MaxConfirmWait = time.Minute
	q := NewReliableMessageQueue(cfg)

	var inflight, started atomic.Int32
	q.setSendFunc(func(ctx context.Context, msg *OutgoingMessage) error {
		started.Add(1)
		inflight.Add(1)
		defer inflight.Add(-1)
		<-ctx.Done()
		time.Sleep(20 * time.Millisecond) // a send that takes a moment to wind down
		return errors.New("cancelled")
	})
	// Two messages per recipient: the second waits behind the first.
	for i, r := range recipients {
		enqueueTo(t, q, fmt.Sprintf("first-%d", i), r)
		enqueueTo(t, q, fmt.Sprintf("second-%d", i), r)
	}

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		q.Start(ctx)
		close(stopped)
	}()
	waitFor(t, "a send in flight to every recipient", time.Second, func() bool { return inflight.Load() == int32(len(recipients)) })

	cancel()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("the queue did not stop within 2s of its context being cancelled")
	}
	if n := inflight.Load(); n != 0 {
		t.Fatalf("the queue stopped with %d sends still in flight", n)
	}
	if n := started.Load(); n != int32(len(recipients)) {
		t.Fatalf("%d sends started, want one per recipient: none after the cancel", n)
	}
	for _, m := range q.GetPendingMessages() {
		if m.State == MessageSending.String() {
			t.Errorf("%s for %s is left in state %s", m.DistributionID, m.RecipientID, m.State)
		}
	}
}
