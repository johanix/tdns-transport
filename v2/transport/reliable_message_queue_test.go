/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The reliable queue keeps a delivered message until the recipient's
 * final confirmation, and sends it again, same ID and nonce, when that
 * confirmation does not come.
 */
package transport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

const testConfirmTimeout = 80 * time.Millisecond

func testQueueConfig() *ReliableMessageQueueConfig {
	return &ReliableMessageQueueConfig{
		ProcessInterval: 5 * time.Millisecond,
		BaseBackoff:     10 * time.Millisecond,
		MaxBackoff:      20 * time.Millisecond,
		ConfirmTimeout:  testConfirmTimeout,
		MaxConfirmWait:  4 * testConfirmTimeout,
	}
}

// sendRecorder stands in for the application's send function.
type sendRecorder struct {
	mu     sync.Mutex
	sent   []OutgoingMessage
	fail   error
	onSend func(msg *OutgoingMessage)
}

func (r *sendRecorder) send(_ context.Context, msg *OutgoingMessage) error {
	r.mu.Lock()
	r.sent = append(r.sent, *msg)
	fail := r.fail
	onSend := r.onSend
	r.mu.Unlock()
	if onSend != nil {
		onSend(msg)
	}
	return fail
}

func (r *sendRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sent)
}

func (r *sendRecorder) nth(i int) OutgoingMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sent[i]
}

func startQueue(t *testing.T, cfg *ReliableMessageQueueConfig, send func(context.Context, *OutgoingMessage) error) *ReliableMessageQueue {
	t.Helper()
	q := NewReliableMessageQueue(cfg)
	q.setSendFunc(send)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		q.Start(ctx)
		close(stopped)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Error("the queue did not stop within 2s of its context being cancelled")
		}
	})
	return q
}

// snapshot returns the queue's view of a message, or nil when the queue
// no longer holds it.
func snapshot(q *ReliableMessageQueue, distID string) *PendingMessageInfo {
	for _, m := range q.GetPendingMessages() {
		if m.DistributionID == distID {
			return &m
		}
	}
	return nil
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("%s: not within %v", what, timeout)
}

func enqueue(t *testing.T, q *ReliableMessageQueue, distID string) {
	t.Helper()
	if err := q.Enqueue(&OutgoingMessage{DistributionID: distID, RecipientID: "agent.example.", Zone: "example."}); err != nil {
		t.Fatal(err)
	}
}

func TestADeliveredMessageWaitsForTheFinalConfirmation(t *testing.T) {
	rec := &sendRecorder{}
	q := startQueue(t, testQueueConfig(), rec.send)
	enqueue(t, q, "d1")

	waitFor(t, "the first send", time.Second, func() bool { return rec.count() == 1 })
	waitFor(t, "the message parked awaiting its confirmation", time.Second, func() bool {
		return q.GetStats().ByState[MessageAwaitingConfirm.String()] == 1
	})
	if !q.MarkConfirmed("d1", "agent.example.") {
		t.Fatal("the final confirmation found no message in the queue")
	}
	st := q.GetStats()
	if st.TotalPending != 0 || st.TotalDelivered != 1 || st.TotalResent != 0 {
		t.Fatalf("after the confirmation: pending %d, delivered %d, resent %d", st.TotalPending, st.TotalDelivered, st.TotalResent)
	}
	time.Sleep(3 * testConfirmTimeout)
	if n := rec.count(); n != 1 {
		t.Fatalf("a confirmed message was sent again: %d sends", n)
	}
}

func TestAnUnconfirmedMessageGoesAgainUnderTheSameIdAndNonce(t *testing.T) {
	rec := &sendRecorder{}
	q := startQueue(t, testQueueConfig(), rec.send)
	enqueue(t, q, "d2")

	waitFor(t, "the first send", time.Second, func() bool { return rec.count() >= 1 })
	first := time.Now()
	waitFor(t, "the resend", 2*time.Second, func() bool { return rec.count() >= 2 })
	if elapsed := time.Since(first); elapsed < testConfirmTimeout/2 {
		t.Fatalf("resent after %v, well before the confirm timeout %v", elapsed, testConfirmTimeout)
	}
	a, b := rec.nth(0), rec.nth(1)
	if a.DistributionID != b.DistributionID || a.Nonce != b.Nonce || b.Nonce == "" {
		t.Fatalf("the resend is not the same message: %q/%q then %q/%q", a.DistributionID, a.Nonce, b.DistributionID, b.Nonce)
	}
	// The recorded send completes in the queue a moment after the
	// recorder saw it: wait for the queue's own view.
	waitFor(t, "the resend parked awaiting its confirmation", time.Second, func() bool {
		s := snapshot(q, "d2")
		return s != nil && s.AttemptCount == 2 && s.State == MessageAwaitingConfirm.String()
	})
	st := q.GetStats()
	if st.TotalResent != 1 || st.TotalDelivered != 0 {
		t.Fatalf("after one resend: resent %d, delivered %d", st.TotalResent, st.TotalDelivered)
	}
	if s := snapshot(q, "d2"); s.Resends != 1 || s.AttemptCount != 2 {
		t.Fatalf("pending snapshot after the resend: %+v", *s)
	}

	// The second wait is twice the first.
	second := time.Now()
	waitFor(t, "the second resend", 3*time.Second, func() bool { return rec.count() >= 3 })
	if elapsed := time.Since(second); elapsed < testConfirmTimeout {
		t.Fatalf("second resend after %v; the wait should have doubled past %v", elapsed, testConfirmTimeout)
	}

	// The final word, whenever it comes, closes the message for good.
	if !q.MarkConfirmed("d2", "agent.example.") {
		t.Fatal("the late confirmation found no message")
	}
	sends := rec.count()
	time.Sleep(3 * testConfirmTimeout)
	if rec.count() != sends {
		t.Fatalf("sent again after the confirmation: %d then %d", sends, rec.count())
	}
}

func TestAPendingFromTheRecipientStartsTheWaitOver(t *testing.T) {
	rec := &sendRecorder{}
	q := startQueue(t, testQueueConfig(), rec.send)
	enqueue(t, q, "d3")

	waitFor(t, "the first send", time.Second, func() bool { return rec.count() == 1 })
	waitFor(t, "the message parked awaiting its confirmation", time.Second, func() bool {
		return q.GetStats().ByState[MessageAwaitingConfirm.String()] == 1
	})

	// The recipient keeps saying "still working" for well past the timeout.
	end := time.Now().Add(3 * testConfirmTimeout)
	for time.Now().Before(end) {
		if !q.MarkPending("d3", "agent.example.") {
			t.Fatal("the pending found no message")
		}
		time.Sleep(testConfirmTimeout / 4)
	}
	if n := rec.count(); n != 1 {
		t.Fatalf("sent again while the recipient kept answering pending: %d sends", n)
	}

	// Silence after that, and the message goes again.
	waitFor(t, "the resend once the pendings stopped", 2*time.Second, func() bool { return rec.count() == 2 })
}

func TestAConfirmationDuringTheSendClosesTheMessage(t *testing.T) {
	rec := &sendRecorder{}
	var q *ReliableMessageQueue
	rec.onSend = func(msg *OutgoingMessage) { q.MarkConfirmed(msg.DistributionID, msg.RecipientID) }
	q = startQueue(t, testQueueConfig(), rec.send)
	enqueue(t, q, "d4")

	waitFor(t, "the send", time.Second, func() bool { return rec.count() == 1 })
	waitFor(t, "the message closed", time.Second, func() bool { return q.GetStats().TotalPending == 0 })
	time.Sleep(2 * testConfirmTimeout)
	st := q.GetStats()
	if n := rec.count(); n != 1 || st.TotalDelivered != 1 || st.TotalResent != 0 {
		t.Fatalf("sends %d, delivered %d, resent %d", n, st.TotalDelivered, st.TotalResent)
	}
}

func TestAPendingParksAMessageWhoseSendFailed(t *testing.T) {
	rec := &sendRecorder{fail: errors.New("notify timed out")}
	cfg := testQueueConfig()
	cfg.BaseBackoff = time.Second // no retry during the test
	cfg.MaxBackoff = time.Second
	q := startQueue(t, cfg, rec.send)
	enqueue(t, q, "d5")

	waitFor(t, "the failed send", time.Second, func() bool { return rec.count() == 1 })
	waitFor(t, "the message queued for a retry", time.Second, func() bool {
		return q.GetStats().ByState[MessageQueued.String()] == 1
	})
	// The recipient answers pending anyway: it has the message.
	if !q.MarkPending("d5", "agent.example.") {
		t.Fatal("the pending found no message")
	}
	info := q.GetPendingMessages()
	if len(info) != 1 || info[0].State != MessageAwaitingConfirm.String() || info[0].LastError == "" {
		t.Fatalf("after the pending: %+v", info)
	}
}

func TestAPendingDuringAFailedSendParksTheMessage(t *testing.T) {
	// The recipient's PENDING arrives while the send is in flight, and the
	// send's own answer is then lost: the recipient has the message.
	rec := &sendRecorder{fail: errors.New("notify response timed out")}
	var q *ReliableMessageQueue
	rec.onSend = func(msg *OutgoingMessage) { q.MarkPending(msg.DistributionID, msg.RecipientID) }
	cfg := testQueueConfig()
	cfg.BaseBackoff = 10 * time.Millisecond // a retry would come fast, were one scheduled
	cfg.MaxBackoff = 10 * time.Millisecond
	q = startQueue(t, cfg, rec.send)
	enqueue(t, q, "d6")

	waitFor(t, "the failed send", time.Second, func() bool { return rec.count() == 1 })
	waitFor(t, "the message parked awaiting its confirmation", time.Second, func() bool {
		s := snapshot(q, "d6")
		return s != nil && s.State == MessageAwaitingConfirm.String()
	})
	time.Sleep(testConfirmTimeout / 2)
	if n := rec.count(); n != 1 {
		t.Fatalf("retried after a PENDING: %d sends", n)
	}
	if s := snapshot(q, "d6"); s == nil || s.LastError == "" {
		t.Fatalf("the failed send's error is not kept: %+v", s)
	}
	if !q.MarkConfirmed("d6", "agent.example.") {
		t.Fatal("the final confirmation found no message")
	}
}

func TestTheConfirmWaitDoublesPerResendUpToTheCap(t *testing.T) {
	q := NewReliableMessageQueue(&ReliableMessageQueueConfig{ConfirmTimeout: time.Minute, MaxConfirmWait: 5 * time.Minute})
	for _, tc := range []struct {
		resends int
		want    time.Duration
	}{{0, time.Minute}, {1, 2 * time.Minute}, {2, 4 * time.Minute}, {3, 5 * time.Minute}, {10, 5 * time.Minute}} {
		if got := q.confirmWait(&pendingMessage{Resends: tc.resends}); got != tc.want {
			t.Errorf("after %d resends the wait is %v, want %v", tc.resends, got, tc.want)
		}
	}
	def := NewReliableMessageQueue(&ReliableMessageQueueConfig{})
	if def.confirmTimeout != 2*time.Minute || def.maxConfirmWait != 15*time.Minute {
		t.Errorf("defaults: confirm timeout %v, max wait %v", def.confirmTimeout, def.maxConfirmWait)
	}
}
