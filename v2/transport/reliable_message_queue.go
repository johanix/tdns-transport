/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Reliable message queue for transport-layer message delivery.
 *
 * Ensures that messages to recipients are delivered with retry-until-confirmed
 * semantics. Messages are queued immediately regardless of recipient state and
 * delivered when the recipient becomes ready. Failed deliveries are retried
 * with exponential backoff.
 *
 * A send that the recipient acknowledges is not the end of the message:
 * the acknowledgement only says the message arrived. The recipient's
 * final word (SUCCESS, FAILED, REJECTED or IGNORED) comes later as a
 * confirmation, and MarkConfirmed closes the entry. Until then the entry
 * waits, and when the wait runs out the same message, same distribution
 * ID and nonce, goes again, with the wait doubling up to a cap, until a
 * final confirmation or the message's expiry. A PENDING from the
 * recipient (MarkPending) starts the wait over. Recipients are idempotent
 * per distribution ID, so a repeat costs at worst an extra confirmation.
 *
 * See tdns/docs/reliable-message-delivery-architecture.md for full design.
 */
package transport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// MessageState tracks the delivery state of a queued message.
type MessageState uint8

const (
	MessageQueued          MessageState = iota // Waiting to be sent
	MessageSending                             // Send in progress
	MessageAwaitingConfirm                     // Sent, waiting for confirmation
	MessageConfirmed                           // Delivery confirmed
	MessageFailed                              // Permanently failed (expired or max retries)
)

var messageStateToString = map[MessageState]string{
	MessageQueued:          "QUEUED",
	MessageSending:         "SENDING",
	MessageAwaitingConfirm: "AWAITING_CONFIRM",
	MessageConfirmed:       "CONFIRMED",
	MessageFailed:          "FAILED",
}

func (s MessageState) String() string {
	if str, ok := messageStateToString[s]; ok {
		return str
	}
	return "UNKNOWN"
}

// MessagePriority determines delivery order when multiple messages are pending.
type MessagePriority uint8

const (
	PriorityHigh   MessagePriority = iota // High-priority updates (zone consistency)
	PriorityNormal                        // Normal updates
)

// OutgoingMessage represents a message to be delivered reliably.
type OutgoingMessage struct {
	DistributionID string          // Shared across all recipients for confirmation correlation
	RecipientID    string          // Who should receive this
	Zone           string          // Zone context
	Payload        interface{}     // Application-specific payload (passed through, never serialized)
	Priority       MessagePriority // Delivery priority
	CreatedAt      time.Time       // When enqueued
	ExpiresAt      time.Time       // When to give up
	Nonce          string          // Unique nonce for replay protection (generated at Enqueue time)
}

// pendingMessage wraps an OutgoingMessage with delivery state tracking.
type pendingMessage struct {
	Message      *OutgoingMessage
	State        MessageState
	AttemptCount int
	Resends      int  // Sends after the first, each for want of a final confirmation
	HeardPending bool // A PENDING from the recipient arrived while a send was in flight
	LastAttempt  time.Time
	NextAttempt  time.Time // Scheduled time for next delivery attempt
	LastError    string
}

// QueueStats provides visibility into the queue's current state.
type QueueStats struct {
	TotalPending   int            `json:"total_pending"`
	ByState        map[string]int `json:"by_state"`
	ByPriority     map[string]int `json:"by_priority"`
	TotalDelivered int            `json:"total_delivered"`
	TotalResent    int            `json:"total_resent"`
	TotalFailed    int            `json:"total_failed"`
	TotalExpired   int            `json:"total_expired"`
	OldestAge      time.Duration  `json:"oldest_age_seconds"`
}

// PendingMessageInfo is a JSON-serializable snapshot of a pending message for CLI display.
type PendingMessageInfo struct {
	DistributionID string `json:"distribution_id"`
	RecipientID    string `json:"recipient_id"`
	Zone           string `json:"zone"`
	Priority       string `json:"priority"`
	State          string `json:"state"`
	AttemptCount   int    `json:"attempt_count"`
	Resends        int    `json:"resends,omitempty"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"`
	NextAttempt    string `json:"next_attempt"`
	LastAttempt    string `json:"last_attempt,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	Age            string `json:"age"`
}

// pendingKey returns the composite map key for a message: "{recipientID}.{distID}".
// Mirrors the {recipientID}.{distID}.{senderID} structure used in CHUNK query qnames.
// This allows the same distID to be used for multiple recipients
// while keeping each delivery independently tracked in the queue.
func pendingKey(distID string, recipientID string) string {
	return recipientID + "." + distID
}

// ReliableMessageQueue ensures messages are delivered with retry-until-confirmed semantics.
//
// Messages are accepted immediately via Enqueue() regardless of recipient state.
// A background worker periodically processes the queue:
//   - Checks if recipient is ready before attempting delivery
//   - Sends via the configured sendFunc
//   - Retries with exponential backoff on failure
//   - Waits for the recipient's final confirmation (MarkConfirmed) and
//     sends the message again when the wait runs out
//   - Expires messages after a configurable timeout
type ReliableMessageQueue struct {
	mu sync.RWMutex

	// Pending messages indexed by "{recipientID}.{distID}" (see pendingKey())
	pending map[string]*pendingMessage

	// isRecipientReadyFn checks whether a recipient is ready to receive messages.
	// If nil, all recipients are considered ready.
	isRecipientReadyFn func(recipientID string) bool

	// sendFunc is called to actually deliver a message. Set by the caller
	// after queue creation to avoid circular dependency.
	// Returns nil on successful send (message is now awaiting confirmation).
	sendFunc func(ctx context.Context, msg *OutgoingMessage) error

	// Statistics
	totalDelivered int
	totalResent    int
	totalFailed    int
	totalExpired   int

	// Configuration
	baseBackoff       time.Duration // Initial retry interval (default: 2s)
	maxBackoff        time.Duration // Maximum retry interval (default: 60s)
	confirmTimeout    time.Duration // Wait for the final confirmation before sending again (default: 2m)
	maxConfirmWait    time.Duration // Cap on that wait as it doubles per resend (default: 15m)
	expirationTimeout time.Duration // How long to keep retrying (default: 24h)
	processInterval   time.Duration // How often to process the queue (default: 1s)
	maxQueueSize      int           // Maximum number of pending messages (default: 10000)
}

// ReliableMessageQueueConfig holds configuration for creating a queue.
type ReliableMessageQueueConfig struct {
	IsRecipientReady  func(recipientID string) bool
	BaseBackoff       time.Duration // Default: 2s
	MaxBackoff        time.Duration // Default: 60s
	ConfirmTimeout    time.Duration // Default: 2m; the wait for a final confirmation before a resend
	MaxConfirmWait    time.Duration // Default: 15m; the cap on that wait as it doubles
	ExpirationTimeout time.Duration // Default: 24h
	ProcessInterval   time.Duration // Default: 1s
	MaxQueueSize      int           // Default: 10000
}

// NewReliableMessageQueue creates a new queue with the given configuration.
func NewReliableMessageQueue(cfg *ReliableMessageQueueConfig) *ReliableMessageQueue {
	q := &ReliableMessageQueue{
		pending:            make(map[string]*pendingMessage),
		isRecipientReadyFn: cfg.IsRecipientReady,

		baseBackoff:       withDefault(cfg.BaseBackoff, 2*time.Second),
		maxBackoff:        withDefault(cfg.MaxBackoff, 60*time.Second),
		confirmTimeout:    withDefault(cfg.ConfirmTimeout, 2*time.Minute),
		maxConfirmWait:    withDefault(cfg.MaxConfirmWait, 15*time.Minute),
		expirationTimeout: withDefault(cfg.ExpirationTimeout, 24*time.Hour),
		processInterval:   withDefault(cfg.ProcessInterval, 1*time.Second),
		maxQueueSize:      withDefaultInt(cfg.MaxQueueSize, 10000),
	}

	return q
}

// setSendFunc sets the function used to deliver messages. Must be called before Start().
// This is set by the caller to avoid circular dependency at construction time.
func (q *ReliableMessageQueue) setSendFunc(f func(ctx context.Context, msg *OutgoingMessage) error) {
	q.sendFunc = f
}

// Start begins processing the queue. Runs until the context is cancelled.
func (q *ReliableMessageQueue) Start(ctx context.Context) {
	if q.sendFunc == nil {
		slog.Warn("reliable queue started without sendFunc, messages will not be delivered")
	}

	slog.Info("reliable queue starting", "baseBackoff", q.baseBackoff, "maxBackoff", q.maxBackoff, "confirmTimeout", q.confirmTimeout, "maxConfirmWait", q.maxConfirmWait, "expiration", q.expirationTimeout, "interval", q.processInterval)

	ticker := time.NewTicker(q.processInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			q.mu.RLock()
			remaining := len(q.pending)
			q.mu.RUnlock()
			slog.Info("reliable queue shutting down", "pending", remaining)
			return

		case <-ticker.C:
			q.processQueue(ctx)
		}
	}
}

// Enqueue adds a message to the queue for reliable delivery.
// Returns immediately. The message will be delivered asynchronously.
func (q *ReliableMessageQueue) Enqueue(msg *OutgoingMessage) error {
	if msg == nil {
		return fmt.Errorf("cannot enqueue nil message")
	}
	if msg.DistributionID == "" {
		return fmt.Errorf("message must have a DistributionID")
	}
	if msg.RecipientID == "" {
		return fmt.Errorf("message must have a RecipientID")
	}

	// H19: Ensure per-message TTL fields are populated
	if msg.CreatedAt.IsZero() {
		msg.CreatedAt = time.Now()
	}
	if msg.ExpiresAt.IsZero() {
		msg.ExpiresAt = msg.CreatedAt.Add(q.expirationTimeout)
	}

	// A4: Generate unique nonce for replay protection and confirmation correlation
	msg.Nonce = generateNonce()

	q.mu.Lock()
	defer q.mu.Unlock()

	// Check queue size
	if len(q.pending) >= q.maxQueueSize {
		return fmt.Errorf("queue full (%d messages), rejecting message %s for %s",
			len(q.pending), msg.DistributionID, msg.RecipientID)
	}

	// Check for duplicate (same distID + same recipient)
	key := pendingKey(msg.DistributionID, msg.RecipientID)
	if _, exists := q.pending[key]; exists {
		return fmt.Errorf("duplicate distribution ID: %s for recipient %s", msg.DistributionID, msg.RecipientID)
	}

	pending := &pendingMessage{
		Message:     msg,
		State:       MessageQueued,
		NextAttempt: time.Now(), // Try immediately
	}

	q.pending[key] = pending

	slog.Debug("enqueued message", "distributionID", msg.DistributionID, "recipient", msg.RecipientID, "zone", msg.Zone, "expires", msg.ExpiresAt.Format(time.RFC3339))

	return nil
}

// MarkConfirmed marks a message as delivered and removes it from the queue:
// the recipient gave its final word, so no resend follows. recipientID is
// the identity of the original message recipient (who is confirming delivery).
func (q *ReliableMessageQueue) MarkConfirmed(distributionID string, recipientID string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	key := pendingKey(distributionID, recipientID)
	pending, exists := q.pending[key]
	if !exists {
		// Not in queue - may have already been confirmed or expired
		return false
	}

	slog.Info("message confirmed", "distributionID", distributionID, "recipient", pending.Message.RecipientID, "attempts", pending.AttemptCount, "resends", pending.Resends, "age", time.Since(pending.Message.CreatedAt).Round(time.Second))

	pending.State = MessageConfirmed
	delete(q.pending, key)
	q.totalDelivered++
	return true
}

// MarkPending records that the recipient has the message and is still
// working on it: the wait for its final confirmation starts over, so a
// slow but live recipient is not sent the message again meanwhile. A
// message whose last send failed is parked the same way, since the
// recipient evidently has it. Returns false when the message is not in
// the queue.
func (q *ReliableMessageQueue) MarkPending(distributionID string, recipientID string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	pending, exists := q.pending[pendingKey(distributionID, recipientID)]
	if !exists {
		return false
	}
	// A send in flight parks the message itself when it returns, and
	// takes the PENDING with it: the recipient has the message whatever
	// becomes of the send's own answer.
	if pending.State == MessageSending {
		pending.HeardPending = true
		return true
	}
	q.awaitConfirmationLocked(pending)
	slog.Debug("recipient still working on the message, the wait starts over", "distributionID", distributionID, "recipient", recipientID, "wait", time.Until(pending.NextAttempt).Round(time.Second))
	return true
}

// GetStats returns current queue statistics.
func (q *ReliableMessageQueue) GetStats() QueueStats {
	q.mu.RLock()
	defer q.mu.RUnlock()

	stats := QueueStats{
		TotalPending:   len(q.pending),
		ByState:        make(map[string]int),
		ByPriority:     make(map[string]int),
		TotalDelivered: q.totalDelivered,
		TotalResent:    q.totalResent,
		TotalFailed:    q.totalFailed,
		TotalExpired:   q.totalExpired,
	}

	var oldest time.Time
	for _, pm := range q.pending {
		stats.ByState[pm.State.String()]++
		if pm.Message.Priority == PriorityHigh {
			stats.ByPriority["high"]++
		} else {
			stats.ByPriority["normal"]++
		}
		if oldest.IsZero() || pm.Message.CreatedAt.Before(oldest) {
			oldest = pm.Message.CreatedAt
		}
	}

	if !oldest.IsZero() {
		stats.OldestAge = time.Since(oldest)
	}

	return stats
}

// GetPendingMessages returns a JSON-serializable snapshot of all pending messages.
func (q *ReliableMessageQueue) GetPendingMessages() []PendingMessageInfo {
	q.mu.RLock()
	defer q.mu.RUnlock()

	msgs := make([]PendingMessageInfo, 0, len(q.pending))
	now := time.Now()

	for _, pm := range q.pending {
		priority := "normal"
		if pm.Message.Priority == PriorityHigh {
			priority = "high"
		}

		info := PendingMessageInfo{
			DistributionID: pm.Message.DistributionID,
			RecipientID:    pm.Message.RecipientID,
			Zone:           pm.Message.Zone,
			Priority:       priority,
			State:          pm.State.String(),
			AttemptCount:   pm.AttemptCount,
			Resends:        pm.Resends,
			CreatedAt:      pm.Message.CreatedAt.Format(time.RFC3339),
			ExpiresAt:      pm.Message.ExpiresAt.Format(time.RFC3339),
			NextAttempt:    pm.NextAttempt.Format(time.RFC3339),
			LastError:      pm.LastError,
			Age:            now.Sub(pm.Message.CreatedAt).Round(time.Second).String(),
		}
		if !pm.LastAttempt.IsZero() {
			info.LastAttempt = pm.LastAttempt.Format(time.RFC3339)
		}

		msgs = append(msgs, info)
	}

	return msgs
}

// processQueue is called periodically to attempt delivery of pending messages.
func (q *ReliableMessageQueue) processQueue(ctx context.Context) {
	q.mu.Lock()

	now := time.Now()
	var toSend []*pendingMessage
	var toRemove []string

	for key, pending := range q.pending {
		// Check expiration
		if now.After(pending.Message.ExpiresAt) {
			slog.Warn("message expired", "distributionID", pending.Message.DistributionID, "recipient", pending.Message.RecipientID, "attempts", pending.AttemptCount, "age", time.Since(pending.Message.CreatedAt).Round(time.Second))
			toRemove = append(toRemove, key)
			q.totalExpired++
			continue
		}

		// Skip if not ready for next attempt
		if now.Before(pending.NextAttempt) {
			continue
		}

		// Skip if already being sent
		if pending.State == MessageSending {
			continue
		}

		// Check if recipient is reachable
		if !q.isRecipientReady(pending.Message.RecipientID) {
			// Log on first deferral to aid debugging
			if pending.AttemptCount == 0 {
				slog.Debug("deferring message, recipient not ready", "distributionID", pending.Message.DistributionID, "recipient", pending.Message.RecipientID)
			}
			// Not ready - schedule a retry but don't count it as a failed attempt
			q.scheduleRetryLocked(pending, false)
			continue
		}

		// Ready to send. A delivered message whose final confirmation
		// did not come within its wait goes again, same ID and nonce.
		if pending.State == MessageAwaitingConfirm {
			pending.Resends++
			q.totalResent++
			slog.Info("no final confirmation, sending again", "distributionID", pending.Message.DistributionID, "recipient", pending.Message.RecipientID, "zone", pending.Message.Zone, "resend", pending.Resends, "age", now.Sub(pending.Message.CreatedAt).Round(time.Second))
		}
		toSend = append(toSend, pending)
		pending.State = MessageSending
		pending.HeardPending = false
	}

	// Remove expired messages
	for _, key := range toRemove {
		delete(q.pending, key)
	}

	q.mu.Unlock()

	// Send messages outside the lock
	for _, pending := range toSend {
		q.attemptDelivery(ctx, pending)
	}
}

// isRecipientReady checks if the recipient is ready to receive messages.
func (q *ReliableMessageQueue) isRecipientReady(recipientID string) bool {
	if q.isRecipientReadyFn == nil {
		return true // no readiness check = always ready
	}
	return q.isRecipientReadyFn(recipientID)
}

// attemptDelivery tries to send a message and handles the result.
func (q *ReliableMessageQueue) attemptDelivery(ctx context.Context, pending *pendingMessage) {
	msg := pending.Message

	if q.sendFunc == nil {
		q.mu.Lock()
		pending.LastError = "no sendFunc configured"
		q.scheduleRetryLocked(pending, true)
		q.mu.Unlock()
		return
	}

	// Attempt delivery
	err := q.sendFunc(ctx, msg)

	q.mu.Lock()
	defer q.mu.Unlock()

	// The recipient's final confirmation can arrive while the send is in
	// flight (MarkConfirmed removed the entry), and so can the expiry.
	// Either way the message is no longer ours to schedule.
	if q.pending[pendingKey(msg.DistributionID, msg.RecipientID)] != pending {
		return
	}

	pending.AttemptCount++
	pending.LastAttempt = time.Now()

	if err != nil {
		pending.LastError = err.Error()
		if pending.HeardPending {
			// The recipient answered PENDING while the send was in flight:
			// it has the message, whatever became of the send's own answer.
			q.awaitConfirmationLocked(pending)
			slog.Info("send failed but the recipient answered pending, awaiting the final confirmation", "distributionID", msg.DistributionID, "recipient", msg.RecipientID, "attempt", pending.AttemptCount, "err", err)
			return
		}
		slog.Warn("send failed", "distributionID", msg.DistributionID, "recipient", msg.RecipientID, "attempt", pending.AttemptCount, "err", err)
		q.scheduleRetryLocked(pending, true)
		return
	}

	// Sent and acknowledged at the transport level: the recipient has the
	// message. Its final word comes later as a confirmation (MarkConfirmed);
	// until then the message waits, and goes again if the wait runs out.
	pending.LastError = ""
	q.awaitConfirmationLocked(pending)
	slog.Info("message delivered, awaiting the final confirmation", "distributionID", msg.DistributionID, "recipient", msg.RecipientID, "attempt", pending.AttemptCount, "wait", pending.NextAttempt.Sub(pending.LastAttempt).Round(time.Second))
}

// awaitConfirmationLocked parks a delivered message until the recipient's
// final confirmation or, failing that, its next send. Must be called with
// q.mu held.
func (q *ReliableMessageQueue) awaitConfirmationLocked(pending *pendingMessage) {
	pending.State = MessageAwaitingConfirm
	pending.NextAttempt = time.Now().Add(q.confirmWait(pending))
}

// confirmWait is how long a delivered message waits for its final
// confirmation before it is sent again: the confirm timeout, doubled for
// every resend so far, capped at maxConfirmWait.
func (q *ReliableMessageQueue) confirmWait(pending *pendingMessage) time.Duration {
	wait := q.confirmTimeout
	for i := 0; i < pending.Resends && wait < q.maxConfirmWait; i++ {
		wait *= 2
	}
	if wait > q.maxConfirmWait {
		wait = q.maxConfirmWait
	}
	return wait
}

// scheduleRetryLocked calculates the next retry time using exponential backoff.
// Must be called with q.mu held.
// If countAsAttempt is false, uses a fixed short backoff (for "not ready" cases).
func (q *ReliableMessageQueue) scheduleRetryLocked(pending *pendingMessage, countAsAttempt bool) {
	if !countAsAttempt {
		// Recipient not ready - use a fixed backoff, don't count as attempt.
		// The state stays: a message awaiting its confirmation still is.
		pending.NextAttempt = time.Now().Add(q.baseBackoff)
		return
	}

	// Exponential backoff: base * 2^(attempts-1), capped at maxBackoff
	backoff := q.baseBackoff
	for i := 1; i < pending.AttemptCount && backoff < q.maxBackoff; i++ {
		backoff *= 2
	}
	if backoff > q.maxBackoff {
		backoff = q.maxBackoff
	}

	pending.NextAttempt = time.Now().Add(backoff)
	pending.State = MessageQueued

	slog.Debug("retry scheduled", "distributionID", pending.Message.DistributionID, "recipient", pending.Message.RecipientID, "backoff", backoff.Round(time.Millisecond), "attempt", pending.AttemptCount)
}

// generateQueueDistributionID creates a unique distribution ID for queue messages.
// Uses the same epoch+counter generator as the DNS transport layer.
func generateQueueDistributionID() string {
	return GenerateDistributionID()
}

// --- Helper functions ---

func withDefault(val, def time.Duration) time.Duration {
	if val == 0 {
		return def
	}
	return val
}

func withDefaultInt(val, def int) int {
	if val == 0 {
		return def
	}
	return val
}

// generateNonce returns a cryptographically random nonce (16 bytes, hex-encoded).
// Used for replay protection in sync/confirm messages.
func generateNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
