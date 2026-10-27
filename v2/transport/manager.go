/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Generic TransportManager for tdns-transport.
 *
 * Orchestrates transport components (DNS/API transports, Router,
 * PeerRegistry, ChunkHandler, ReliableMessageQueue) at startup.
 * At runtime, messages flow directly between components without
 * passing through the TransportManager.
 *
 * Applications register their own message handlers on the Router
 * and use Enqueue for reliable outgoing delivery. The TM has no
 * knowledge of specific message types or application semantics.
 */
package transport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// TransportManagerConfig holds configuration for creating a TransportManager.
// Application-specific behavior is injected via callbacks.
type TransportManagerConfig struct {
	// Identity
	LocalID     string
	ControlZone string

	// Transport timeouts
	APITimeout time.Duration
	DNSTimeout time.Duration

	// CHUNK configuration
	ChunkMode                  string // "edns0" or "query"
	ChunkMaxSize               int
	ChunkQueryEndpoint         string
	ChunkQueryEndpointInNotify bool

	// ChunkStore for query mode; nil means the transport's own in-memory
	// store. The application calls DNSTransport.ServeChunkQueries to
	// answer for it.
	ChunkStore ChunkStore

	// Crypto
	PayloadCrypto *PayloadCrypto

	// Which transports to enable: "api", "dns"
	SupportedMechanisms []string

	// TLS client config for API transport
	ClientCertFile string
	ClientKeyFile  string

	// Application callbacks
	IsPeerAuthorized      func(senderID, zone string) (bool, string)
	IsRecipientReady      func(recipientID string) bool
	GetPeerAddress        func(senderID string) (string, bool)
	OnPeerDiscoveryNeeded func(peerID string)

	// Distribution tracking callbacks (optional)
	DistributionAdd           func(qname, senderID, receiverID, operation, distributionID string, payloadSize int)
	DistributionMarkCompleted func(qname string)

	// RMQ configuration
	RMQBaseBackoff       time.Duration
	RMQMaxBackoff        time.Duration
	RMQConfirmTimeout    time.Duration
	RMQMaxConfirmWait    time.Duration
	RMQExpirationTimeout time.Duration
}

// TransportManager orchestrates transport components.
// After construction, applications interact with the components
// directly (Router for incoming, ReliableQueue for outgoing).
type TransportManager struct {
	// Components — applications access these directly
	APITransport  *APITransport
	DNSTransport  *DNSTransport
	ChunkHandler  *ChunkNotifyHandler
	Router        *DNSMessageRouter
	PeerRegistry  *PeerRegistry
	ReliableQueue *ReliableMessageQueue

	// Identity
	LocalID     string
	ControlZone string

	// OnPeerDiscovered is the application's hook for a completed
	// discovery. The application sets it at startup; transport never
	// sets it; nil means no callback. The callback receives the
	// registered, non-nil *Peer.
	//
	// Fired by transport itself, at the end of every successful
	// RegisterDiscoveredPeer (discovery runs in transport since Phase
	// 2.6): addresses, mechanism states and crypto slots are already on
	// the peer when the application sees it, so the callback only
	// materializes the application's own view of it.
	OnPeerDiscovered func(peer *Peer)

	// OnDiscoveryFailed is invoked when a peer-discovery attempt
	// fails. The application's discovery loop is responsible for
	// retries — this callback fires once per failed attempt round,
	// not once forever; the same peer may produce multiple
	// invocations across the lifetime of the loop.
	//
	// Optional. If nil, transport takes no action beyond what the
	// invocation site already does on failure (e.g. logging).
	//
	// Symmetric with OnPeerDiscovered: invocation site resolves the
	// peer (using GetOrCreate when discovery fails before a peer
	// has materialised) and passes a non-nil *Peer plus the error
	// that ended this round.
	//
	// Fired when a discovery round for the peer ends in failure: no
	// usable endpoint, or a registration the transport refused. The
	// application's retry loop drives the rounds and fires it for the
	// rounds it runs; an established peer must not be regressed by it.
	OnDiscoveryFailed func(peer *Peer, err error)

	// GetImr late-binds the IMR resolver used by the in-package discovery
	// process (the resolver starts asynchronously after the manager is
	// constructed). Set by the application at startup; nil means fresh
	// discovery cannot run (DiscoverPeer only returns already-known
	// peers).
	//
	// Phase 2.6: replaces the TEMPORARY DiscoveryDriver seam — the
	// discovery process now lives in this package (discovery.go).
	GetImr func() *Imr

	// Which mechanisms are active
	supportedMechanisms []string
}

// SetSupportedMechanisms sets the active mechanism set for managers
// constructed via struct literal rather than NewTransportManager (tdns-mp
// builds its bridge that way). The in-package discovery process consults
// this via isTransportSupported (Fix E: only locally-supported transports
// are probed).
func (tm *TransportManager) SetSupportedMechanisms(mechanisms []string) {
	tm.supportedMechanisms = mechanisms
}

// NewTransportManager creates and wires all transport components.
// After creation, the application should:
//  1. Register message handlers on tm.Router
//  2. Call tm.RegisterChunkNotifyHandler() to plug into the DNS server
//  3. Call tm.StartReliableQueue() to begin outgoing delivery
func NewTransportManager(cfg *TransportManagerConfig) *TransportManager {
	tm := &TransportManager{
		LocalID:             cfg.LocalID,
		ControlZone:         cfg.ControlZone,
		supportedMechanisms: cfg.SupportedMechanisms,
	}

	// Create PeerRegistry
	tm.PeerRegistry = NewPeerRegistry()

	// Create Router
	tm.Router = NewDNSMessageRouter()

	// Create DNS transport if enabled
	if isIn(cfg.SupportedMechanisms, "dns") {
		dnsTimeout := cfg.DNSTimeout
		if dnsTimeout == 0 {
			dnsTimeout = 5 * time.Second
		}
		tm.DNSTransport = NewDNSTransport(&DNSTransportConfig{
			LocalID:                    cfg.LocalID,
			ControlZone:                cfg.ControlZone,
			Timeout:                    dnsTimeout,
			PayloadCrypto:              cfg.PayloadCrypto,
			ChunkMode:                  cfg.ChunkMode,
			ChunkStore:                 cfg.ChunkStore,
			ChunkQueryEndpoint:         cfg.ChunkQueryEndpoint,
			ChunkQueryEndpointInNotify: cfg.ChunkQueryEndpointInNotify,
			ChunkMaxSize:               cfg.ChunkMaxSize,
			DistributionAdd:            cfg.DistributionAdd,
			DistributionMarkCompleted:  cfg.DistributionMarkCompleted,
		})
	}

	// Create API transport if enabled
	if isIn(cfg.SupportedMechanisms, "api") {
		apiTimeout := cfg.APITimeout
		if apiTimeout == 0 {
			apiTimeout = 5 * time.Second
		}
		tm.APITransport = NewAPITransport(&APITransportConfig{
			LocalID:        cfg.LocalID,
			DefaultTimeout: apiTimeout,
			GetImr: func() *Imr {
				if tm.GetImr != nil {
					return tm.GetImr()
				}
				return nil
			},
		})
		tm.PeerRegistry.OnRemove = tm.APITransport.ForgetPeer
	}

	// Create ChunkNotifyHandler if DNS transport is available
	if tm.DNSTransport != nil {
		tm.ChunkHandler = NewChunkNotifyHandler(cfg.ControlZone, cfg.LocalID, tm.DNSTransport)
		tm.ChunkHandler.Router = tm.Router

		// Wire application callbacks into ChunkHandler
		if cfg.IsPeerAuthorized != nil {
			tm.ChunkHandler.IsPeerAuthorized = cfg.IsPeerAuthorized
		}
		if cfg.GetPeerAddress != nil {
			tm.ChunkHandler.GetPeerAddress = cfg.GetPeerAddress
		}
		if cfg.OnPeerDiscoveryNeeded != nil {
			tm.ChunkHandler.OnPeerDiscoveryNeeded = cfg.OnPeerDiscoveryNeeded
		}
		if cfg.PayloadCrypto != nil {
			tm.ChunkHandler.SecureWrapper = NewSecurePayloadWrapper(cfg.PayloadCrypto)
		}
	}

	// Create ReliableMessageQueue
	tm.ReliableQueue = NewReliableMessageQueue(&ReliableMessageQueueConfig{
		IsRecipientReady:  cfg.IsRecipientReady,
		BaseBackoff:       cfg.RMQBaseBackoff,
		MaxBackoff:        cfg.RMQMaxBackoff,
		ConfirmTimeout:    cfg.RMQConfirmTimeout,
		MaxConfirmWait:    cfg.RMQMaxConfirmWait,
		ExpirationTimeout: cfg.RMQExpirationTimeout,
	})

	return tm
}

// SelectTransport chooses the best transport for a peer.
// Respects peer's PreferredTransport, falls back to API then DNS.
func (tm *TransportManager) SelectTransport(peer *Peer) Transport {
	apiUsable := tm.APITransport != nil && peer.APIUsable()
	switch peer.GetPreferredTransport() {
	case "DNS":
		if tm.DNSTransport != nil && peer.CurrentAddress() != nil {
			return tm.DNSTransport
		}
	case "API":
		if apiUsable {
			return tm.APITransport
		}
	}

	// Default: API first (more reliable), then DNS
	if apiUsable {
		return tm.APITransport
	}
	if tm.DNSTransport != nil && peer.CurrentAddress() != nil {
		return tm.DNSTransport
	}

	return nil
}

// RegisterChunkNotifyHandler registers the CHUNK NOTIFY handler
// with the DNS server. The registerFn is provided by the application
// (typically tdns.RegisterNotifyHandler).
func (tm *TransportManager) RegisterChunkNotifyHandler(
	registerFn func(qtype uint16, handler interface{}) error,
) error {
	if tm.ChunkHandler == nil {
		return nil // DNS transport not enabled
	}
	// The application provides the registration function that
	// bridges to its DNS server's handler registry.
	// The ChunkHandler.RouteViaRouter method matches the expected signature.
	return registerFn(0, tm.ChunkHandler) // 0 = application determines qtype
}

// StartReliableQueue starts the RMQ background worker.
// The sendFunc is called by RMQ to deliver messages — the application
// provides this to handle transport selection and actual sending.
func (tm *TransportManager) StartReliableQueue(ctx context.Context,
	sendFunc func(ctx context.Context, msg *OutgoingMessage) error) {
	tm.ReliableQueue.setSendFunc(sendFunc)
	go tm.ReliableQueue.Start(ctx)
	slog.Info("reliable queue started")
}

// Enqueue adds a message to the reliable delivery queue.
// Returns the distribution ID for confirmation tracking.
func (tm *TransportManager) Enqueue(msg *OutgoingMessage) (string, error) {
	return msg.DistributionID, tm.ReliableQueue.Enqueue(msg)
}

// MarkDeliveryConfirmed marks a queued message as confirmed.
// Returns true if the message was found and confirmed.
func (tm *TransportManager) MarkDeliveryConfirmed(distributionID, senderID string) bool {
	return tm.ReliableQueue.MarkConfirmed(distributionID, senderID)
}

// Send delivers a message to a peer using the primary transport
// chosen by SelectTransport, falling back to the alternative on
// error. The message type is determined by the concrete type of req:
//
//   - *AppMessage     → Transport.SendApp (all application verbs; C2)
//   - *PingRequest    → Transport.Ping
//   - *ConfirmRequest → Transport.Confirm (see Confirm)
//
// (Hello and Beat are deliberately NOT supported by this
// primary-then-fallback path: they are sent on every eligible
// mechanism, each outcome mattering. Use SendAll for them (D1).)
//
// Returns the response (one of *AppResponse, *PingResponse; nil for a
// confirmation) or an error if both transports failed or the
// message type is unsupported. A verb only DNS carries has no API fallback.
// When every transport tried has failed, the error names each mechanism
// with its error and wraps each one: errors.Is matches any of them, and
// errors.As returns the first match, the primary's error before the
// fallback's.
//
// Bite 3 of the transport refactor early-bites plan; see
// tdns-mp/docs/2026-04-25-transport-refactor-early-bites.md.
func (tm *TransportManager) Send(ctx context.Context, peer *Peer, req interface{}) (interface{}, error) {
	if peer == nil {
		return nil, fmt.Errorf("Send: peer is nil")
	}
	primary := tm.SelectTransport(peer)
	if primary == nil {
		return nil, fmt.Errorf("Send: no usable transport for peer %s (%s)", peer.ID, tm.noTransportReason(peer))
	}
	primary, fallback := tm.route(peer, req, primary)
	return sendWith(ctx, peer, req, primary, fallback)
}

// SendOutcome is how a SendOn went: the mechanism tried first, why that one
// did not carry the message, and the mechanism that did.
type SendOutcome struct {
	First    string // the mechanism tried first; "" when none was tried
	FirstErr error  // why First did not carry the message; nil when it did
	Carrier  string // the mechanism that carried it; "" when none did
}

// SendOn sends req to peer as Send does, with mechanism's transport first
// instead of the one SelectTransport picks: an answer goes back the way its
// request came (tdns-mp #238). When mechanism is not known (""), this
// manager has no transport for it, or that one does not reach the peer, the
// first choice is SelectTransport's. The fallback is Send's, when it
// reaches the peer, with Send's rule: a failure to deliver, or a reply that
// the endpoint does not take the verb (verbNotAccepted), goes on the other
// mechanism; a refusal the peer judged (Answered) is returned and the other
// is not tried. req is sent once, as an answer or a confirmation is: when
// there is another mechanism, the first try gets half of ctx's time.
//
// A failure to deliver on the first choice is counted against that
// mechanism (RecordMechanismFailure), so a pair that works one way only
// shows in the gossip matrix (tdns-mp #236). The mechanism that carries
// req, the first or the other, has its count cleared
// (RecordMechanismSuccess). A judged refusal and a verb the
// mechanism does not carry are answers, not failures to deliver, and are
// not counted. The outcome says which mechanism carried req, and why the
// first did not.
func (tm *TransportManager) SendOn(ctx context.Context, peer *Peer, mechanism string, req interface{}) (interface{}, SendOutcome, error) {
	if peer == nil {
		return nil, SendOutcome{}, fmt.Errorf("SendOn: peer is nil")
	}
	primary := tm.transportFor(mechanism)
	if primary == nil || !reaches(primary, peer) {
		primary = tm.SelectTransport(peer)
	}
	if primary == nil {
		return nil, SendOutcome{}, fmt.Errorf("SendOn: no usable transport for peer %s (%s)", peer.ID, tm.noTransportReason(peer))
	}
	primary, fallback := tm.route(peer, req, primary)
	// An API with no TLSA to check the peer's certificate against, or a DNS
	// with no address, is no fallback: there is nothing to try there.
	if fallback != nil && !reaches(fallback, peer) {
		fallback = nil
	}
	resp, out, err := send(ctx, peer, req, primary, fallback, true)
	if undelivered(out.FirstErr) {
		peer.RecordMechanismFailure(out.First)
	}
	if out.Carrier != "" {
		peer.RecordMechanismSuccess(out.Carrier)
	}
	return resp, out, err
}

// transportFor is this manager's transport for mechanism, nil when it has
// none.
func (tm *TransportManager) transportFor(mechanism string) Transport {
	switch mechanism {
	case MechanismAPI:
		if tm.APITransport != nil {
			return tm.APITransport
		}
	case MechanismDNS:
		if tm.DNSTransport != nil {
			return tm.DNSTransport
		}
	}
	return nil
}

// route is the primary and the fallback for req when primary is the first
// choice. The fallback is the one that isn't the primary. Only the sync
// family has an API endpoint; every other application verb is DNS-only.
// Those go to DNS up front rather than letting the API primary reject them
// and relying on the fallback, and get no API fallback: API would only
// refuse the verb.
func (tm *TransportManager) route(peer *Peer, req interface{}, primary Transport) (Transport, Transport) {
	am, isApp := req.(*AppMessage)
	dnsOnly := isApp && am != nil && !isSyncFamily(am.TypeToken)
	if dnsOnly && primary == tm.APITransport && tm.DNSTransport != nil && peer.HasMechanism("DNS") {
		primary = tm.DNSTransport
	}
	var fallback Transport
	if primary == tm.APITransport && tm.DNSTransport != nil {
		fallback = tm.DNSTransport
	} else if primary == tm.DNSTransport && tm.APITransport != nil && !dnsOnly {
		fallback = tm.APITransport
	}
	return primary, fallback
}

// Confirm sends a confirmation to peer as Send sends a message: on the
// transport SelectTransport picks (the API when the peer offers it), then
// on the other one when that fails. A receiver that does not take
// confirmations over HTTPS refuses the API's, and the DNS NOTIFY carries
// it instead. A receiver that takes it and refuses it has judged it: that
// refusal is returned, Answered, and DNS is not tried. When the other one
// can reach the peer, the first try gets half of ctx's time.
//
// A try that times out after the receiver took the confirmation sends it
// again on the other mechanism, and the receiver gets it twice, as it
// does when a sender re-sends a message whose confirmation was lost.
func (tm *TransportManager) Confirm(ctx context.Context, peer *Peer, req *ConfirmRequest) error {
	if req == nil {
		return fmt.Errorf("Confirm: empty confirmation")
	}
	_, err := tm.Send(ctx, peer, req)
	return err
}

// reaches reports whether t has somewhere to send to peer: an endpoint and
// a TLSA for the API (APIUsable), an address for DNS. A transport of another
// kind (a test's) is taken to reach it.
func reaches(t Transport, peer *Peer) bool {
	switch t.(type) {
	case *APITransport:
		return peer.APIUsable()
	case *DNSTransport:
		return peer.CurrentAddress() != nil
	}
	return true
}

// halfOfDeadline is ctx with half the time it has left, or ctx itself
// when it has no deadline.
func halfOfDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, time.Until(deadline)/2)
}

// noTransportReason says, per mechanism, why SelectTransport found no
// transport for peer.
func (tm *TransportManager) noTransportReason(peer *Peer) string {
	apiWhy, dnsWhy := "peer has no endpoint", "peer has no address"
	if tm.APITransport == nil {
		apiWhy = "not enabled"
	} else if peer.GetAPIEndpoint() != "" {
		apiWhy = "peer has no usable TLSA"
	}
	if tm.DNSTransport == nil {
		dnsWhy = "not enabled"
	}
	return "API: " + apiWhy + "; DNS: " + dnsWhy
}

// sendWith is Send's primary-then-fallback over the given transports
// (fallback nil: there is none). It is separate from the manager's
// concrete transport fields so that tests can inject fakes.
func sendWith(ctx context.Context, peer *Peer, req interface{}, primary, fallback Transport) (interface{}, error) {
	resp, _, err := send(ctx, peer, req, primary, fallback, false)
	return resp, err
}

// fallsBack reports whether a primary that failed with err leaves the
// message to the fallback: not after a non-retryable error, which would hit
// the other transport identically, and not after an Answered refusal, which
// the recipient would give again. Errors not wrapped in *TransportError fall
// back (a safe default for unaudited code paths).
func fallsBack(err error) bool {
	var te *TransportError
	return !errors.As(err, &te) || (te.Retryable && !te.Answered)
}

// undelivered reports whether err is a failure to deliver on the
// mechanism: one that falls back, other than a verb the mechanism does not
// carry (NotAccepted).
func undelivered(err error) bool {
	if err == nil || !fallsBack(err) {
		return false
	}
	var te *TransportError
	return !errors.As(err, &te) || !te.NotAccepted
}

// send is sendWith, with the outcome. A message sent once (once: an answer;
// a confirmation always is) leaves the fallback time: when the fallback can
// reach the peer, the primary gets half the time left, so that a peer that
// hangs on it leaves the fallback the other half.
func send(ctx context.Context, peer *Peer, req interface{}, primary, fallback Transport, once bool) (interface{}, SendOutcome, error) {
	var out SendOutcome
	var dispatch func(ctx context.Context, t Transport) (interface{}, error)
	switch r := req.(type) {
	case *AppMessage:
		dispatch = func(ctx context.Context, t Transport) (interface{}, error) {
			resp, err := t.SendApp(ctx, peer, r)
			if err != nil {
				return nil, err
			}
			// A non-ok confirmation of a zone-data verb is an
			// application-level rejection, retryable for the caller's
			// queue (the pre-C2 DNSTransport.Sync contract). When the
			// endpoint does not take the verb, nothing judged the
			// message, and the other mechanism may carry it. Any
			// other refusal is the peer's judgment: Answered, so the
			// other mechanism is not tried — it would refuse again
			// for the same reason (tdns-transport #36).
			if resp.Status == ConfirmFailed && isSyncFamily(r.TypeToken) {
				err := fmt.Errorf("recipient rejected %s: %s", r.TypeToken, resp.Message)
				if verbNotAccepted(resp.Message, r.TypeToken) {
					return resp, NewNotAcceptedTransportError(t.Name(), r.TypeToken, peer.ID, err)
				}
				return resp, NewAnsweredTransportError(t.Name(), r.TypeToken, peer.ID, err)
			}
			return resp, nil
		}
	case *ConfirmRequest:
		once = true
		dispatch = func(ctx context.Context, t Transport) (interface{}, error) {
			return nil, t.Confirm(ctx, peer, r)
		}
	case *PingRequest:
		dispatch = func(ctx context.Context, t Transport) (interface{}, error) {
			resp, err := t.Ping(ctx, peer, r)
			if err != nil {
				return nil, err
			}
			if resp != nil && !resp.OK {
				// A negative acknowledgement counts as a failed send for
				// the fallback decision, not as a success with OK=false.
				return resp, NewTransportError(t.Name(), "Ping", peer.ID,
					fmt.Errorf("ping not acknowledged by %s", peer.ID), true)
			}
			return resp, nil
		}
	default:
		return nil, out, fmt.Errorf("Send: unsupported message type %T (use SendAll for hello/beat fan-out)", req)
	}

	out.First = primary.Name()
	pctx, cancel := ctx, context.CancelFunc(func() {})
	if once && fallback != nil && reaches(fallback, peer) {
		pctx, cancel = halfOfDeadline(ctx)
	}
	resp, primaryErr := dispatch(pctx, primary)
	cancel()
	if primaryErr == nil {
		out.Carrier = primary.Name()
		return resp, out, nil
	}
	out.FirstErr = primaryErr
	// Don't fall back on non-retryable errors. The same problem
	// (e.g. missing crypto key, no address, marshal failure) will
	// hit the alternate transport identically — falling back just
	// turns a clear error into a confusing one. Errors not wrapped
	// in *TransportError are treated as fall-back-eligible (safe
	// default for unaudited code paths).
	//
	// Don't fall back on an Answered refusal either: the recipient
	// already judged the message. A reply that the endpoint does not
	// take the verb (verbNotAccepted) is not Answered, for a message or
	// a confirmation alike: a peer whose /msg does not take it yet gets
	// it over DNS (tdns-transport #36;
	// TestManagerConfirmPrefersAPIFallsBackToDNS,
	// TestSendVerbNotAcceptedFallsBack).
	if !fallsBack(primaryErr) {
		if transportErrorAnswered(primaryErr) {
			slog.Debug("primary transport answered with a refusal, not falling back",
				"transport", primary.Name(), "peer", peer.ID, "err", primaryErr)
		} else {
			slog.Debug("primary transport failed with non-retryable error, not falling back",
				"transport", primary.Name(), "peer", peer.ID, "err", primaryErr)
		}
		return resp, out, primaryErr
	}
	if fallback == nil {
		return nil, out, fmt.Errorf("Send: all transports failed for peer %s (%s: %w)",
			peer.ID, primary.Name(), primaryErr)
	}
	slog.Debug("primary transport failed, trying fallback",
		"transport", primary.Name(), "peer", peer.ID, "err", primaryErr)

	resp, fallbackErr := dispatch(ctx, fallback)
	if fallbackErr == nil {
		out.Carrier = fallback.Name()
		return resp, out, nil
	}
	// The fallback's error alone would hide why the primary failed.
	return resp, out, fmt.Errorf("Send: all transports failed for peer %s (%s: %w; %s: %w)",
		peer.ID, primary.Name(), primaryErr, fallback.Name(), fallbackErr)
}

// transportErrorAnswered reports whether err is a TransportError whose
// recipient answered with a refusal (Answered).
func transportErrorAnswered(err error) bool {
	var te *TransportError
	return errors.As(err, &te) && te.Answered
}

// GetQueueStats returns RMQ statistics.
func (tm *TransportManager) GetQueueStats() QueueStats {
	return tm.ReliableQueue.GetStats()
}

// GetQueuePendingMessages returns a snapshot of pending messages.
func (tm *TransportManager) GetQueuePendingMessages() []PendingMessageInfo {
	return tm.ReliableQueue.GetPendingMessages()
}

// DiscoverPeer initiates peer discovery for the given identity and
// blocks until discovery completes, the context is cancelled, or
// discovery fails. Returns the resolved Peer on success.
//
// If a peer with this identity is already in PeerStateKnown (or
// higher), DiscoverPeer returns it immediately without re-discovery,
// unless one of its mechanisms still needs discovery (an API endpoint
// without a usable TLSA, say); then it looks again, and returns the
// known peer as it was if that look cannot run or fails.
// Otherwise the in-package discovery process runs (discovery.go —
// Phase 2.6; the TEMPORARY DiscoveryDriver seam is gone). When
// tm.GetImr is nil, DiscoverPeer can only return already-known
// peers; an unknown identity yields an error.
//
// The asynchronous discovery path (the application's polling loop
// that watches for NEEDED peers) is unaffected by this method.
// Callers wanting fire-and-forget behaviour can launch their own
// goroutine — DiscoverPeer is intentionally synchronous so that
// CLI commands, tests, and other inline callers can use the result
// immediately.
func (tm *TransportManager) DiscoverPeer(ctx context.Context, identity string) (*Peer, error) {
	if identity == "" {
		return nil, fmt.Errorf("DiscoverPeer: empty identity")
	}
	peer := tm.PeerRegistry.GetOrCreate(identity)
	// A peer known on one mechanism is looked up again while another still
	// needs discovery: an API endpoint whose TLSA was not published yet,
	// say, or was withdrawn.
	known := peer.EffectiveState() >= PeerStateKnown
	if known && !peer.mechanismNeedsDiscovery() {
		return peer, nil
	}
	// A mechanism still needed must not hide one that works: a known peer
	// whose re-discovery cannot run, or fails, is returned as it is.
	if tm.GetImr == nil {
		if known {
			return peer, nil
		}
		return nil, fmt.Errorf("DiscoverPeer: peer %q not known and no IMR accessor configured", identity)
	}
	if err := tm.DiscoverAndRegisterPeer(ctx, identity); err != nil {
		if known {
			lgTransport().Debug("re-discovery for a needed mechanism failed; the peer stays as it was",
				"peer", identity, "err", err)
			return peer, nil
		}
		return nil, fmt.Errorf("DiscoverPeer: discovery failed for %q: %w", identity, err)
	}
	if peer.EffectiveState() < PeerStateKnown {
		return nil, fmt.Errorf("DiscoverPeer: discovery succeeded but peer %q state is %v, expected >= Known",
			identity, peer.EffectiveState())
	}
	return peer, nil
}

// SendPing sends a ping to a peer using the best available
// transport, falling back to the alternate transport if the primary
// fails with a retryable error. Bite G: delegates to tm.Send so that
// ping inherits the primary-then-fallback behaviour from the generic
// path; Hello and Beat are NOT migrated to tm.Send because their
// wrappers send on all transports in parallel rather than
// primary-then-fallback (Phase 5 of the main refactor).
func (tm *TransportManager) SendPing(ctx context.Context, peer *Peer) (*PingResponse, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate ping nonce: %w", err)
	}
	resp, err := tm.Send(ctx, peer, &PingRequest{
		SenderID:  tm.LocalID,
		Nonce:     hex.EncodeToString(nonce),
		Timestamp: time.Now(),
	})
	if err != nil {
		return nil, err
	}
	pingResp, ok := resp.(*PingResponse)
	if !ok {
		return nil, fmt.Errorf("SendPing: unexpected response type %T", resp)
	}
	return pingResp, nil
}

// isTransportSupported checks if a transport mechanism is enabled.
func (tm *TransportManager) isTransportSupported(mechanism string) bool {
	return isIn(tm.supportedMechanisms, mechanism)
}

// isIn checks if a string is in a slice.
func isIn(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
