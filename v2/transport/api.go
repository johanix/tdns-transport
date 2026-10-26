/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * API transport implementation for multi-provider DNSSEC coordination (HSYNC).
 * Wraps the existing HTTPS-based API communication in tdns/v2.
 */

package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// APITransport implements the Transport interface using HTTPS REST API.
type APITransport struct {
	// LocalID is our own identity
	LocalID string

	// DefaultTimeout for API calls
	DefaultTimeout time.Duration

	// HTTPClient is the shared HTTP client (can be configured for TLS).
	// No request goes through it: every peer gets a client of its own, made
	// from it, that checks the peer's certificate against the peer's TLSA
	// and dials the API address discovery found (clientFor).
	HTTPClient *http.Client

	// TLSA checks a peer's certificate against its TLSA RRset, here for the
	// receiver and in the receiving application for the client.
	TLSA *TLSAChecker

	mu      sync.Mutex
	clients map[*Peer]*peerClient
}

// peerClient is a peer's own HTTP client. Its TLS config checks the peer's
// certificate against the peer's TLSA (VerifyConnection). It dials addr, the
// API address discovery found, when there is one, whatever the endpoint's
// host name would resolve to; the URL keeps the name. base is the shared
// transport it was made from, tlsa the TLSA set it was made under.
type peerClient struct {
	addr   string
	tlsa   string
	base   *http.Transport
	client *http.Client
}

// APITransportConfig holds configuration for creating an APITransport.
type APITransportConfig struct {
	LocalID        string
	DefaultTimeout time.Duration
	TLSConfig      *tls.Config
	// GetImr is the node's resolver, for the TLSA checks (TLSAChecker). Nil
	// checks against the TLSA discovery stored on the peer.
	GetImr func() *Imr
}

// NewAPITransport creates a new APITransport with the given configuration.
func NewAPITransport(cfg *APITransportConfig) *APITransport {
	timeout := cfg.DefaultTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	tlsConfig := cfg.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	return &APITransport{
		LocalID:        cfg.LocalID,
		DefaultTimeout: timeout,
		TLSA:           NewTLSAChecker(cfg.GetImr),
		HTTPClient: &http.Client{
			Timeout:       timeout,
			CheckRedirect: refuseRedirect,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}
}

// Name returns the transport name for logging.
func (t *APITransport) Name() string {
	return "API"
}

// apiURL returns the full URL for an API operation on a peer, from
// peer.APIEndpoint (the discovered or configured base URI). The address
// dialed for it is the discovered one when there is one (clientFor).
func apiURL(peer *Peer, path string) (string, error) {
	endpoint := peer.GetAPIEndpoint()
	if endpoint == "" {
		// API transport requires an explicit HTTPS endpoint. Falling
		// back to peer.CurrentAddress() (a DNS endpoint for DNS-only
		// peers) would produce structurally invalid HTTP URLs like
		// "udp://host:53/sync" — guaranteed to fail with
		// "unsupported protocol scheme udp". Refusing here gives
		// callers a clear error instead.
		return "", fmt.Errorf("peer %s has no API endpoint configured", peer.ID)
	}
	if err := requireHTTPS(endpoint); err != nil {
		return "", fmt.Errorf("peer %s: %w", peer.ID, err)
	}
	return endpoint + path, nil
}

// requireHTTPS refuses an API endpoint that is not an https URL: the HTTPS
// mechanism carries application payloads verbatim, and TLS is all that
// protects them.
func requireHTTPS(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid API endpoint %q: %w", endpoint, err)
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return fmt.Errorf("API endpoint %q is not an https URL", endpoint)
	}
	return nil
}

// refuseRedirect keeps the client from following a redirect: the sync API
// never redirects, and a redirect would take the payload somewhere the
// peer's discovered endpoint did not name.
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("redirect to %s refused", req.URL.Redacted())
}

// The HTTPS mechanism speaks the same bodies the multi-provider sync API
// has always accepted (cleanup plan step 5): hello, beat and ping post the
// transport-own wire structs (wire_own.go, byte-identical to the DNS
// payloads), an application message posts its payload verbatim to /msg, a
// confirmation posts the DNS confirm payload to /msg, and every reply is
// the receiver's {Status, Error, ErrorMsg, ...} object.
// The snake_case dialect this file spoke before step 5 had no receiver.

// apiReply is the receiver's response object, in every endpoint's shape:
// the fields an endpoint does not use are simply absent.
type apiReply struct {
	Status       string
	MyIdentity   string
	YourIdentity string
	AgentId      string
	Zone         string
	Nonce        string
	Time         time.Time
	Msg          string
	Error        bool
	ErrorMsg     string
	Gossip       json.RawMessage // a beat's answer: the responder's gossip, as a DNS beat's confirm carries it
}

// responderOf is the identity the reply names for itself.
func (r *apiReply) responderOf(peer *Peer) string {
	switch {
	case r.MyIdentity != "":
		return r.MyIdentity
	case r.AgentId != "":
		return r.AgentId
	}
	return peer.ID
}

// accepted reports whether the receiver processed the message. Every
// receiver of the sync API sets Status "ok" on success; a reply without it
// (an empty object included) is not an acceptance.
func (r *apiReply) accepted() bool {
	return !r.Error && r.Status == "ok"
}

// Hello sends a hello handshake request to a peer via HTTPS API.
func (t *APITransport) Hello(ctx context.Context, peer *Peer, req *HelloRequest) (*HelloResponse, error) {
	url, err := apiURL(peer, "/hello")
	if err != nil {
		return nil, NewTransportError("API", "Hello", peer.ID, err, false)
	}

	respBody, err := t.doRequest(ctx, peer, "POST", url, buildHelloPost(req, peer.ID))
	if err != nil {
		return nil, NewTransportError("API", "Hello", peer.ID, err, true)
	}

	var reply apiReply
	if err := json.Unmarshal(respBody, &reply); err != nil {
		return nil, NewTransportError("API", "Hello", peer.ID,
			fmt.Errorf("failed to unmarshal response: %w", err), false)
	}

	if !reply.accepted() {
		reason := reply.ErrorMsg
		if reason == "" {
			reason = reply.Msg
		}
		return &HelloResponse{
			ResponderID:  reply.responderOf(peer),
			Accepted:     false,
			RejectReason: reason,
			Timestamp:    time.Now(),
		}, nil
	}

	return &HelloResponse{
		ResponderID: reply.responderOf(peer),
		Accepted:    true,
		Timestamp:   time.Now(),
		Nonce:       req.Nonce,
	}, nil
}

// Beat sends a heartbeat to a peer via HTTPS API.
func (t *APITransport) Beat(ctx context.Context, peer *Peer, req *BeatRequest) (*BeatResponse, error) {
	url, err := apiURL(peer, "/beat")
	if err != nil {
		return nil, NewTransportError("API", "Beat", peer.ID, err, false)
	}

	respBody, err := t.doRequest(ctx, peer, "POST", url, buildBeatPost(req, peer.ID))
	if err != nil {
		return nil, NewTransportError("API", "Beat", peer.ID, err, true)
	}

	var reply apiReply
	if err := json.Unmarshal(respBody, &reply); err != nil {
		return nil, NewTransportError("API", "Beat", peer.ID,
			fmt.Errorf("failed to unmarshal response: %w", err), false)
	}

	ack := reply.accepted()
	if ack {
		peer.recordMechanismBeatSent("API")
	}

	return &BeatResponse{
		ResponderID: reply.responderOf(peer),
		Timestamp:   time.Now(),
		Sequence:    req.Sequence,
		State:       reply.Msg,
		Ack:         ack,
		Gossip:      reply.Gossip,
	}, nil
}

// Ping sends a lightweight liveness probe to a peer via HTTPS API.
func (t *APITransport) Ping(ctx context.Context, peer *Peer, req *PingRequest) (*PingResponse, error) {
	url, err := apiURL(peer, "/sync/ping")
	if err != nil {
		return nil, NewTransportError("API", "Ping", peer.ID, err, false)
	}

	sendTime := time.Now()
	respBody, err := t.doRequest(ctx, peer, "POST", url, buildPingPost(req, peer.ID))
	rtt := time.Since(sendTime)
	if err != nil {
		return nil, NewTransportError("API", "Ping", peer.ID, err, true)
	}

	var reply apiReply
	if err := json.Unmarshal(respBody, &reply); err != nil {
		return nil, NewTransportError("API", "Ping", peer.ID,
			fmt.Errorf("failed to unmarshal response: %w", err), false)
	}

	return &PingResponse{
		ResponderID: reply.responderOf(peer),
		Nonce:       reply.Nonce,
		OK:          reply.accepted() && reply.Nonce == req.Nonce,
		Timestamp:   time.Now(),
		RTT:         rtt,
	}, nil
}

// Confirm posts a confirmation to the peer's /msg. The body is the confirm
// payload a DNS confirmation carries in its NOTIFY, so the receiver routes
// it to the same handler. It is a message of its own: the PENDING and the
// final confirmation of a SYNC come after the reply to the SYNC's POST.
//
// Every failure is retryable. Those that do not keep DNS from the
// receiver are not Answered, so that TransportManager.Confirm sends the
// confirmation over DNS instead: a receiver from before confirmations went
// over HTTPS answers that /msg does not take it (verbNotAccepted), and
// whatever else keeps the API from delivering it (a timeout, an endpoint
// that is not https, a reply that is not JSON). A receiver that took the
// confirmation and refused it (the sender is not the client certificate's
// identity, the handler refused it) has judged it; DNS would get the same
// answer, so that refusal is Answered (tdns-transport #36).
func (t *APITransport) Confirm(ctx context.Context, peer *Peer, req *ConfirmRequest) error {
	if req == nil {
		return NewTransportError("API", "Confirm", peer.ID, fmt.Errorf("empty confirmation"), false)
	}
	payload, err := json.Marshal(buildConfirmPayload(req))
	if err != nil {
		return NewTransportError("API", "Confirm", peer.ID,
			fmt.Errorf("failed to marshal confirm payload: %w", err), false)
	}
	resp, err := t.postMsg(ctx, peer, &AppMessage{
		Scope:          req.Zone,
		TypeToken:      VerbConfirm,
		Payload:        payload,
		DistributionID: req.DistributionID,
	})
	if err != nil {
		var te *TransportError
		if errors.As(err, &te) {
			err = te.Err
		}
		return NewTransportError("API", "Confirm", peer.ID, err, true)
	}
	if resp.Status != ConfirmSuccess {
		err := fmt.Errorf("recipient refused the confirmation: %s", resp.Message)
		if verbNotAccepted(resp.Message) {
			return NewTransportError("API", "Confirm", peer.ID, err, true)
		}
		return NewAnsweredTransportError("API", "Confirm", peer.ID, err)
	}
	peer.Stats.recordMessageSent(VerbConfirm)
	return nil
}

// clientFor is the client a request to peer goes through: one of its own,
// made from the shared HTTPClient, whose TLS config checks the peer's
// certificate against the peer's TLSA (VerifyConnection, chained after any
// the shared config has). It also dials the API address discovery found,
// when there is one: discovery found it, and validated it, with the node's
// own resolver, and the host need not have a system resolver at all. The
// URL keeps the name.
//
// When the peer's address or TLSA set changes, the old client's idle
// connections are closed, so none checked under the old set carries
// another request. Where the check cannot be installed (a proxy, a TLS
// dialer of the shared client's own, a transport other than
// *http.Transport), there is no client: an unchecked connection is not an
// option.
func (t *APITransport) clientFor(peer *Peer) (*http.Client, error) {
	base, ok := t.HTTPClient.Transport.(*http.Transport)
	if !ok || base.Proxy != nil || base.DialTLSContext != nil || base.DialTLS != nil {
		return nil, fmt.Errorf("the HTTPS client cannot check %s's certificate against its TLSA (a proxy, a TLS dialer of its own, or not an *http.Transport)", peer.ID)
	}
	hostport := ""
	if addr := peer.MechanismAddress("API"); addr != nil {
		hostport = addr.HostPort()
	}
	tlsa := tlsaKey(peer.MechanismTLSA("API").Records)

	t.mu.Lock()
	pc := t.clients[peer]
	if pc != nil && pc.addr == hostport && pc.tlsa == tlsa && pc.base == base && pc.client.Timeout == t.HTTPClient.Timeout {
		t.mu.Unlock()
		return pc.client, nil
	}
	tr := base.Clone()
	if hostport != "" {
		dial := base.DialContext
		if dial == nil {
			dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial(ctx, network, hostport)
		}
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	prev := tr.TLSClientConfig.VerifyConnection
	checker := t.TLSA
	// The handshake has no context of its own; its lookups get the
	// request's time limit (the cached one is instant after doRequest's).
	budget := t.HTTPClient.Timeout
	if budget <= 0 {
		budget = 2 * checker.lookupTimeout()
	}
	tr.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if prev != nil {
			if err := prev(cs); err != nil {
				return err
			}
		}
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("%w: %s presented no certificate", ErrTLSAMismatch, peer.ID)
		}
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		return checker.Check(ctx, peer, "API", cs.PeerCertificates[0])
	}
	if tr.IdleConnTimeout == 0 {
		tr.IdleConnTimeout = 90 * time.Second
	}
	client := &http.Client{
		Timeout:       t.HTTPClient.Timeout,
		CheckRedirect: refuseRedirect, // whatever the shared client says
		Transport:     tr,
	}
	if t.clients == nil {
		t.clients = make(map[*Peer]*peerClient)
	}
	t.clients[peer] = &peerClient{addr: hostport, tlsa: tlsa, base: base, client: client}
	t.mu.Unlock()

	if pc != nil {
		pc.client.CloseIdleConnections()
	}
	return client, nil
}

// ForgetPeer drops peer's client and closes its idle connections: the peer
// is gone from the registry (PeerRegistry.OnRemove).
func (t *APITransport) ForgetPeer(peer *Peer) {
	t.mu.Lock()
	pc := t.clients[peer]
	delete(t.clients, peer)
	t.mu.Unlock()
	if pc != nil {
		pc.client.CloseIdleConnections()
	}
}

// doRequest performs an HTTP request to peer and returns the response body.
func (t *APITransport) doRequest(ctx context.Context, peer *Peer, method, url string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	switch b := body.(type) {
	case nil:
	case json.RawMessage:
		reqBody = bytes.NewReader(b)
	default:
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// The TLSA set as the resolver has it now: a kept-alive connection does
	// no handshake, so the check there is this one. A peer with no TLSA to
	// check its certificate against is not dialed.
	if t.TLSA == nil {
		return nil, fmt.Errorf("%w: %s: the HTTPS client has no TLSA checker", ErrNoTLSA, peer.ID)
	}
	set, err := t.TLSA.Refresh(ctx, peer, "API")
	if err != nil {
		return nil, err
	}
	if len(set.Records) == 0 {
		t.TLSA.NoteNoTLSA(peer, set.Owner)
		return nil, fmt.Errorf("%w: %s (%s)", ErrNoTLSA, peer.ID, ownerOrUnknown(set.Owner))
	}
	client, err := t.clientFor(peer)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, url, string(respBody))
	}

	return respBody, nil
}
