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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APITransport implements the Transport interface using HTTPS REST API.
type APITransport struct {
	// LocalID is our own identity
	LocalID string

	// DefaultTimeout for API calls
	DefaultTimeout time.Duration

	// HTTPClient is the shared HTTP client (can be configured for TLS)
	HTTPClient *http.Client
}

// APITransportConfig holds configuration for creating an APITransport.
type APITransportConfig struct {
	LocalID        string
	DefaultTimeout time.Duration
	TLSConfig      *tls.Config
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

// apiURL returns the full URL for an API operation on a peer.
// Uses peer.APIEndpoint (the discovered base URI) when available,
// falling back to constructing from CurrentAddress().
func apiURL(peer *Peer, path string) (string, error) {
	if peer.APIEndpoint == "" {
		// API transport requires an explicit HTTPS endpoint. Falling
		// back to peer.CurrentAddress() (a DNS endpoint for DNS-only
		// peers) would produce structurally invalid HTTP URLs like
		// "udp://host:53/sync" — guaranteed to fail with
		// "unsupported protocol scheme udp". Refusing here gives
		// callers a clear error instead.
		return "", fmt.Errorf("peer %s has no API endpoint configured", peer.ID)
	}
	if err := requireHTTPS(peer.APIEndpoint); err != nil {
		return "", fmt.Errorf("peer %s: %w", peer.ID, err)
	}
	return peer.APIEndpoint + path, nil
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
// payloads), an application message posts its payload verbatim to /msg,
// and every reply is the receiver's {Status, Error, ErrorMsg, ...} object.
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

	respBody, err := t.doRequest(ctx, "POST", url, buildHelloPost(req, peer.ID))
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

	respBody, err := t.doRequest(ctx, "POST", url, buildBeatPost(req, peer.ID))
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
	}, nil
}

// Ping sends a lightweight liveness probe to a peer via HTTPS API.
func (t *APITransport) Ping(ctx context.Context, peer *Peer, req *PingRequest) (*PingResponse, error) {
	url, err := apiURL(peer, "/sync/ping")
	if err != nil {
		return nil, NewTransportError("API", "Ping", peer.ID, err, false)
	}

	sendTime := time.Now()
	respBody, err := t.doRequest(ctx, "POST", url, buildPingPost(req, peer.ID))
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

// Confirm is not carried by the HTTPS mechanism: a message's confirmation
// is the synchronous reply to the POST that delivered it. The DNS
// mechanism sends confirm NOTIFYs; there was never an HTTPS receiver.
func (t *APITransport) Confirm(ctx context.Context, peer *Peer, req *ConfirmRequest) error {
	return NewTransportError("API", "Confirm", peer.ID,
		fmt.Errorf("confirmations are not carried by the HTTPS mechanism"), false)
}

// doRequest performs an HTTP request and returns the response body.
func (t *APITransport) doRequest(ctx context.Context, method, url string, body interface{}) ([]byte, error) {
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

	resp, err := t.HTTPClient.Do(req)
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
