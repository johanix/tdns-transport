/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Unit tests for the role-neutral router middleware.
 */

package transport

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestLoggingMiddleware(t *testing.T) {
	middleware := newLoggingMiddleware(false) // Non-verbose
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.PeerID = "peer1"
	ctx.DistributionID = "test-123"

	called := false
	err := middleware(ctx, func(ctx *MessageContext) error {
		called = true
		return nil
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if !called {
		t.Error("Next handler was not called")
	}
}

func TestMetricsMiddleware(t *testing.T) {
	metrics := make(map[string]float64)
	collector := &mockMetricsCollector{metrics: metrics}

	middleware := newMetricsMiddleware(collector)
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")

	err := middleware(ctx, func(ctx *MessageContext) error {
		return nil
	})
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if metrics["message.success"] != 1 {
		t.Errorf("Expected message.success=1, got %v", metrics["message.success"])
	}

	err = middleware(ctx, func(ctx *MessageContext) error {
		return errors.New("handler failed")
	})
	if err == nil {
		t.Fatal("Expected the handler error to be returned")
	}
	if metrics["message.errors"] != 1 {
		t.Errorf("Expected message.errors=1, got %v", metrics["message.errors"])
	}
}

// Mock metrics collector
type mockMetricsCollector struct {
	metrics map[string]float64
}

func (m *mockMetricsCollector) RecordMetric(name string, value float64) {
	m.metrics[name] = value
}
