package oidc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mockOutboxDeliverer is a test fake for OutboxDeliverer.
type mockOutboxDeliverer struct {
	mu           sync.Mutex
	deliverFunc  func(ctx context.Context, sink SessionStore) error
	deliverCalls int
	lastSink     SessionStore
}

func (m *mockOutboxDeliverer) DeliverPending(ctx context.Context, sink SessionStore) error {
	m.mu.Lock()
	m.deliverCalls++
	m.lastSink = sink
	fn := m.deliverFunc
	m.mu.Unlock()

	if fn != nil {
		return fn(ctx, sink)
	}
	return nil
}

func (m *mockOutboxDeliverer) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deliverCalls
}

func TestNewRevocationWorker_PanicsOnNilOutbox(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil Outbox")
		}
	}()

	NewRevocationWorker(RevocationWorkerConfig{
		Outbox:       nil,
		SessionStore: NewInMemorySessionStore(),
	})
}

func TestNewRevocationWorker_PanicsOnNilSessionStore(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil SessionStore")
		}
	}()

	NewRevocationWorker(RevocationWorkerConfig{
		Outbox:       &mockOutboxDeliverer{},
		SessionStore: nil,
	})
}

func TestNewRevocationWorker_DefaultsTickInterval(t *testing.T) {
	outbox := &mockOutboxDeliverer{}
	store := NewInMemorySessionStore()

	w := NewRevocationWorker(RevocationWorkerConfig{
		Outbox:       outbox,
		SessionStore: store,
		// TickInterval not set — should default to 5s
	})

	if w.tickInterval != 5*time.Second {
		t.Errorf("tickInterval = %v, want 5s", w.tickInterval)
	}
}

func TestRevocationWorker_Run_CallsDeliverPending(t *testing.T) {
	outbox := &mockOutboxDeliverer{}
	store := NewInMemorySessionStore()

	w := NewRevocationWorker(RevocationWorkerConfig{
		Outbox:       outbox,
		SessionStore: store,
		TickInterval: 10 * time.Millisecond, // fast for testing
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Run the worker in a goroutine
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	// Wait for at least 2 ticks
	time.Sleep(30 * time.Millisecond)

	// Cancel and wait for shutdown
	cancel()
	select {
	case <-done:
		// OK
	case <-time.After(time.Second):
		t.Fatal("worker did not shut down in time")
	}

	// Verify DeliverPending was called at least once
	calls := outbox.callCount()
	if calls < 1 {
		t.Errorf("DeliverPending called %d times, want >= 1", calls)
	}
}

func TestRevocationWorker_Run_GracefulShutdown(t *testing.T) {
	outbox := &mockOutboxDeliverer{}
	store := NewInMemorySessionStore()

	w := NewRevocationWorker(RevocationWorkerConfig{
		Outbox:       outbox,
		SessionStore: store,
		TickInterval: time.Hour, // long interval so we don't tick during test
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	// Give the worker time to start
	time.Sleep(10 * time.Millisecond)

	// Cancel immediately
	cancel()

	// Worker should shut down quickly
	select {
	case <-done:
		// OK — graceful shutdown worked
	case <-time.After(100 * time.Millisecond):
		t.Fatal("worker did not shut down gracefully")
	}
}

func TestRevocationWorker_Run_ContinuesAfterError(t *testing.T) {
	callCount := 0
	outbox := &mockOutboxDeliverer{
		deliverFunc: func(ctx context.Context, sink SessionStore) error {
			callCount++
			if callCount == 1 {
				return errors.New("transient error")
			}
			return nil
		},
	}
	store := NewInMemorySessionStore()

	w := NewRevocationWorker(RevocationWorkerConfig{
		Outbox:       outbox,
		SessionStore: store,
		TickInterval: 10 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	// Wait for multiple ticks
	time.Sleep(50 * time.Millisecond)

	cancel()
	<-done

	// Verify multiple calls happened despite the first error
	calls := outbox.callCount()
	if calls < 2 {
		t.Errorf("DeliverPending called %d times, want >= 2 (should continue after error)", calls)
	}
}

func TestRevocationWorker_Run_PassesCorrectSink(t *testing.T) {
	outbox := &mockOutboxDeliverer{}
	store := NewInMemorySessionStore()

	w := NewRevocationWorker(RevocationWorkerConfig{
		Outbox:       outbox,
		SessionStore: store,
		TickInterval: 10 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	// Wait for at least one tick
	time.Sleep(20 * time.Millisecond)

	cancel()
	<-done

	// Verify the correct SessionStore was passed
	outbox.mu.Lock()
	lastSink := outbox.lastSink
	outbox.mu.Unlock()

	if lastSink != store {
		t.Error("DeliverPending was called with wrong SessionStore")
	}
}
