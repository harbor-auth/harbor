package httpserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestHealthMux(t *testing.T) {
	mux := NewHealthMux()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	res := rec.Result()
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want %d", res.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got := string(body); got != "ok" {
		t.Fatalf("GET /healthz body = %q, want %q", got, "ok")
	}
}

func TestHealthMux_MethodNotAllowed(t *testing.T) {
	mux := NewHealthMux()

	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// The method-specific pattern "GET /healthz" must not match POST.
	if rec.Result().StatusCode == http.StatusOK {
		t.Fatalf("POST /healthz unexpectedly returned 200")
	}
}

// discardLogger returns a logger that discards all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// getFreePort returns a free TCP port on localhost.
func getFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("failed to close port listener: %v", err)
	}
	return port
}

func TestRun_GracefulShutdown(t *testing.T) {
	port := getFreePort(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	ctx, cancel := context.WithCancel(context.Background())
	logger := discardLogger()

	mux := NewHealthMux()

	// Start the server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, addr, mux, logger)
	}()

	// Wait for the server to be ready by polling the health endpoint.
	if err := waitForServer(t, "http://"+addr+"/healthz", 2*time.Second); err != nil {
		t.Fatalf("server did not become ready: %v", err)
	}

	// Verify the server is serving requests.
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Cancel the context to trigger graceful shutdown.
	cancel()

	// Wait for Run to return.
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error on graceful shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within timeout")
	}
}

func TestRun_AddressInUse(t *testing.T) {
	// Bind a port to simulate "address already in use".
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind port: %v", err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			t.Errorf("failed to close listener: %v", err)
		}
	}()

	addr := ln.Addr().String()
	ctx := context.Background()
	logger := discardLogger()

	mux := NewHealthMux()

	// Try to start the server on the already-bound address.
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, addr, mux, logger)
	}()

	// Run should return an error quickly.
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Run returned nil, want address-in-use error")
		}
		// Any error from ListenAndServe on a bound port is the expected behavior.
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within timeout")
	}
}

func TestRun_ServesRequests(t *testing.T) {
	port := getFreePort(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := discardLogger()

	// Custom handler to verify requests are served.
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, addr, handler, logger)
	}()

	if err := waitForServer(t, "http://"+addr+"/", 2*time.Second); err != nil {
		t.Fatalf("server did not become ready: %v", err)
	}

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != "hello" {
		t.Fatalf("GET / body = %q, want %q", string(body), "hello")
	}

	cancel()
	<-errCh
}

// waitForServer polls the given URL until it responds or timeout expires.
func waitForServer(t *testing.T, url string, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return context.DeadlineExceeded
}
