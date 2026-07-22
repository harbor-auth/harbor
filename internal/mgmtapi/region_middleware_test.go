package mgmtapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// newRegionTestRequest builds a GET request with its Host set to host. The
// region middleware resolves from r.Host, so the target URL path is irrelevant.
func newRegionTestRequest(host string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/enroll", nil)
	req.Host = host
	return req
}

// TestRegionMiddlewarePinsKnownHost asserts that a request to a known
// region-prefixed host is pinned to the correct region and forwarded to the
// next handler, which can recover the region via region.FromContext (REQ-001,
// REQ-002).
func TestRegionMiddlewarePinsKnownHost(t *testing.T) {
	cases := []struct {
		host string
		want region.Region
	}{
		{"eu.harbor.id", region.EU},
		{"us.harbor.id", region.US},
		{"apac.harbor.id", region.APAC},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			var (
				called bool
				got    region.Region
				gotErr error
			)
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				got, gotErr = region.FromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})
			h := RegionMiddleware(telemetry.New(nil))(next)

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, newRegionTestRequest(tc.host))

			if !called {
				t.Fatalf("next handler not called for known host %q", tc.host)
			}
			if gotErr != nil {
				t.Fatalf("FromContext downstream error = %v, want nil", gotErr)
			}
			if got != tc.want {
				t.Fatalf("pinned region = %q, want %q", got, tc.want)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
		})
	}
}

// TestRegionMiddlewareRejectsUnknownHost asserts that a request whose Host does
// not map to a known region is rejected with 400 and the region_unknown error
// code, and the next handler is NEVER invoked (REQ-001 — total, fail-closed).
// The cold-path envelope uses the {error, message} shape (errorResponse).
func TestRegionMiddlewareRejectsUnknownHost(t *testing.T) {
	for _, host := range []string{"unknown.example", "harbor.id", ""} {
		t.Run(host, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			})
			h := RegionMiddleware(telemetry.New(nil))(next)

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, newRegionTestRequest(host))

			if called {
				t.Fatalf("next handler was called for unknown host %q; must fail closed", host)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			var body errorResponse
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode error body: %v", err)
			}
			if body.Error != regionUnknownCode {
				t.Fatalf("error code = %q, want %q", body.Error, regionUnknownCode)
			}
		})
	}
}

// TestRegionMiddlewarePassesControlOnSuccess asserts the middleware forwards to
// the next handler (and does not write the response itself) on a resolvable
// host, leaving status and body to the downstream handler.
func TestRegionMiddlewarePassesControlOnSuccess(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("downstream"))
	})
	h := RegionMiddleware(telemetry.New(nil))(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newRegionTestRequest("eu.harbor.id"))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d (downstream handler should own the response)", rec.Code, http.StatusTeapot)
	}
	if rec.Body.String() != "downstream" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "downstream")
	}
}

// TestRegionMiddlewareExemptsHealthz asserts that a liveness/readiness probe
// hitting /healthz from a bare pod IP (which does not map to any region) is
// NOT rejected with 400 — it passes through un-pinned to the next handler.
// This prevents kubelet probes from being killed by the region gate.
func TestRegionMiddlewareExemptsHealthz(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	h := RegionMiddleware(telemetry.New(nil))(next)

	// Simulate a kubelet liveness probe: Host is the bare pod IP, path is /healthz.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Host = "10.42.0.40:8081" // bare pod IP — maps to no region

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatal("next handler not called for /healthz on unknown host; probe must not be region-gated")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for /healthz probe", rec.Code)
	}
}

// TestRegionMiddlewareResolvesIssuerStyleHost confirms an issuer-style host
// with a port still resolves, matching region.Resolve's normalisation.
func TestRegionMiddlewareResolvesIssuerStyleHost(t *testing.T) {
	var (
		got    region.Region
		gotErr error
	)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, gotErr = region.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := RegionMiddleware(telemetry.New(nil))(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newRegionTestRequest("us.harbor.id:443"))

	if gotErr != nil {
		t.Fatalf("FromContext downstream error = %v, want nil", gotErr)
	}
	if got != region.US {
		t.Fatalf("pinned region = %q, want %q", got, region.US)
	}
}
