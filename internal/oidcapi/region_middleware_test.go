package oidcapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harbor/harbor/internal/gen/openapi"
	"github.com/harbor/harbor/internal/region"
	"github.com/harbor/harbor/internal/telemetry"
)

// newTestRequest builds a GET request with its Host set to host. The region
// middleware resolves from r.Host, so the target URL path is irrelevant.
func newTestRequest(host string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
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
			h.ServeHTTP(rec, newTestRequest(tc.host))

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
func TestRegionMiddlewareRejectsUnknownHost(t *testing.T) {
	for _, host := range []string{"unknown.example", "harbor.id", ""} {
		t.Run(host, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			})
			h := RegionMiddleware(telemetry.New(nil))(next)

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, newTestRequest(host))

			if called {
				t.Fatalf("next handler was called for unknown host %q; must fail closed", host)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			var body openapi.Error
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode error body: %v", err)
			}
			if body.Code != regionUnknownCode {
				t.Fatalf("error code = %q, want %q", body.Code, regionUnknownCode)
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
	h.ServeHTTP(rec, newTestRequest("eu.harbor.id"))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d (downstream handler should own the response)", rec.Code, http.StatusTeapot)
	}
	if rec.Body.String() != "downstream" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "downstream")
	}
}

// TestRegionMiddlewareResolvesIssuerStyleHost confirms an issuer-style host
// with a port still resolves, matching region.Resolve's normalisation.
func TestRegionMiddlewareResolvesIssuerStyleHost(t *testing.T) {
	var got region.Region
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = region.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := RegionMiddleware(telemetry.New(nil))(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newTestRequest("us.harbor.id:443"))

	if got != region.US {
		t.Fatalf("pinned region = %q, want %q", got, region.US)
	}
}
