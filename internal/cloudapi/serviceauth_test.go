package cloudapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// --- test signing helpers -----------------------------------------------

func encodeSegment(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func signES256(t *testing.T, priv *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	signingInput := encodeSegment(t, header) + "." + encodeSegment(t, claims)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func signEdDSA(t *testing.T, priv ed25519.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	signingInput := encodeSegment(t, header) + "." + encodeSegment(t, claims)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func pemEncodePublicKey(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// testEnv bundles a verifier wired to an ES256 trust anchor and miniredis
// replay guard, plus the signing key so tests can mint tokens.
type testEnv struct {
	verifier *ServiceAuthVerifier
	ecPriv   *ecdsa.PrivateKey
	mr       *miniredis.Miniredis
	now      time.Time
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	verifier, err := NewServiceAuthVerifier(ServiceAuthVerifierConfig{
		PublicKeyPEM: pemEncodePublicKey(t, &priv.PublicKey),
		ReplayGuard:  NewRedisReplayGuard(client),
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewServiceAuthVerifier: %v", err)
	}

	return &testEnv{verifier: verifier, ecPriv: priv, mr: mr, now: now}
}

func (e *testEnv) validClaims() map[string]any {
	return map[string]any{
		"iss":   "harbor-cloud",
		"sub":   "harbor-cloud-svc-1",
		"aud":   ExpectedAudience,
		"scope": "sessions:mint namespaces:read",
		"exp":   e.now.Add(90 * time.Second).Unix(),
		"iat":   e.now.Unix(),
		"jti":   "jti-1",
	}
}

func (e *testEnv) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	return signES256(t, e.ecPriv, map[string]any{"alg": "ES256", "typ": "JWT"}, claims)
}

// --- tests ---------------------------------------------------------------

func TestServiceAuthVerifierValid(t *testing.T) {
	env := newTestEnv(t)
	token := env.sign(t, env.validClaims())

	claims, err := env.verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if claims.Subject != "harbor-cloud-svc-1" {
		t.Errorf("Subject = %q, want harbor-cloud-svc-1", claims.Subject)
	}
	if claims.Audience != ExpectedAudience {
		t.Errorf("Audience = %q, want %q", claims.Audience, ExpectedAudience)
	}
	if claims.JTI != "jti-1" {
		t.Errorf("JTI = %q, want jti-1", claims.JTI)
	}
	wantScopes := []string{"sessions:mint", "namespaces:read"}
	if len(claims.Scopes) != len(wantScopes) {
		t.Fatalf("Scopes = %v, want %v", claims.Scopes, wantScopes)
	}
	for i, s := range wantScopes {
		if claims.Scopes[i] != s {
			t.Errorf("Scopes[%d] = %q, want %q", i, claims.Scopes[i], s)
		}
	}
	if !claims.HasScope("sessions:mint") {
		t.Error("HasScope(sessions:mint) = false, want true")
	}
	if claims.HasScope("keys:rotate") {
		t.Error("HasScope(keys:rotate) = true, want false")
	}
}

func TestServiceAuthVerifierEdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	verifier, err := NewServiceAuthVerifier(ServiceAuthVerifierConfig{
		PublicKeyPEM: pemEncodePublicKey(t, pub),
		ReplayGuard:  NewRedisReplayGuard(client),
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewServiceAuthVerifier: %v", err)
	}

	claims := map[string]any{
		"iss": "harbor-cloud", "sub": "harbor-cloud-svc-1", "aud": ExpectedAudience,
		"scope": "keys:rotate", "exp": now.Add(60 * time.Second).Unix(), "iat": now.Unix(), "jti": "jti-ed",
	}
	token := signEdDSA(t, priv, map[string]any{"alg": "EdDSA", "typ": "JWT"}, claims)

	got, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if got.Subject != "harbor-cloud-svc-1" {
		t.Errorf("Subject = %q, want harbor-cloud-svc-1", got.Subject)
	}
}

func TestServiceAuthVerifierWrongAudience(t *testing.T) {
	env := newTestEnv(t)
	claims := env.validClaims()
	claims["aud"] = "some-other-audience"
	token := env.sign(t, claims)

	_, err := env.verifier.Verify(context.Background(), token)
	if !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("Verify error = %v, want ErrWrongAudience", err)
	}
}

func TestServiceAuthVerifierMissingScope(t *testing.T) {
	env := newTestEnv(t)
	claims := env.validClaims()
	delete(claims, "scope")
	token := env.sign(t, claims)

	_, err := env.verifier.Verify(context.Background(), token)
	if !errors.Is(err, ErrMissingScope) {
		t.Fatalf("Verify error = %v, want ErrMissingScope", err)
	}

	claims2 := env.validClaims()
	claims2["scope"] = "   "
	claims2["jti"] = "jti-blank-scope"
	token2 := env.sign(t, claims2)
	if _, err := env.verifier.Verify(context.Background(), token2); !errors.Is(err, ErrMissingScope) {
		t.Fatalf("Verify (blank scope) error = %v, want ErrMissingScope", err)
	}
}

func TestServiceAuthVerifierExpired(t *testing.T) {
	env := newTestEnv(t)
	claims := env.validClaims()
	claims["exp"] = env.now.Add(-1 * time.Second).Unix()
	token := env.sign(t, claims)

	_, err := env.verifier.Verify(context.Background(), token)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify error = %v, want ErrExpired", err)
	}
}

//harbor:invariant INV-CLOUDAPI-REPLAY-RESISTANT
func TestServiceAuthVerifierReplayed(t *testing.T) {
	env := newTestEnv(t)
	token := env.sign(t, env.validClaims())

	if _, err := env.verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("first Verify: unexpected error: %v", err)
	}
	_, err := env.verifier.Verify(context.Background(), token)
	if !errors.Is(err, ErrReplayed) {
		t.Fatalf("second Verify error = %v, want ErrReplayed", err)
	}
}

func TestServiceAuthVerifierReplayAllowedAfterExpiry(t *testing.T) {
	env := newTestEnv(t)
	claims := env.validClaims()
	claims["exp"] = env.now.Add(30 * time.Second).Unix()
	token := env.sign(t, claims)

	if _, err := env.verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("first Verify: unexpected error: %v", err)
	}
	// The replay-guard TTL is bounded by the token's own exp, so once the key
	// naturally expires in Redis a *new* token reusing the same jti (which
	// would only be possible after the old one is already unusable) is not
	// spuriously blocked forever.
	env.mr.FastForward(31 * time.Second)

	claims2 := env.validClaims()
	claims2["exp"] = env.now.Add(90 * time.Second).Unix() // still "now" per the frozen clock
	token2 := env.sign(t, claims2)
	if _, err := env.verifier.Verify(context.Background(), token2); err != nil {
		t.Fatalf("Verify after replay-guard TTL elapsed: unexpected error: %v", err)
	}
}

func TestServiceAuthVerifierUnconfiguredTrustAnchor(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup

	verifier, err := NewServiceAuthVerifier(ServiceAuthVerifierConfig{
		ReplayGuard: NewRedisReplayGuard(client),
	})
	if err != nil {
		t.Fatalf("NewServiceAuthVerifier: %v", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	now := time.Now()
	claims := map[string]any{
		"iss": "harbor-cloud", "sub": "harbor-cloud-svc-1", "aud": ExpectedAudience,
		"scope": "sessions:mint", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "jti": "jti-x",
	}
	token := signES256(t, priv, map[string]any{"alg": "ES256", "typ": "JWT"}, claims)

	_, err = verifier.Verify(context.Background(), token)
	if !errors.Is(err, ErrTrustAnchorUnconfigured) {
		t.Fatalf("Verify error = %v, want ErrTrustAnchorUnconfigured", err)
	}
}

func TestServiceAuthVerifierUnconfiguredReplayGuard(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	now := time.Now()
	verifier, err := NewServiceAuthVerifier(ServiceAuthVerifierConfig{
		PublicKeyPEM: pemEncodePublicKey(t, &priv.PublicKey),
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewServiceAuthVerifier: %v", err)
	}

	claims := map[string]any{
		"iss": "harbor-cloud", "sub": "harbor-cloud-svc-1", "aud": ExpectedAudience,
		"scope": "sessions:mint", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "jti": "jti-y",
	}
	token := signES256(t, priv, map[string]any{"alg": "ES256", "typ": "JWT"}, claims)

	_, err = verifier.Verify(context.Background(), token)
	if !errors.Is(err, ErrReplayGuardUnavailable) {
		t.Fatalf("Verify error = %v, want ErrReplayGuardUnavailable", err)
	}
}

func TestServiceAuthVerifierMalformedAndAlgConfusion(t *testing.T) {
	env := newTestEnv(t)

	t.Run("not three segments", func(t *testing.T) {
		_, err := env.verifier.Verify(context.Background(), "not-a-jwt")
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("Verify error = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		claims := env.validClaims()
		token := signES256(t, env.ecPriv, map[string]any{"alg": "HS256", "typ": "JWT"}, claims)
		_, err := env.verifier.Verify(context.Background(), token)
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("Verify error = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("wrong signing key", func(t *testing.T) {
		otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ec key: %v", err)
		}
		claims := env.validClaims()
		claims["jti"] = "jti-wrong-key"
		token := signES256(t, otherPriv, map[string]any{"alg": "ES256", "typ": "JWT"}, claims)
		_, err = env.verifier.Verify(context.Background(), token)
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("Verify error = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("missing required claim", func(t *testing.T) {
		claims := env.validClaims()
		delete(claims, "jti")
		token := env.sign(t, claims)
		_, err := env.verifier.Verify(context.Background(), token)
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("Verify error = %v, want ErrInvalidToken", err)
		}
	})
}

func TestConstantTimeStringEqual(t *testing.T) {
	if !constantTimeStringEqual("harbor-mgmt-cloudapi", "harbor-mgmt-cloudapi") {
		t.Error("expected equal strings to compare equal")
	}
	if constantTimeStringEqual("harbor-mgmt-cloudapi", "something-else") {
		t.Error("expected different strings to compare unequal")
	}
	if constantTimeStringEqual("short", "much-longer-string") {
		t.Error("expected different-length strings to compare unequal")
	}
}

func TestRouteFromContext(t *testing.T) {
	if got := routeFromContext(context.Background()); got != "unknown" {
		t.Errorf("routeFromContext(bare ctx) = %q, want unknown", got)
	}
	ctx := WithRoute(context.Background(), "POST /admin/v1/sessions")
	if got := routeFromContext(ctx); got != "POST /admin/v1/sessions" {
		t.Errorf("routeFromContext = %q, want POST /admin/v1/sessions", got)
	}
}

// --- §7: multi-anchor trust with per-key scope binding --------------------

// TestServiceAuthVerifierPerAnchorScopeBinding is the test the design
// earns: a trust anchor configured with a restricted AllowedScopes set can
// only ever produce accepted claims for scopes within that set — even
// though a token's own `scope` claim is self-asserted and would otherwise
// be trusted verbatim. Without this, handing the SAML-bridge caller the
// same signing key as the main provisioning service would let it mint a
// token claiming keys:rotate.
func TestServiceAuthVerifierPerAnchorScopeBinding(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	verifier, err := NewServiceAuthVerifier(ServiceAuthVerifierConfig{
		Anchors: []TrustAnchorConfig{
			{PublicKeyPEM: pemEncodePublicKey(t, &priv.PublicKey), AllowedScopes: []string{"user-sessions:mint"}},
		},
		ReplayGuard: NewRedisReplayGuard(client),
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewServiceAuthVerifier: %v", err)
	}

	sign := func(scope, jti string) string {
		claims := map[string]any{
			"iss": "harbor-cloud", "sub": "saml-bridge", "aud": ExpectedAudience,
			"scope": scope, "exp": now.Add(90 * time.Second).Unix(), "iat": now.Unix(), "jti": jti,
		}
		return signES256(t, priv, map[string]any{"alg": "ES256", "typ": "JWT"}, claims)
	}

	t.Run("permitted scope is accepted", func(t *testing.T) {
		claims, err := verifier.Verify(context.Background(), sign("user-sessions:mint", "jti-permitted"))
		if err != nil {
			t.Fatalf("Verify: unexpected error: %v", err)
		}
		if !claims.HasScope("user-sessions:mint") {
			t.Error("HasScope(user-sessions:mint) = false, want true")
		}
	})

	t.Run("scope outside the key's set is rejected", func(t *testing.T) {
		_, err := verifier.Verify(context.Background(), sign("keys:rotate", "jti-forbidden"))
		if !errors.Is(err, ErrScopeNotPermittedForAnchor) {
			t.Fatalf("Verify error = %v, want ErrScopeNotPermittedForAnchor", err)
		}
	})

	t.Run("a token mixing a permitted and a forbidden scope is rejected in full, not partially honoured", func(t *testing.T) {
		_, err := verifier.Verify(context.Background(), sign("user-sessions:mint keys:rotate", "jti-mixed"))
		if !errors.Is(err, ErrScopeNotPermittedForAnchor) {
			t.Fatalf("Verify error = %v, want ErrScopeNotPermittedForAnchor", err)
		}
	})
}

// TestServiceAuthVerifierLegacySingleAnchorPermitsAllScopes proves
// PublicKeyPEM's back-compat contract: the single legacy anchor may assert
// ANY scope, matching pre-§7 behavior, so an existing deployment's config
// keeps working unmodified.
func TestServiceAuthVerifierLegacySingleAnchorPermitsAllScopes(t *testing.T) {
	env := newTestEnv(t)
	claims := env.validClaims()
	claims["scope"] = "keys:rotate"
	claims["jti"] = "jti-legacy-all-scopes"

	got, err := env.verifier.Verify(context.Background(), env.sign(t, claims))
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if !got.HasScope("keys:rotate") {
		t.Error("HasScope(keys:rotate) = false, want true (legacy single anchor permits all scopes)")
	}
}

// TestServiceAuthVerifierMultipleAnchorsEachScopedIndependently proves two
// distinct anchors (e.g. the main provisioning service and the SAML bridge)
// coexist under one verifier, each enforcing only its own permitted scopes.
func TestServiceAuthVerifierMultipleAnchorsEachScopedIndependently(t *testing.T) {
	mainPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	samlPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	verifier, err := NewServiceAuthVerifier(ServiceAuthVerifierConfig{
		Anchors: []TrustAnchorConfig{
			{PublicKeyPEM: pemEncodePublicKey(t, &mainPriv.PublicKey), AllowedScopes: []string{"sessions:mint", "namespaces:read", "namespaces:write", "keys:rotate"}},
			{PublicKeyPEM: pemEncodePublicKey(t, &samlPriv.PublicKey), AllowedScopes: []string{"user-sessions:mint"}},
		},
		ReplayGuard: NewRedisReplayGuard(client),
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewServiceAuthVerifier: %v", err)
	}

	sign := func(priv *ecdsa.PrivateKey, scope, jti string) string {
		claims := map[string]any{
			"iss": "harbor-cloud", "sub": "svc", "aud": ExpectedAudience,
			"scope": scope, "exp": now.Add(90 * time.Second).Unix(), "iat": now.Unix(), "jti": jti,
		}
		return signES256(t, priv, map[string]any{"alg": "ES256", "typ": "JWT"}, claims)
	}

	if _, err := verifier.Verify(context.Background(), sign(mainPriv, "keys:rotate", "jti-main")); err != nil {
		t.Errorf("main anchor keys:rotate: unexpected error: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), sign(samlPriv, "user-sessions:mint", "jti-saml")); err != nil {
		t.Errorf("saml anchor user-sessions:mint: unexpected error: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), sign(samlPriv, "keys:rotate", "jti-saml-escalate")); !errors.Is(err, ErrScopeNotPermittedForAnchor) {
		t.Errorf("saml anchor keys:rotate = %v, want ErrScopeNotPermittedForAnchor", err)
	}
}

// TestParseTrustAnchorsEnv covers CLOUD_SERVICE_AUTH_PUBLIC_KEYS's parse
// format: "<scope>[,<scope>...] <pem, \n-escaped>" per line, comments/blank
// lines skipped, and malformed lines rejected (boot-time fail-fast).
func TestParseTrustAnchorsEnv(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	escaped := strings.ReplaceAll(pemEncodePublicKey(t, &priv.PublicKey), "\n", `\n`)

	t.Run("valid single anchor", func(t *testing.T) {
		anchors, err := ParseTrustAnchorsEnv("user-sessions:mint " + escaped)
		if err != nil {
			t.Fatalf("ParseTrustAnchorsEnv: %v", err)
		}
		if len(anchors) != 1 {
			t.Fatalf("got %d anchors, want 1", len(anchors))
		}
		if len(anchors[0].AllowedScopes) != 1 || anchors[0].AllowedScopes[0] != "user-sessions:mint" {
			t.Errorf("AllowedScopes = %v, want [user-sessions:mint]", anchors[0].AllowedScopes)
		}
	})

	t.Run("comments and blank lines are skipped", func(t *testing.T) {
		raw := "# a comment\n\nuser-sessions:mint " + escaped + "\n"
		anchors, err := ParseTrustAnchorsEnv(raw)
		if err != nil {
			t.Fatalf("ParseTrustAnchorsEnv: %v", err)
		}
		if len(anchors) != 1 {
			t.Fatalf("got %d anchors, want 1", len(anchors))
		}
	})

	t.Run("multiple comma-separated scopes", func(t *testing.T) {
		anchors, err := ParseTrustAnchorsEnv("sessions:mint,namespaces:read " + escaped)
		if err != nil {
			t.Fatalf("ParseTrustAnchorsEnv: %v", err)
		}
		if len(anchors[0].AllowedScopes) != 2 {
			t.Fatalf("AllowedScopes = %v, want 2 entries", anchors[0].AllowedScopes)
		}
	})

	for name, raw := range map[string]string{
		"missing pem (no space in line)": "user-sessions:mint",
		"empty scope in list":            ", " + escaped,
	} {
		t.Run("malformed: "+name, func(t *testing.T) {
			if _, err := ParseTrustAnchorsEnv(raw); err == nil {
				t.Fatalf("ParseTrustAnchorsEnv(%q): expected an error, got none", raw)
			}
		})
	}
}

// TestNewServiceAuthVerifierRejectsMalformedAnchor proves a malformed
// CLOUD_SERVICE_AUTH_PUBLIC_KEYS anchor fails boot (NewServiceAuthVerifier
// returns an error) rather than silently dropping that anchor — a dropped
// anchor would leave a deployment believing a caller is authorized when it
// silently is not.
func TestNewServiceAuthVerifierRejectsMalformedAnchor(t *testing.T) {
	if _, err := NewServiceAuthVerifier(ServiceAuthVerifierConfig{
		Anchors: []TrustAnchorConfig{{PublicKeyPEM: "not a pem", AllowedScopes: []string{"user-sessions:mint"}}},
	}); err == nil {
		t.Fatal("expected an error for a malformed anchor PEM")
	}
}

// TestNewServiceAuthVerifierRejectsEmptyNonNilAllowedScopes proves a
// TrustAnchorConfig with a non-nil but empty AllowedScopes is rejected at
// boot rather than silently treated as either "unrestricted" or
// "always-rejecting" — nil (unrestricted) must be spelled explicitly.
func TestNewServiceAuthVerifierRejectsEmptyNonNilAllowedScopes(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	if _, err := NewServiceAuthVerifier(ServiceAuthVerifierConfig{
		Anchors: []TrustAnchorConfig{{PublicKeyPEM: pemEncodePublicKey(t, &priv.PublicKey), AllowedScopes: []string{}}},
	}); err == nil {
		t.Fatal("expected an error for a non-nil, empty AllowedScopes")
	}
}
