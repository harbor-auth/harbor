package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/crypto"
)

func hotStartupAssembly(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", source, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "run" {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		return string(source[start:end])
	}
	t.Fatal("harbor-hot startup must be isolated in run so failures can be tested before listen")
	return ""
}

func TestStartupRejectsMissingProductionConfigurationBeforeListen(t *testing.T) {
	startup := hotStartupAssembly(t)
	listen := strings.Index(startup, "httpserver.Run(")
	if listen < 0 {
		t.Fatal("harbor-hot startup does not contain the HTTP listen boundary")
	}

	for name, marker := range map[string]string{
		"PostgreSQL":          `production requires DATABASE_URL`,
		"Redis":               `production requires REDIS_URL`,
		"issuer URL":          `validateProductionURL("ISSUER"`,
		"login URL":           `validateProductionURL("LOGIN_URL"`,
		"shared user-DEK KEK": `HARBOR_KMS_SECRET`,
	} {
		check := strings.Index(startup, marker)
		if check < 0 {
			t.Errorf("harbor-hot startup does not reject missing %s (want %q)", name, marker)
			continue
		}
		if check > listen {
			t.Errorf("harbor-hot checks %s after its HTTP listen boundary", name)
		}
	}
}

func TestBFFConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     bffConfig
		wantErr bool
	}{
		{
			name: "empty LOGIN_URL is valid (dev mode)",
			cfg: bffConfig{
				LoginURL:   "",
				SessionTTL: 5 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "valid https LOGIN_URL",
			cfg: bffConfig{
				LoginURL:   "https://auth.example.com/login",
				SessionTTL: 5 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "valid http LOGIN_URL (localhost dev)",
			cfg: bffConfig{
				LoginURL:   "http://localhost:8081/login",
				SessionTTL: 5 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "LOGIN_URL missing scheme",
			cfg: bffConfig{
				LoginURL:   "example.com/login",
				SessionTTL: 5 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "LOGIN_URL with invalid scheme",
			cfg: bffConfig{
				LoginURL:   "ftp://example.com/login",
				SessionTTL: 5 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "LOGIN_URL missing host",
			cfg: bffConfig{
				LoginURL:   "https:///login",
				SessionTTL: 5 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "zero SessionTTL is invalid",
			cfg: bffConfig{
				LoginURL:   "",
				SessionTTL: 0,
			},
			wantErr: true,
		},
		{
			name: "negative SessionTTL is invalid",
			cfg: bffConfig{
				LoginURL:   "",
				SessionTTL: -1 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "all fields valid",
			cfg: bffConfig{
				LoginURL:    "https://auth.example.com/login",
				DatabaseURL: "postgres://user:pass@db:5432/harbor",
				SessionTTL:  10 * time.Minute,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProductionBFFConfigRejectsInsecureLoginURL(t *testing.T) {
	t.Setenv("HARBOR_DEV_MODE", "")
	cfg := bffConfig{LoginURL: "http://login.example.com/login", SessionTTL: 5 * time.Minute}
	if err := cfg.validate(); err == nil {
		t.Fatal("production accepted an HTTP LOGIN_URL; browser authentication redirects must use HTTPS")
	}
}

func TestProductionStartupValidatesAbuseAndExternalURLs(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	assembly := string(source)
	for _, required := range []string{
		"RATE_LIMIT_DISABLED is not allowed in production",
		"validateProductionURL(\"ISSUER\"",
		"validateProductionURL(\"LOGIN_URL\"",
	} {
		if !strings.Contains(assembly, required) {
			t.Errorf("production harbor-hot startup does not enforce %q", required)
		}
	}
}

func TestLoadBFFConfig(t *testing.T) {
	// Save and restore environment after test.
	restore := func(keys ...string) func() {
		saved := make(map[string]string)
		for _, k := range keys {
			saved[k] = envString(k, "")
		}
		return func() {
			for k, v := range saved {
				if v == "" {
					t.Setenv(k, "")
				} else {
					t.Setenv(k, v)
				}
			}
		}
	}

	t.Run("defaults when env unset", func(t *testing.T) {
		defer restore("LOGIN_URL", "DATABASE_URL", "BFF_SESSION_TTL")()
		t.Setenv("LOGIN_URL", "")
		t.Setenv("DATABASE_URL", "")
		t.Setenv("BFF_SESSION_TTL", "")

		cfg, err := loadBFFConfig()
		if err != nil {
			t.Fatalf("loadBFFConfig() error = %v", err)
		}
		if cfg.LoginURL != "" {
			t.Errorf("LoginURL = %q, want empty", cfg.LoginURL)
		}
		if cfg.DatabaseURL != "" {
			t.Errorf("DatabaseURL = %q, want empty", cfg.DatabaseURL)
		}
		if cfg.SessionTTL != defaultBFFSessionTTL {
			t.Errorf("SessionTTL = %v, want %v", cfg.SessionTTL, defaultBFFSessionTTL)
		}
	})

	t.Run("reads env vars", func(t *testing.T) {
		defer restore("LOGIN_URL", "DATABASE_URL", "BFF_SESSION_TTL")()
		t.Setenv("LOGIN_URL", "https://auth.example.com/login")
		t.Setenv("DATABASE_URL", "postgres://localhost/harbor")
		t.Setenv("BFF_SESSION_TTL", "10m")

		cfg, err := loadBFFConfig()
		if err != nil {
			t.Fatalf("loadBFFConfig() error = %v", err)
		}
		if cfg.LoginURL != "https://auth.example.com/login" {
			t.Errorf("LoginURL = %q, want %q", cfg.LoginURL, "https://auth.example.com/login")
		}
		if cfg.DatabaseURL != "postgres://localhost/harbor" {
			t.Errorf("DatabaseURL = %q, want %q", cfg.DatabaseURL, "postgres://localhost/harbor")
		}
		if cfg.SessionTTL != 10*time.Minute {
			t.Errorf("SessionTTL = %v, want %v", cfg.SessionTTL, 10*time.Minute)
		}
	})

	t.Run("invalid LOGIN_URL fails", func(t *testing.T) {
		defer restore("LOGIN_URL", "DATABASE_URL", "BFF_SESSION_TTL")()
		t.Setenv("LOGIN_URL", "not-a-valid-url")
		t.Setenv("DATABASE_URL", "")
		t.Setenv("BFF_SESSION_TTL", "")

		_, err := loadBFFConfig()
		if err == nil {
			t.Error("loadBFFConfig() expected error for invalid LOGIN_URL")
		}
	})

	t.Run("invalid BFF_SESSION_TTL falls back to default", func(t *testing.T) {
		defer restore("LOGIN_URL", "DATABASE_URL", "BFF_SESSION_TTL")()
		t.Setenv("LOGIN_URL", "")
		t.Setenv("DATABASE_URL", "")
		t.Setenv("BFF_SESSION_TTL", "not-a-duration")

		cfg, err := loadBFFConfig()
		if err != nil {
			t.Fatalf("loadBFFConfig() error = %v", err)
		}
		// envDuration falls back to default on invalid input
		if cfg.SessionTTL != defaultBFFSessionTTL {
			t.Errorf("SessionTTL = %v, want default %v", cfg.SessionTTL, defaultBFFSessionTTL)
		}
	})
}

func TestBuildBFFDeps(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("returns nil deps when pool is nil", func(t *testing.T) {
		// buildBFFDepsFromPool accepts a nil pool (DATABASE_URL unset path) and
		// returns zero-value deps — the caller falls back to dev-mode stub.
		deps, err := buildBFFDepsFromPool(nil, logger)
		if err != nil {
			t.Fatalf("buildBFFDepsFromPool() error = %v", err)
		}
		if deps.secretLoader != nil {
			t.Error("secretLoader should be nil when pool is nil")
		}
		if deps.grantStore != nil {
			t.Error("grantStore should be nil when pool is nil")
		}
	})
}

func TestLoadAdminToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// A 32-byte token for production tests.
	const validToken = "12345678901234567890123456789012" // exactly 32 bytes
	const shortToken = "tooshort"                         // 8 bytes < 32

	tests := []struct {
		name       string
		dbSet      bool
		devMode    string
		adminToken string
		wantErr    bool
		wantToken  string
	}{
		{
			name:      "no DB, token unset => no error, empty token",
			dbSet:     false,
			wantErr:   false,
			wantToken: "",
		},
		{
			name:       "no DB, token set => no error, token returned",
			dbSet:      false,
			adminToken: validToken,
			wantErr:    false,
			wantToken:  validToken,
		},
		{
			name:    "DB set, prod, token unset => error",
			dbSet:   true,
			wantErr: true,
		},
		{
			name:       "DB set, prod, token too short => error",
			dbSet:      true,
			adminToken: shortToken,
			wantErr:    true,
		},
		{
			name:       "DB set, prod, token >= 32 bytes => ok",
			dbSet:      true,
			adminToken: validToken,
			wantErr:    false,
			wantToken:  validToken,
		},
		{
			name:    "DB set, dev mode, token unset => ok (warn only)",
			dbSet:   true,
			devMode: "1",
			wantErr: false,
		},
		{
			name:       "DB set, dev mode, token short => ok (warn only)",
			dbSet:      true,
			devMode:    "1",
			adminToken: shortToken,
			wantErr:    false,
			wantToken:  shortToken,
		},
		{
			name:       "DB set, dev mode, token valid => ok",
			dbSet:      true,
			devMode:    "1",
			adminToken: validToken,
			wantErr:    false,
			wantToken:  validToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ADMIN_API_TOKEN", tt.adminToken)
			t.Setenv("HARBOR_DEV_MODE", tt.devMode)

			got, err := loadAdminToken(tt.dbSet, logger)
			if (err != nil) != tt.wantErr {
				t.Fatalf("loadAdminToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.wantToken {
				t.Errorf("loadAdminToken() = %q, want %q", got, tt.wantToken)
			}
		})
	}
}

func TestProductionReadinessRequiresCompleteDurableGraph(t *testing.T) {
	t.Setenv("HARBOR_DEV_MODE", "")
	t.Setenv("REDIS_URL", "")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := validateProductionReadiness(bffConfig{}, bffDeps{}, logger)
	if err == nil {
		t.Fatal("validateProductionReadiness() accepted an empty production graph")
	}

	// Keep this list at the object-graph boundary. A configured URL alone is
	// not proof that the live service received the durable implementation.
	for _, dependency := range []string{
		"PostgreSQL",
		"Redis",
		"external KMS",
		"durable client registry",
		"durable authorization code store",
		"durable grant store",
		"durable session store",
		"durable revocation store",
		"revocation outbox worker",
		"JWT verifier",
		"logout verifier",
		"session revoker",
	} {
		if !strings.Contains(err.Error(), dependency) {
			t.Errorf("startup error %q does not identify missing %s", err, dependency)
		}
	}
}

func TestProductionLiveGraphContainsNoScaffoldConstructors(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	start := strings.Index(string(source), "func run(")
	end := strings.Index(string(source), "// noopSessionRevoker")
	if start < 0 || end <= start {
		t.Fatal("could not isolate run production assembly")
	}
	productionAssembly := string(source[start:end])

	// These constructors and concrete no-op values make insecure behavior
	// reachable from run's live HTTP handler. Explicitly isolated dev/test
	// helpers may continue to exist, but run must not assemble them.
	for _, forbidden := range []string{
		"oidc.NewPlaceholderIssuer()",
		"oidc.NewInMemoryClientRegistry()",
		"oidc.NewInMemoryAuthCodeStore()",
		"oidc.NewInMemoryGrantStore()",
		"noopSessionRevoker{}",
		`ID:            "demo-client"`,
	} {
		if strings.Contains(productionAssembly, forbidden) {
			t.Errorf("live harbor-hot graph still references forbidden scaffold %q", forbidden)
		}
	}
}

func TestDevelopmentGraphRegistersE2ERedirectURI(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	config, _, err := buildDevHotGraph("http://localhost:8080", crypto.RuntimeConfig{
		Mode:         crypto.RuntimeDevelopment,
		DevKeySecret: "test-only-development-secret",
	}, logger)
	if err != nil {
		t.Fatalf("build development graph: %v", err)
	}
	client, found := config.Clients.Lookup(context.Background(), "demo-client")
	if !found {
		t.Fatal("development demo client not registered")
	}
	if len(config.Signers) != 1 {
		t.Fatalf("development graph signers = %d, want 1 for JWT/JWKS parity", len(config.Signers))
	}
	for _, redirectURI := range client.RedirectURIs {
		if redirectURI == "http://localhost:3000/callback" {
			return
		}
	}
	t.Fatalf("development demo client redirects = %v, missing e2e callback", client.RedirectURIs)
}
