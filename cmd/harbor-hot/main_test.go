package main

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

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
