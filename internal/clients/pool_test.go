package clients

import (
	"strings"
	"testing"
	"time"
)

func TestPoolSettingsFromEnv(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		clearPoolEnvironment(t)
		settings, err := poolSettingsFromEnv()
		if err != nil {
			t.Fatalf("poolSettingsFromEnv() error = %v", err)
		}
		if settings.maxConns != 10 || settings.minConns != 2 || settings.maxConnLifetime != 30*time.Minute {
			t.Fatalf("poolSettingsFromEnv() = %+v, want max=10 min=2 lifetime=30m", settings)
		}
	})

	t.Run("overrides", func(t *testing.T) {
		clearPoolEnvironment(t)
		t.Setenv("DB_MAX_CONNS", "25")
		t.Setenv("DB_MIN_CONNS", "5")
		t.Setenv("DB_MAX_CONN_LIFETIME", "15m")

		settings, err := poolSettingsFromEnv()
		if err != nil {
			t.Fatalf("poolSettingsFromEnv() error = %v", err)
		}
		if settings.maxConns != 25 || settings.minConns != 5 || settings.maxConnLifetime != 15*time.Minute {
			t.Fatalf("poolSettingsFromEnv() = %+v, want max=25 min=5 lifetime=15m", settings)
		}
	})
}

func TestPoolSettingsFromEnvRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		value   string
		wantErr string
	}{
		{name: "malformed max", key: "DB_MAX_CONNS", value: "many", wantErr: "DB_MAX_CONNS"},
		{name: "zero max", key: "DB_MAX_CONNS", value: "0", wantErr: "must be positive"},
		{name: "negative max", key: "DB_MAX_CONNS", value: "-1", wantErr: "must be positive"},
		{name: "overflowing max", key: "DB_MAX_CONNS", value: "2147483648", wantErr: "DB_MAX_CONNS"},
		{name: "malformed min", key: "DB_MIN_CONNS", value: "few", wantErr: "DB_MIN_CONNS"},
		{name: "zero min", key: "DB_MIN_CONNS", value: "0", wantErr: "must be positive"},
		{name: "negative min", key: "DB_MIN_CONNS", value: "-1", wantErr: "must be positive"},
		{name: "overflowing min", key: "DB_MIN_CONNS", value: "2147483648", wantErr: "DB_MIN_CONNS"},
		{name: "malformed lifetime", key: "DB_MAX_CONN_LIFETIME", value: "later", wantErr: "DB_MAX_CONN_LIFETIME"},
		{name: "overflowing lifetime", key: "DB_MAX_CONN_LIFETIME", value: "2562048h", wantErr: "DB_MAX_CONN_LIFETIME"},
		{name: "zero lifetime", key: "DB_MAX_CONN_LIFETIME", value: "0s", wantErr: "must be positive"},
		{name: "negative lifetime", key: "DB_MAX_CONN_LIFETIME", value: "-1s", wantErr: "must be positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearPoolEnvironment(t)
			t.Setenv(tt.key, tt.value)
			_, err := poolSettingsFromEnv()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("poolSettingsFromEnv() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestPoolSettingsFromEnvRejectsMinAboveMax(t *testing.T) {
	clearPoolEnvironment(t)
	t.Setenv("DB_MAX_CONNS", "4")
	t.Setenv("DB_MIN_CONNS", "5")

	_, err := poolSettingsFromEnv()
	if err == nil || !strings.Contains(err.Error(), "DB_MIN_CONNS") {
		t.Fatalf("poolSettingsFromEnv() error = %v, want min/max consistency error", err)
	}
}

func clearPoolEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("DB_MAX_CONNS", "")
	t.Setenv("DB_MIN_CONNS", "")
	t.Setenv("DB_MAX_CONN_LIFETIME", "")
}

func TestDefaultPoolBudgetAtHPACeiling(t *testing.T) {
	const (
		hpaMaxReplicas         = 20
		operationalHeadroom    = 20
		postgresMaxConnections = 220
	)

	applicationConnections := hpaMaxReplicas * int(defaultMaxConns)
	if applicationConnections != 200 {
		t.Fatalf("application connection budget = %d, want 200", applicationConnections)
	}
	if applicationConnections+operationalHeadroom > postgresMaxConnections {
		t.Fatalf("%d application connections + %d headroom exceed max_connections=%d", applicationConnections, operationalHeadroom, postgresMaxConnections)
	}
}
