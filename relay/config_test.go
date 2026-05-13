package relay

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfigInvalidYAML(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bad.yaml")
	os.WriteFile(path, []byte("{{invalid yaml"), 0644)
	t.Setenv("AGE_PLUGIN_RELAY_CONFIG", path)

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadConfigMissing(t *testing.T) {
	t.Setenv("AGE_PLUGIN_RELAY_CONFIG", filepath.Join(t.TempDir(), "nonexistent.yaml"))
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("missing config should not error: %v", err)
	}
	if cfg != nil {
		t.Fatal("missing config should return nil")
	}
}

func TestLookupRemoteEmptyURL(t *testing.T) {
	cfg := &Config{Remotes: map[string]RemoteConfig{
		"nourl": {URL: ""},
	}}
	_, err := cfg.LookupRemote("nourl")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestLookupRemoteNilConfig(t *testing.T) {
	var cfg *Config
	_, err := cfg.LookupRemote("anything")
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestLookupRemoteNotFound(t *testing.T) {
	cfg := &Config{Remotes: map[string]RemoteConfig{
		"alpha": {URL: "http://localhost:1"},
	}}
	_, err := cfg.LookupRemote("beta")
	if err == nil {
		t.Fatal("expected error for missing remote")
	}
}

func TestTimeoutDurationDefault(t *testing.T) {
	rc := RemoteConfig{}
	if rc.TimeoutDuration() != 5*time.Minute {
		t.Fatalf("expected 5m default, got %v", rc.TimeoutDuration())
	}
}

func TestTimeoutDurationInvalid(t *testing.T) {
	rc := RemoteConfig{Timeout: "notaduration"}
	if rc.TimeoutDuration() != 5*time.Minute {
		t.Fatalf("expected 5m fallback for invalid, got %v", rc.TimeoutDuration())
	}
}

func TestTimeoutDurationCustom(t *testing.T) {
	rc := RemoteConfig{Timeout: "30s"}
	if rc.TimeoutDuration() != 30*time.Second {
		t.Fatalf("expected 30s, got %v", rc.TimeoutDuration())
	}
}

func TestPollIntervalDefault(t *testing.T) {
	// Default timeout = 5m → 5m/60 = 5s.
	r := RemoteConfig{}
	if d := r.PollIntervalDuration(); d != 5*time.Second {
		t.Fatalf("expected 5s default, got %s", d)
	}

	// Short timeout = 10s → 10s/60 ≈ 166ms → clamped to 500ms.
	r2 := RemoteConfig{Timeout: "10s"}
	if d := r2.PollIntervalDuration(); d != 500*time.Millisecond {
		t.Fatalf("expected 500ms floor, got %s", d)
	}

	// Long timeout = 1h → 1h/60 = 1m → capped at 5s.
	r3 := RemoteConfig{Timeout: "1h"}
	if d := r3.PollIntervalDuration(); d != 5*time.Second {
		t.Fatalf("expected 5s cap, got %s", d)
	}

	// Explicit poll_interval overrides.
	r4 := RemoteConfig{PollInterval: "2s"}
	if d := r4.PollIntervalDuration(); d != 2*time.Second {
		t.Fatalf("expected 2s from config, got %s", d)
	}
}
