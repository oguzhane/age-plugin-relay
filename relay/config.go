package relay

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultConfigFile is the filename looked for in $PWD.
	DefaultConfigFile = "relay-config.yaml"

	// DefaultTimeout is the HTTP timeout when not configured.
	DefaultTimeout = 5 * time.Minute
)

// Config is the top-level relay config file structure.
type Config struct {
	Remotes map[string]RemoteConfig `yaml:"remotes"`
}

// RemoteConfig holds per-remote relay endpoint settings.
type RemoteConfig struct {
	URL       string `yaml:"url"`                  // required
	TLSCert   string `yaml:"tls_cert,omitempty"`   // optional: client cert for mTLS
	TLSKey    string `yaml:"tls_key,omitempty"`    // optional: client key for mTLS
	TLSCA     string `yaml:"tls_ca,omitempty"`     // optional: CA cert for server verification
	Timeout   string `yaml:"timeout,omitempty"`    // optional: Go duration (default: 5m)
	Stream    bool   `yaml:"stream,omitempty"`     // optional: use SSE for long-running requests
	AuthToken string `yaml:"auth_token,omitempty"` // optional: Bearer token for relay server auth
	HMACKey   string `yaml:"hmac_key,omitempty"`   // optional: HMAC-SHA256 shared key for request signing + replay protection
}

// TimeoutDuration parses the timeout string, falling back to DefaultTimeout.
func (r RemoteConfig) TimeoutDuration() time.Duration {
	if r.Timeout == "" {
		return DefaultTimeout
	}
	d, err := time.ParseDuration(r.Timeout)
	if err != nil {
		return DefaultTimeout
	}
	return d
}

// LoadConfig loads the relay config from disk.
// Resolution order:
//  1. AGE_PLUGIN_RELAY_CONFIG env var
//  2. $PWD/relay-config.yaml
//
// Returns nil (no error) if no config file exists — config is optional.
func LoadConfig() (*Config, error) {
	path := os.Getenv("AGE_PLUGIN_RELAY_CONFIG")
	if path == "" {
		path = DefaultConfigFile
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // config is optional
		}
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return &cfg, nil
}

// LookupRemote finds a remote by name. Returns an error if the config is nil
// or the remote doesn't exist.
func (c *Config) LookupRemote(name string) (RemoteConfig, error) {
	if c == nil || c.Remotes == nil {
		return RemoteConfig{}, fmt.Errorf("no config file found (looked for %s and AGE_PLUGIN_RELAY_CONFIG)", DefaultConfigFile)
	}
	remote, ok := c.Remotes[name]
	if !ok {
		return RemoteConfig{}, fmt.Errorf("remote %q not found in config (available: %s)", name, remoteNames(c.Remotes))
	}
	if remote.URL == "" {
		return RemoteConfig{}, fmt.Errorf("remote %q has no url", name)
	}
	return remote, nil
}

func remoteNames(m map[string]RemoteConfig) string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	if len(names) == 0 {
		return "(none)"
	}
	s := names[0]
	for _, n := range names[1:] {
		s += ", " + n
	}
	return s
}
