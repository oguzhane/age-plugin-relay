package relay

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
)

// RelayIdentity matches relay stanzas by tag and forwards them to a relay URL
// for unwrapping by a remote identity.
type RelayIdentity struct {
	Tag    [TagSize]byte
	Remote RemoteConfig
}

// NewRelayIdentity creates a RelayIdentity from the raw Bech32 data payload
// of an AGE-PLUGIN-RELAY-1... identity string.
//
// The payload after the 4-byte tag is either:
//   - A full URL (starts with "http://" or "https://") — legacy mode
//   - A remote name — looked up in relay-config.yaml
func NewRelayIdentity(data []byte) (*RelayIdentity, error) {
	tag, target, err := DecodeIdentityData(data)
	if err != nil {
		return nil, err
	}

	remote, err := ResolveRemote(target)
	if err != nil {
		return nil, fmt.Errorf("resolving relay target %q: %w", target, err)
	}

	return &RelayIdentity{Tag: tag, Remote: remote}, nil
}

// ResolveRemote resolves a target string to a RemoteConfig.
// If it's a URL, wrap it directly. Otherwise, look it up in the config file.
func ResolveRemote(target string) (RemoteConfig, error) {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if strings.HasPrefix(target, "http://") {
			fmt.Fprintf(os.Stderr, "WARNING: relay URL uses plaintext HTTP — file keys will be transmitted unencrypted\n")
		}
		return RemoteConfig{URL: target}, nil
	}

	cfg, err := LoadConfig()
	if err != nil {
		return RemoteConfig{}, err
	}
	return cfg.LookupRemote(target)
}

// Unwrap finds relay stanzas matching this identity's tag, reconstructs the
// inner stanzas, and forwards them to the relay URL for decryption.
func (id *RelayIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	var matched []*age.Stanza

	for _, s := range stanzas {
		if s.Type != "relay" || len(s.Args) < 2 {
			continue
		}
		stanzaTagBytes, err := base64.RawStdEncoding.DecodeString(s.Args[0])
		if err != nil || len(stanzaTagBytes) != TagSize {
			continue
		}
		if !bytes.Equal(stanzaTagBytes, id.Tag[:]) {
			continue
		}

		inner := &age.Stanza{
			Type: s.Args[1],
			Args: s.Args[2:],
			Body: s.Body,
		}
		matched = append(matched, inner)
	}

	if len(matched) == 0 {
		return nil, age.ErrIncorrectIdentity
	}

	fileKey, err := PostToRelay(id.Remote, matched)
	if err != nil {
		return nil, fmt.Errorf("relay unwrap: %w", err)
	}

	// Copy the file key before it can be reused/leaked by future calls.
	// The caller (age) takes ownership; we clear our reference.
	result := make([]byte, len(fileKey))
	copy(result, fileKey)
	clear(fileKey)
	return result, nil
}
