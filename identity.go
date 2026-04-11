package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	"filippo.io/age"
)

// RelayIdentity matches relay stanzas by tag and forwards them to a relay URL
// for unwrapping by a remote identity.
type RelayIdentity struct {
	tag    [4]byte
	remote RemoteConfig // resolved relay endpoint config
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

	remote, err := resolveRemote(target)
	if err != nil {
		return nil, fmt.Errorf("resolving relay target %q: %w", target, err)
	}

	return &RelayIdentity{tag: tag, remote: remote}, nil
}

// resolveRemote resolves a target string to a RemoteConfig.
// If it's a URL, wrap it directly. Otherwise, look it up in the config file.
func resolveRemote(target string) (RemoteConfig, error) {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
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
		if err != nil || len(stanzaTagBytes) != 4 {
			continue
		}
		if !bytes.Equal(stanzaTagBytes, id.tag[:]) {
			continue
		}

		// Reconstruct inner stanza: strip "relay" type and tag argument
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

	fileKey, err := PostToRelay(id.remote, matched)
	if err != nil {
		return nil, fmt.Errorf("relay unwrap: %w", err)
	}
	return fileKey, nil
}
