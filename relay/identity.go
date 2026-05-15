package relay

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"filippo.io/age"
)

// RelayIdentity matches relay stanzas by tag and forwards them to a remote
// relay server for unwrapping.
type RelayIdentity struct {
	Tag    [TagSize]byte
	Remote RemoteConfig
}

// NewRelayIdentity creates a RelayIdentity from the raw Bech32 data payload
// of an AGE-PLUGIN-RELAY-1... identity string.
//
// The payload after the 16-byte tag is a remote name, looked up in relay-config.yaml.
func NewRelayIdentity(data []byte) (*RelayIdentity, error) {
	tag, remoteName, err := DecodeIdentityData(data)
	if err != nil {
		return nil, err
	}

	remote, err := ResolveRemote(remoteName)
	if err != nil {
		return nil, fmt.Errorf("resolving remote %q: %w", remoteName, err)
	}

	return &RelayIdentity{Tag: tag, Remote: remote}, nil
}

// ResolveRemote resolves a remote name to a RemoteConfig by looking it up
// in the relay-config.yaml file.
func ResolveRemote(remoteName string) (RemoteConfig, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return RemoteConfig{}, err
	}
	return cfg.LookupRemote(remoteName)
}

// Unwrap finds relay stanzas matching this identity's tag, reconstructs the
// inner stanzas, and forwards them to the remote relay server for decryption.
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

	if id.Remote.UnwrapRecipient == "" {
		return nil, fmt.Errorf("relay unwrap: unwrap_recipient is required in config (encrypted payload mode)")
	}

	fileKey, err := PostToRelay(id.Remote, matched, id.Remote.UnwrapRecipient)
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
