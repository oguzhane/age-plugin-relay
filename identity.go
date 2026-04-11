package main

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"filippo.io/age"
)

// RelayIdentity matches relay stanzas by tag and forwards them to a relay URL
// for unwrapping by a remote identity.
type RelayIdentity struct {
	tag      [4]byte
	relayURL string
}

// NewRelayIdentity creates a RelayIdentity from the raw Bech32 data payload
// of an AGE-PLUGIN-RELAY-1... identity string.
func NewRelayIdentity(data []byte) (*RelayIdentity, error) {
	tag, relayURL, err := DecodeIdentityData(data)
	if err != nil {
		return nil, err
	}
	return &RelayIdentity{tag: tag, relayURL: relayURL}, nil
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

	fileKey, err := PostToRelay(id.relayURL, matched)
	if err != nil {
		return nil, fmt.Errorf("relay unwrap: %w", err)
	}
	return fileKey, nil
}
