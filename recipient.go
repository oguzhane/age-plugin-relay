package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"filippo.io/age"
)

// RelayRecipient wraps file keys using the inner recipient's public key,
// then re-tags the resulting stanzas as "relay" stanzas.
type RelayRecipient struct {
	inner    age.Recipient
	innerStr string
	tag      [4]byte
}

// NewRelayRecipient creates a RelayRecipient from the raw Bech32 data payload
// of an age1relay1... recipient string.
func NewRelayRecipient(data []byte) (*RelayRecipient, error) {
	innerStr := string(data)
	if innerStr == "" {
		return nil, errNoInnerRecipient
	}

	recipients, err := age.ParseRecipients(strings.NewReader(innerStr))
	if err != nil {
		return nil, fmt.Errorf("parsing inner recipient: %w", err)
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients parsed from %q", innerStr)
	}

	return &RelayRecipient{
		inner:    recipients[0],
		innerStr: innerStr,
		tag:      ComputeTag(innerStr),
	}, nil
}

// Wrap encrypts the file key using the inner recipient, then re-tags each
// resulting stanza as a relay stanza.
//
// Stanza format:
//
//	-> relay <tag_b64> <inner_type> [inner_args...]
//	<body>
func (r *RelayRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	innerStanzas, err := r.inner.Wrap(fileKey)
	if err != nil {
		return nil, fmt.Errorf("inner wrap: %w", err)
	}

	out := make([]*age.Stanza, 0, len(innerStanzas))
	tagB64 := base64.RawStdEncoding.EncodeToString(r.tag[:])

	for _, s := range innerStanzas {
		args := make([]string, 0, 2+len(s.Args))
		args = append(args, tagB64, s.Type)
		args = append(args, s.Args...)

		out = append(out, &age.Stanza{
			Type: "relay",
			Args: args,
			Body: s.Body,
		})
	}
	return out, nil
}
