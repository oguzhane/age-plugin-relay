package main

import (
	"crypto/sha256"

	"filippo.io/age/plugin"
)

const pluginName = "relay"

// ComputeTag computes a 4-byte tag from an inner recipient string.
// Used for matching stanzas to identities during decryption.
func ComputeTag(innerRecipient string) [4]byte {
	h := sha256.Sum256([]byte(innerRecipient))
	return [4]byte(h[:4])
}

// EncodeRelayRecipient produces an age1relay1... string from an inner recipient string.
func EncodeRelayRecipient(innerRecipient string) string {
	return plugin.EncodeRecipient(pluginName, []byte(innerRecipient))
}

// EncodeRelayIdentity produces an AGE-PLUGIN-RELAY-1... string from a tag and relay URL.
func EncodeRelayIdentity(tag [4]byte, relayURL string) string {
	data := make([]byte, 4+len(relayURL))
	copy(data[:4], tag[:])
	copy(data[4:], relayURL)
	return plugin.EncodeIdentity(pluginName, data)
}

// DecodeIdentityData parses the Bech32 payload of an AGE-PLUGIN-RELAY-1... identity
// into a tag and relay URL.
func DecodeIdentityData(data []byte) (tag [4]byte, relayURL string, err error) {
	if len(data) < 5 { // 4 bytes tag + at least 1 byte URL
		return tag, "", errShortIdentityData
	}
	copy(tag[:], data[:4])
	relayURL = string(data[4:])
	return tag, relayURL, nil
}
