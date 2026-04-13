package relay

import (
	"crypto/sha256"

	"filippo.io/age/plugin"
)

// PluginName is the age plugin name used in recipient/identity Bech32 encoding.
const PluginName = "relay"

// TagSize is the number of bytes used for the relay routing tag.
// 16 bytes (128 bits) makes collisions infeasible.
const TagSize = 16

// ComputeTag computes a 16-byte tag from an inner recipient string.
// Used for matching stanzas to identities during decryption.
func ComputeTag(innerRecipient string) [TagSize]byte {
	h := sha256.Sum256([]byte(innerRecipient))
	return [TagSize]byte(h[:TagSize])
}

// EncodeRelayRecipient produces an age1relay1... string from an inner recipient string.
func EncodeRelayRecipient(innerRecipient string) string {
	return plugin.EncodeRecipient(PluginName, []byte(innerRecipient))
}

// EncodeRelayIdentity produces an AGE-PLUGIN-RELAY-1... string from a tag and
// a target (either a relay URL or a remote name).
func EncodeRelayIdentity(tag [TagSize]byte, target string) string {
	data := make([]byte, TagSize+len(target))
	copy(data[:TagSize], tag[:])
	copy(data[TagSize:], target)
	return plugin.EncodeIdentity(PluginName, data)
}

// DecodeIdentityData parses the Bech32 payload of an AGE-PLUGIN-RELAY-1... identity
// into a tag and target string (URL or remote name).
func DecodeIdentityData(data []byte) (tag [TagSize]byte, target string, err error) {
	if len(data) < TagSize+1 { // TagSize bytes tag + at least 1 byte target
		return tag, "", ErrShortIdentityData
	}
	copy(tag[:], data[:TagSize])
	target = string(data[TagSize:])
	return tag, target, nil
}
