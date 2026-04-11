package relay

import (
	"crypto/sha256"

	"filippo.io/age/plugin"
)

// PluginName is the age plugin name used in recipient/identity Bech32 encoding.
const PluginName = "relay"

// ComputeTag computes a 4-byte tag from an inner recipient string.
// Used for matching stanzas to identities during decryption.
func ComputeTag(innerRecipient string) [4]byte {
	h := sha256.Sum256([]byte(innerRecipient))
	return [4]byte(h[:4])
}

// EncodeRelayRecipient produces an age1relay1... string from an inner recipient string.
func EncodeRelayRecipient(innerRecipient string) string {
	return plugin.EncodeRecipient(PluginName, []byte(innerRecipient))
}

// EncodeRelayIdentity produces an AGE-PLUGIN-RELAY-1... string from a tag and
// a target (either a relay URL or a remote name).
func EncodeRelayIdentity(tag [4]byte, target string) string {
	data := make([]byte, 4+len(target))
	copy(data[:4], tag[:])
	copy(data[4:], target)
	return plugin.EncodeIdentity(PluginName, data)
}

// DecodeIdentityData parses the Bech32 payload of an AGE-PLUGIN-RELAY-1... identity
// into a tag and target string (URL or remote name).
func DecodeIdentityData(data []byte) (tag [4]byte, target string, err error) {
	if len(data) < 5 { // 4 bytes tag + at least 1 byte target
		return tag, "", ErrShortIdentityData
	}
	copy(tag[:], data[:4])
	target = string(data[4:])
	return tag, target, nil
}
