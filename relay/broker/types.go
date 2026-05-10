// Package broker provides the in-memory intent queue for the relay broker.
//
// The broker is a zero-trust stateful queue that stores opaque, encrypted
// payloads keyed by plugin-supplied intent IDs and indexed by tag. It holds
// no age identity and no key material — it cannot read or verify the
// cryptographic content of any intent.
package broker

import (
	"time"

	"github.com/oguzhane/age-plugin-relay/relay"
)

// Status represents the lifecycle state of an intent.
type Status string

const (
	StatusPending   Status = "pending"
	StatusFulfilled Status = "fulfilled"
	StatusRejected  Status = "rejected"
)

// Intent is the internal representation of a queued unwrap intent.
type Intent struct {
	// IntentID is the plugin-generated unique identifier (16 random bytes, hex).
	IntentID string

	// Tag is the base64-encoded routing tag parsed from the plugin's request.
	// Used to index intents for operator pull queries.
	Tag string

	// Request is the original plugin POST body, stored verbatim.
	Request []byte

	// Status is the current lifecycle state.
	Status Status

	// EncryptedPayload is set when the operator fulfills the intent.
	// Opaque to the broker — age-encrypted to the plugin's ephemeral recipient.
	EncryptedPayload string

	// CreatedAt is when the broker received the intent. Used for TTL enforcement.
	CreatedAt time.Time
}

// PullIntent is a single intent as returned to the operator on a pull request.
type PullIntent struct {
	IntentID string             `json:"intent_id"`
	Request  relay.RelayRequest `json:"request"`
}

// PullResponse is the broker's response to an operator pull request.
type PullResponse struct {
	Intents []PullIntent `json:"intents"`
}

// PollResponse is the broker's response to a plugin poll request.
type PollResponse struct {
	Status           string `json:"status"`
	EncryptedPayload string `json:"encrypted_payload,omitempty"`
}

// AsyncAccepted is the broker's 202 response to a plugin unwrap request
// that was queued for async processing.
type AsyncAccepted struct{}
