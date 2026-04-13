package relay

import "errors"

var (
	ErrShortIdentityData = errors.New("identity data too short: need at least 16 bytes tag + target")
	ErrNoInnerRecipient  = errors.New("recipient data is empty")
	ErrNoMatchingStanza  = errors.New("no matching relay stanza found")
)
