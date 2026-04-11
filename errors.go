package main

import "errors"

var (
	errShortIdentityData = errors.New("identity data too short: need at least 4 bytes tag + URL")
	errNoInnerRecipient  = errors.New("recipient data is empty")
	errNoMatchingStanza  = errors.New("no matching relay stanza found")
)
