package main

import (
	"filippo.io/age/plugin"
)

// parseRecipientViaPlugin decodes a plugin recipient string using the age plugin package.
func parseRecipientViaPlugin(s string) (name string, data []byte, err error) {
	return plugin.ParseRecipient(s)
}

// parseIdentityViaPlugin decodes a plugin identity string using the age plugin package.
func parseIdentityViaPlugin(s string) (name string, data []byte, err error) {
	return plugin.ParseIdentity(s)
}
