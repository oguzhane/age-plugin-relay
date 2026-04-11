package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"filippo.io/age"
	ageplugin "filippo.io/age/plugin"
)

// Generate produces a relay recipient and identity from an inner recipient
// string and a relay URL.
func Generate(innerRecipient, relayURL string) error {
	innerRecipient = strings.TrimSpace(innerRecipient)
	relayURL = strings.TrimSpace(relayURL)

	if innerRecipient == "" {
		return fmt.Errorf("--inner-recipient is required")
	}
	if relayURL == "" {
		return fmt.Errorf("--relay-url is required")
	}

	// Validate the inner recipient parses correctly.
	recipients, err := age.ParseRecipients(strings.NewReader(innerRecipient))
	if err != nil {
		return fmt.Errorf("invalid inner recipient: %w", err)
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients parsed from %q", innerRecipient)
	}

	// Warn if inner recipient is a plugin type and the binary is missing.
	warnIfPluginMissing(innerRecipient)

	tag := ComputeTag(innerRecipient)
	recipient := EncodeRelayRecipient(innerRecipient)
	identity := EncodeRelayIdentity(tag, relayURL)

	fmt.Fprintf(os.Stdout, "# Relay recipient (for encryption — add to .sops.yaml or age -r):\n")
	fmt.Fprintf(os.Stdout, "#   Inner: %s\n", innerRecipient)
	fmt.Fprintf(os.Stdout, "#   Relay: %s\n", relayURL)
	fmt.Fprintf(os.Stdout, "%s\n\n", recipient)

	fmt.Fprintf(os.Stdout, "# Relay identity (for decryption — add to identity file):\n")
	fmt.Fprintf(os.Stdout, "#   Relay: %s\n", relayURL)
	fmt.Fprintf(os.Stdout, "%s\n", identity)

	return nil
}

// warnIfPluginMissing checks if an inner recipient requires a plugin binary
// and warns if that binary is not found in PATH.
func warnIfPluginMissing(innerRecipient string) {
	name, _, err := ageplugin.ParseRecipient(innerRecipient)
	if err != nil {
		// Not a plugin recipient (e.g., native X25519). No warning needed.
		return
	}

	binaryName := "age-plugin-" + name
	if _, err := exec.LookPath(binaryName); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: inner recipient requires %s in PATH during encryption.\n", binaryName)
		fmt.Fprintf(os.Stderr, "  It was not found. Encryption will fail unless it is installed.\n\n")
	}
}
