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
// string and either a relay URL (legacy) or a remote name (config mode).
func Generate(innerRecipient, relayURL, remoteName string) error {
	innerRecipient = strings.TrimSpace(innerRecipient)
	relayURL = strings.TrimSpace(relayURL)
	remoteName = strings.TrimSpace(remoteName)

	if innerRecipient == "" {
		return fmt.Errorf("--inner-recipient is required")
	}
	if relayURL == "" && remoteName == "" {
		return fmt.Errorf("--relay-url or --remote is required")
	}
	if relayURL != "" && remoteName != "" {
		return fmt.Errorf("--relay-url and --remote are mutually exclusive")
	}

	// If --remote, validate config entry exists.
	if remoteName != "" {
		cfg, err := LoadConfig()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		remote, err := cfg.LookupRemote(remoteName)
		if err != nil {
			return err
		}
		relayURL = remote.URL
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

	// Identity target: remote name (short) or full URL (legacy)
	identityTarget := relayURL
	if remoteName != "" {
		identityTarget = remoteName
	}
	identity := EncodeRelayIdentity(tag, identityTarget)

	fmt.Fprintf(os.Stdout, "# Relay recipient (for encryption — add to .sops.yaml or age -r):\n")
	fmt.Fprintf(os.Stdout, "#   Inner: %s\n", innerRecipient)
	if remoteName != "" {
		fmt.Fprintf(os.Stdout, "#   Remote: %s → %s\n", remoteName, relayURL)
	} else {
		fmt.Fprintf(os.Stdout, "#   Relay: %s\n", relayURL)
	}
	fmt.Fprintf(os.Stdout, "%s\n\n", recipient)

	fmt.Fprintf(os.Stdout, "# Relay identity (for decryption — add to identity file):\n")
	if remoteName != "" {
		fmt.Fprintf(os.Stdout, "#   Remote: %s → %s\n", remoteName, relayURL)
	} else {
		fmt.Fprintf(os.Stdout, "#   Relay: %s\n", relayURL)
	}
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
