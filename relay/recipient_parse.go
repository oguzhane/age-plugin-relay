package relay

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// parseAnyRecipient parses any age recipient string — native (X25519, PQ) or plugin.
// Follows age's own dispatch: try native parsing first, fall back to plugin parsing.
// For plugin recipients, the external plugin binary (age-plugin-<name>) must be in PATH
// and will be spawned during Wrap().
func parseAnyRecipient(s string) (age.Recipient, error) {
	// Try native recipients first (no external binary needed).
	recipients, err := age.ParseRecipients(strings.NewReader(s))
	if err == nil && len(recipients) > 0 {
		return recipients[0], nil
	}

	// Check if it looks like a plugin recipient (age1<name>1...).
	_, _, pluginErr := plugin.ParseRecipient(s)
	if pluginErr != nil {
		// Neither native nor plugin — return the original native parse error.
		return nil, fmt.Errorf("parsing recipient %q: %w", s, err)
	}

	// Create a plugin-backed recipient that spawns the external binary during Wrap().
	return plugin.NewRecipient(s, &plugin.ClientUI{})
}

// ParseAnyIdentities parses identity lines from a reader — native (X25519, PQ) or plugin.
// Follows age's own dispatch: native identities are parsed directly, plugin identities
// (AGE-PLUGIN-<NAME>-1...) are handled via plugin.NewIdentity().
// The external plugin binary (age-plugin-<name>) must be in PATH for plugin identities.
func ParseAnyIdentities(r io.Reader) ([]age.Identity, error) {
	var identities []age.Identity
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip non-identity lines (e.g., "Recipient: age1..." from age-plugin-yubikey).
		// All age identity strings start with "AGE-".
		if !strings.HasPrefix(line, "AGE-") {
			continue
		}

		// Try native identity parsing (AGE-SECRET-KEY-1... or AGE-SECRET-KEY-PQ-1...).
		nativeIDs, err := age.ParseIdentities(strings.NewReader(line))
		if err == nil && len(nativeIDs) > 0 {
			identities = append(identities, nativeIDs...)
			continue
		}

		// Check if it looks like a plugin identity (AGE-PLUGIN-<NAME>-1...).
		_, _, pluginErr := plugin.ParseIdentity(line)
		if pluginErr != nil {
			return nil, fmt.Errorf("unknown identity type on line %q", line)
		}

		// Create a plugin-backed identity that spawns the external binary during Unwrap().
		id, err := plugin.NewIdentity(line, &plugin.ClientUI{})
		if err != nil {
			return nil, fmt.Errorf("creating plugin identity: %w", err)
		}
		identities = append(identities, id)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading identities: %w", err)
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no identities found")
	}

	return identities, nil
}
