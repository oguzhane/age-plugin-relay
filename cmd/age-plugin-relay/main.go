package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"filippo.io/age"
	ageplugin "filippo.io/age/plugin"

	"github.com/oguzhane/age-plugin-relay/relay"
)

func main() {
	p, err := ageplugin.New(relay.PluginName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var (
		generateFlag   bool
		innerRecipient string
		relayURL       string
		remoteName     string
	)

	fs := flag.CommandLine
	p.RegisterFlags(fs)
	fs.BoolVar(&generateFlag, "generate", false, "Generate a relay recipient and identity")
	fs.StringVar(&innerRecipient, "inner-recipient", "", "Inner age recipient string (e.g., age1...)")
	fs.StringVar(&relayURL, "relay-url", "", "Relay endpoint URL for decryption (legacy mode)")
	fs.StringVar(&remoteName, "remote", "", "Remote name from relay-config.yaml (config mode)")
	flag.Parse()

	if generateFlag {
		if err := generate(innerRecipient, relayURL, remoteName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	p.HandleRecipient(func(data []byte) (age.Recipient, error) {
		return relay.NewRelayRecipient(data)
	})

	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		return relay.NewRelayIdentity(data)
	})

	os.Exit(p.Main())
}

// generate produces a relay recipient and identity from an inner recipient
// string and either a relay URL (legacy) or a remote name (config mode).
func generate(innerRecipient, relayURL, remoteName string) error {
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

	if remoteName != "" {
		cfg, err := relay.LoadConfig()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		remote, err := cfg.LookupRemote(remoteName)
		if err != nil {
			return err
		}
		relayURL = remote.URL
	}

	recipients, err := age.ParseRecipients(strings.NewReader(innerRecipient))
	if err != nil {
		return fmt.Errorf("invalid inner recipient: %w", err)
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients parsed from %q", innerRecipient)
	}

	warnIfPluginMissing(innerRecipient)

	tag := relay.ComputeTag(innerRecipient)
	recipient := relay.EncodeRelayRecipient(innerRecipient)

	identityTarget := relayURL
	if remoteName != "" {
		identityTarget = remoteName
	}
	identity := relay.EncodeRelayIdentity(tag, identityTarget)

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

func warnIfPluginMissing(innerRecipient string) {
	name, _, err := ageplugin.ParseRecipient(innerRecipient)
	if err != nil {
		return
	}
	binaryName := "age-plugin-" + name
	if _, err := exec.LookPath(binaryName); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: inner recipient requires %s in PATH during encryption.\n", binaryName)
		fmt.Fprintf(os.Stderr, "  It was not found. Encryption will fail unless it is installed.\n\n")
	}
}
