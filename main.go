package main

import (
	"flag"
	"fmt"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

func main() {
	p, err := plugin.New(pluginName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Custom flags for --generate mode.
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

	// Handle --generate before entering plugin protocol.
	if generateFlag {
		if err := Generate(innerRecipient, relayURL, remoteName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Register recipient handler: age1relay1<bech32(inner_recipient_bytes)>
	p.HandleRecipient(func(data []byte) (age.Recipient, error) {
		return NewRelayRecipient(data)
	})

	// Register identity handler: AGE-PLUGIN-RELAY-1<bech32(tag:4 || url_or_name)>
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		return NewRelayIdentity(data)
	})

	os.Exit(p.Main())
}
