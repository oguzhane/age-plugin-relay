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
	)

	fs := flag.CommandLine
	p.RegisterFlags(fs)
	fs.BoolVar(&generateFlag, "generate", false, "Generate a relay recipient and identity")
	fs.StringVar(&innerRecipient, "inner-recipient", "", "Inner age recipient string (e.g., age1...)")
	fs.StringVar(&relayURL, "relay-url", "", "Relay endpoint URL for decryption")
	flag.Parse()

	// Handle --generate before entering plugin protocol.
	if generateFlag {
		if err := Generate(innerRecipient, relayURL); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Register recipient handler: age1relay1<bech32(inner_recipient_bytes)>
	p.HandleRecipient(func(data []byte) (age.Recipient, error) {
		return NewRelayRecipient(data)
	})

	// Register identity handler: AGE-PLUGIN-RELAY-1<bech32(tag:4 || relay_url)>
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		return NewRelayIdentity(data)
	})

	os.Exit(p.Main())
}
