// age-plugin-stub is a minimal age plugin for testing plugin-agnostic relay support.
// It wraps X25519 crypto under the "stub" plugin type (age1stub1... / AGE-PLUGIN-STUB-1...).
// The bech32 data stores the native age X25519 recipient or identity string.
package main

import (
	"flag"
	"fmt"
	"os"

	"filippo.io/age"
	ageplugin "filippo.io/age/plugin"
)

func main() {
	p, err := ageplugin.New("stub")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var generateFlag bool
	fs := flag.CommandLine
	p.RegisterFlags(fs)
	fs.BoolVar(&generateFlag, "generate", false, "Generate a stub recipient and identity")
	flag.Parse()

	if generateFlag {
		if err := generate(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	p.HandleRecipient(func(data []byte) (age.Recipient, error) {
		// data contains the native age X25519 recipient string.
		return age.ParseX25519Recipient(string(data))
	})

	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		// data contains the native age X25519 identity string.
		return age.ParseX25519Identity(string(data))
	})

	os.Exit(p.Main())
}

func generate() error {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generating X25519 identity: %w", err)
	}

	recipient := ageplugin.EncodeRecipient("stub", []byte(id.Recipient().String()))
	identity := ageplugin.EncodeIdentity("stub", []byte(id.String()))

	fmt.Printf("# recipient: %s\n", recipient)
	fmt.Println(identity)
	return nil
}
