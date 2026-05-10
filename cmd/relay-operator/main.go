// relay-operator is a CLI tool that polls a relay-broker for pending unwrap
// intents, verifies the plugin's HMAC end-to-end, unwraps stanzas locally
// using an age identity, and fulfills (or rejects) the intent.
//
// The operator holds the age private key and shares an hmac_key with the plugin
// (not with the broker). The broker is treated as zero-trust.
//
// Usage:
//
//	relay-operator \
//	  --broker https://broker.example:8443 \
//	  --identity keys.txt \
//	  --tag QPg24g \
//	  --hmac-key shared-with-plugin \
//	  [--auth-token broker-bearer-token] \
//	  [--pull-interval 5s]
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/oguzhane/age-plugin-relay/relay"
	"github.com/oguzhane/age-plugin-relay/relay/broker"
)

func main() {
	var (
		brokerURL    string
		identityFile string
		tag          string
		hmacKey      string
		authToken    string
		pullInterval = 5 * time.Second
	)

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--broker":
			i++
			if i < len(os.Args) {
				brokerURL = os.Args[i]
			}
		case "--identity":
			i++
			if i < len(os.Args) {
				identityFile = os.Args[i]
			}
		case "--tag":
			i++
			if i < len(os.Args) {
				tag = os.Args[i]
			}
		case "--hmac-key":
			i++
			if i < len(os.Args) {
				hmacKey = os.Args[i]
			}
		case "--auth-token":
			i++
			if i < len(os.Args) {
				authToken = os.Args[i]
			}
		case "--pull-interval":
			i++
			if i < len(os.Args) {
				if d, err := time.ParseDuration(os.Args[i]); err == nil {
					pullInterval = d
				}
			}
		}
	}

	if brokerURL == "" || identityFile == "" || tag == "" || hmacKey == "" {
		fmt.Fprintf(os.Stderr, "Usage: relay-operator --broker URL --identity FILE --tag TAG --hmac-key KEY [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  --auth-token TOKEN   Bearer token for broker access\n")
		fmt.Fprintf(os.Stderr, "  --pull-interval DUR  Polling interval (default: 5s)\n")
		os.Exit(1)
	}

	if authToken == "" {
		authToken = os.Getenv("RELAY_BROKER_AUTH_TOKEN")
	}

	identities, err := loadIdentities(identityFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading identities: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[relay-operator] Loaded %d identity(ies) from %s\n", len(identities), identityFile)
	fmt.Fprintf(os.Stderr, "[relay-operator] Polling %s for tag=%s every %s\n", brokerURL, tag, pullInterval)

	// Nonce dedup for replay protection.
	seenNonces := make(map[string]time.Time)

	// Nonce cleanup ticker.
	go func() {
		for {
			time.Sleep(relay.HMACMaxDrift)
			now := time.Now()
			for k, t := range seenNonces {
				if now.Sub(t) > relay.HMACMaxDrift {
					delete(seenNonces, k)
				}
			}
		}
	}()

	for {
		pullResp, err := pullIntents(brokerURL, tag, authToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[relay-operator] Pull error: %v\n", err)
			time.Sleep(pullInterval)
			continue
		}

		for _, intent := range pullResp.Intents {
			fmt.Fprintf(os.Stderr, "[relay-operator] Processing intent %s\n", intent.IntentID)

			// 1. Verify plugin HMAC end-to-end.
			requestBody, err := json.Marshal(intent.Request)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[relay-operator]   Failed to marshal request: %v\n", err)
				continue
			}

			if err := relay.ValidateTimestamp(intent.PluginHeaders.Timestamp); err != nil {
				fmt.Fprintf(os.Stderr, "[relay-operator]   HMAC timestamp invalid: %v — skipping\n", err)
				continue
			}

			if err := relay.VerifySignature(
				[]byte(hmacKey),
				intent.PluginHeaders.Timestamp,
				intent.PluginHeaders.Nonce,
				requestBody,
				intent.PluginHeaders.Signature,
				intent.PluginHeaders.EphemeralKey,
			); err != nil {
				fmt.Fprintf(os.Stderr, "[relay-operator]   HMAC verification failed: %v — skipping\n", err)
				continue
			}

			// Nonce dedup.
			if _, seen := seenNonces[intent.PluginHeaders.Nonce]; seen {
				fmt.Fprintf(os.Stderr, "[relay-operator]   Duplicate nonce — skipping\n")
				continue
			}
			seenNonces[intent.PluginHeaders.Nonce] = time.Now()

			// 2. Convert stanzas and attempt unwrap.
			stanzas := make([]*age.Stanza, len(intent.Request.Stanzas))
			for i, s := range intent.Request.Stanzas {
				bodyBytes, err := base64.RawStdEncoding.DecodeString(s.Body)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[relay-operator]   Invalid stanza body: %v\n", err)
					continue
				}
				stanzas[i] = &age.Stanza{
					Type: s.Type,
					Args: s.Args,
					Body: bodyBytes,
				}
			}

			var fileKey []byte
			for _, id := range identities {
				fileKey, err = id.Unwrap(stanzas)
				if err == nil {
					break
				}
			}
			if fileKey == nil {
				fmt.Fprintf(os.Stderr, "[relay-operator]   No identity could unwrap — rejecting\n")
				if err := rejectIntent(brokerURL, intent.IntentID, authToken); err != nil {
					fmt.Fprintf(os.Stderr, "[relay-operator]   Reject error: %v\n", err)
				}
				continue
			}

			// 3. Seal file key to plugin's ephemeral public key.
			ephKeyBytes, err := base64.RawStdEncoding.DecodeString(intent.PluginHeaders.EphemeralKey)
			if err != nil || len(ephKeyBytes) != 32 {
				fmt.Fprintf(os.Stderr, "[relay-operator]   Invalid ephemeral key — rejecting\n")
				if err := rejectIntent(brokerURL, intent.IntentID, authToken); err != nil {
					fmt.Fprintf(os.Stderr, "[relay-operator]   Reject error: %v\n", err)
				}
				clear(fileKey)
				continue
			}

			var clientPub [32]byte
			copy(clientPub[:], ephKeyBytes)

			sealed, err := relay.SealFileKey(fileKey, clientPub)
			clear(fileKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[relay-operator]   Seal error: %v — rejecting\n", err)
				if err := rejectIntent(brokerURL, intent.IntentID, authToken); err != nil {
					fmt.Fprintf(os.Stderr, "[relay-operator]   Reject error: %v\n", err)
				}
				continue
			}

			// 4. Fulfill the intent.
			if err := fulfillIntent(brokerURL, intent.IntentID, sealed, authToken); err != nil {
				fmt.Fprintf(os.Stderr, "[relay-operator]   Fulfill error: %v\n", err)
				continue
			}
			fmt.Fprintf(os.Stderr, "[relay-operator]   Fulfilled intent %s\n", intent.IntentID)
		}

		time.Sleep(pullInterval)
	}
}

func pullIntents(brokerURL, tag, authToken string) (*broker.PullResponse, error) {
	req := relay.RelayRequest{
		Version: 1,
		Action:  "pull",
		Tag:     tag,
	}
	return doRequest[broker.PullResponse](brokerURL, req, authToken)
}

func fulfillIntent(brokerURL, intentID, encryptedFileKey, authToken string) error {
	req := relay.RelayRequest{
		Version:          1,
		Action:           "fulfill",
		IntentID:         intentID,
		EncryptedFileKey: encryptedFileKey,
	}
	_, err := doRequest[map[string]string](brokerURL, req, authToken)
	return err
}

func rejectIntent(brokerURL, intentID, authToken string) error {
	req := relay.RelayRequest{
		Version:  1,
		Action:   "reject",
		IntentID: intentID,
	}
	_, err := doRequest[map[string]string](brokerURL, req, authToken)
	return err
}

func doRequest[T any](brokerURL string, req relay.RelayRequest, authToken string) (*T, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", brokerURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if authToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var result T
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &result, nil
}

func loadIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return age.ParseIdentities(f)
}
