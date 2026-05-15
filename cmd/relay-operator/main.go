// relay-operator is a CLI tool that polls a relay-broker for pending unwrap
// intents, decrypts the encrypted payload using an age identity, unwraps
// stanzas locally, and fulfills (or rejects) the intent.
//
// The operator holds the age private key. The broker is treated as zero-trust —
// all payloads are encrypted end-to-end between the plugin and the operator.
//
// Usage:
//
//	relay-operator \
//	  --broker https://broker.example:8443 \
//	  --identity keys.txt \
//	  --tag QPg24ggKk7xKd2t3c5rL9A \
//	  [--loop] \
//	  [--auth-token broker-bearer-token] \
//	  [--pull-interval 5s]
//
// By default the operator runs in one-shot mode: it pulls pending intents once,
// processes them, and exits. Use --loop to run as a continuous polling daemon.
package main

import (
	"bytes"
	"crypto/ed25519"
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
		authToken    string
		loop         bool
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
		case "--auth-token":
			i++
			if i < len(os.Args) {
				authToken = os.Args[i]
			}
		case "--loop":
			loop = true
		case "--pull-interval":
			i++
			if i < len(os.Args) {
				if d, err := time.ParseDuration(os.Args[i]); err == nil {
					pullInterval = d
				}
			}
		}
	}

	if brokerURL == "" || identityFile == "" || tag == "" {
		fmt.Fprintf(os.Stderr, "Usage: relay-operator --broker URL --identity FILE --tag TAG [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  --loop               Run as a continuous daemon (default: one-shot)\n")
		fmt.Fprintf(os.Stderr, "  --auth-token TOKEN   Bearer token for broker access\n")
		fmt.Fprintf(os.Stderr, "  --pull-interval DUR  Polling interval in loop mode (default: 5s)\n")
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
	if loop {
		fmt.Fprintf(os.Stderr, "[relay-operator] Polling %s for tag=%s every %s (loop mode)\n", brokerURL, tag, pullInterval)
	} else {
		fmt.Fprintf(os.Stderr, "[relay-operator] Pulling %s for tag=%s (one-shot)\n", brokerURL, tag)
	}

	for {
		processIntents(brokerURL, tag, authToken, identities)

		if !loop {
			break
		}
		time.Sleep(pullInterval)
	}
}

func processIntents(brokerURL, tag, authToken string, identities []age.Identity) {
	pullResp, err := pullIntents(brokerURL, tag, authToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[relay-operator] Pull error: %v\n", err)
		return
	}

	for _, intent := range pullResp.Intents {
		fmt.Fprintf(os.Stderr, "[relay-operator] Processing intent %s\n", intent.IntentID)

		// 0. Unmarshal the verbatim request from the broker.
		var req relay.RelayRequest
		if err := json.Unmarshal(intent.Request, &req); err != nil {
			fmt.Fprintf(os.Stderr, "[relay-operator]   Malformed request — skipping\n")
			continue
		}

		// 1. Decrypt the encrypted payload.
		if req.EncryptedPayload == "" {
			fmt.Fprintf(os.Stderr, "[relay-operator]   No encrypted_payload — skipping\n")
			continue
		}

		inner, err := relay.DecryptPayload(req.EncryptedPayload, identities)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[relay-operator]   Decrypt failed: %v — skipping\n", err)
			continue
		}

		// 2. Verify outer hash and expiry.
		if err := relay.VerifyRequestPayload(inner, req.Version, req.Action, req.Stream, req.IntentID, req.Tag, req.ExpiresAt, req.IntentClaimPub); err != nil {
			fmt.Fprintf(os.Stderr, "[relay-operator]   Verification failed: %v — rejecting\n", err)
			if err := rejectIntent(brokerURL, intent.IntentID, inner.EphemeralKey, nil, authToken); err != nil {
				fmt.Fprintf(os.Stderr, "[relay-operator]   Reject error: %v\n", err)
			}
			continue
		}

		// 2b. Extract intent claim secret for signing fulfill/reject.
		var claimPriv ed25519.PrivateKey
		if inner.IntentClaimSecret != "" {
			priv, err := relay.DecodeIntentClaimSecret(inner.IntentClaimSecret)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[relay-operator]   Invalid intent claim secret: %v — skipping\n", err)
				continue
			}
			claimPriv = priv
		}

		// 3. Convert stanzas and attempt unwrap.
		stanzas := make([]*age.Stanza, len(inner.Stanzas))
		for i, s := range inner.Stanzas {
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
			if err := rejectIntent(brokerURL, intent.IntentID, inner.EphemeralKey, claimPriv, authToken); err != nil {
				fmt.Fprintf(os.Stderr, "[relay-operator]   Reject error: %v\n", err)
			}
			continue
		}

		// 4. Build response payload and seal with age encryption to plugin's ephemeral recipient.
		respInner, err := relay.BuildResponsePayload(1, "fulfill", intent.IntentID, fileKey)
		clear(fileKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[relay-operator]   Build response error: %v — rejecting\n", err)
			if err := rejectIntent(brokerURL, intent.IntentID, inner.EphemeralKey, claimPriv, authToken); err != nil {
				fmt.Fprintf(os.Stderr, "[relay-operator]   Reject error: %v\n", err)
			}
			continue
		}

		sealed, err := relay.SealResponse(*respInner, inner.EphemeralKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[relay-operator]   Seal error: %v — rejecting\n", err)
			if err := rejectIntent(brokerURL, intent.IntentID, inner.EphemeralKey, claimPriv, authToken); err != nil {
				fmt.Fprintf(os.Stderr, "[relay-operator]   Reject error: %v\n", err)
			}
			continue
		}

		// 6. Fulfill the intent.
		if err := fulfillIntent(brokerURL, intent.IntentID, sealed, claimPriv, authToken); err != nil {
			fmt.Fprintf(os.Stderr, "[relay-operator]   Fulfill error: %v\n", err)
			continue
		}
		fmt.Fprintf(os.Stderr, "[relay-operator]   Fulfilled intent %s\n", intent.IntentID)
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

func fulfillIntent(brokerURL, intentID, encryptedPayload string, claimPriv ed25519.PrivateKey, authToken string) error {
	var claimSig string
	if claimPriv != nil {
		claimSig = relay.SignIntentClaim(claimPriv, 1, "fulfill", intentID, encryptedPayload)
	}
	req := relay.RelayRequest{
		Version:          1,
		Action:           "fulfill",
		IntentID:         intentID,
		IntentClaimSig:   claimSig,
		EncryptedPayload: encryptedPayload,
	}
	_, err := doRequest[map[string]string](brokerURL, req, authToken)
	return err
}

func rejectIntent(brokerURL, intentID, ephemeralKey string, claimPriv ed25519.PrivateKey, authToken string) error {
	// Build reject inner payload with outer hash (empty file_key).
	respInner, err := relay.BuildResponsePayload(1, "reject", intentID, nil)
	if err != nil {
		return fmt.Errorf("building reject payload: %w", err)
	}
	sealed, err := relay.SealResponse(*respInner, ephemeralKey)
	if err != nil {
		return fmt.Errorf("sealing reject payload: %w", err)
	}
	var claimSig string
	if claimPriv != nil {
		claimSig = relay.SignIntentClaim(claimPriv, 1, "reject", intentID, sealed)
	}
	req := relay.RelayRequest{
		Version:          1,
		Action:           "reject",
		IntentID:         intentID,
		IntentClaimSig:   claimSig,
		EncryptedPayload: sealed,
	}
	_, err = doRequest[map[string]string](brokerURL, req, authToken)
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
