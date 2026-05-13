package relay

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"filippo.io/age"
)

// GenerateIntentID produces a random 16-byte hex string (32 chars) for use as
// a plugin-generated intent ID in the async flow.
func GenerateIntentID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generating intent ID: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// asyncPollResponse is the broker's response to a poll action.
type asyncPollResponse struct {
	Status   string          `json:"status"`
	Response json.RawMessage `json:"response,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// RelayRequest is the JSON envelope for all relay protocol messages.
//
// IMPORTANT — Complete Outer Field Binding: Every field in this struct except
// EncryptedPayload is included in the outer hash (computed inside the encrypted
// payload). If you add a new field, you MUST also add it to OuterHashRequest
// and/or OuterHashResponse in payload.go. See ARCHITECTURE.md §3.5.
type RelayRequest struct {
	Version          int    `json:"version"`
	Action           string `json:"action"`
	Stream           bool   `json:"stream,omitempty"`             // request SSE response
	IntentID         string `json:"intent_id,omitempty"`          // plugin-generated, 16 random bytes hex
	Tag              string `json:"tag,omitempty"`                // routing tag for operator pull
	ExpiresAt        int64  `json:"expires_at,omitempty"`         // Unix timestamp (seconds)
	EncryptedPayload string `json:"encrypted_payload,omitempty"` // age-encrypted inner payload
}

// RelayStanza is a single age stanza serialized for the relay protocol.
type RelayStanza struct {
	Type string   `json:"type"`
	Args []string `json:"args"`
	Body string   `json:"body"` // base64 raw standard encoding
}

// RelayResponse is the JSON response from the relay endpoint.
type RelayResponse struct {
	EncryptedPayload string `json:"encrypted_payload,omitempty"` // age-encrypted inner response
	Error            string `json:"error,omitempty"`
}

// PostToRelay sends inner stanzas to the relay URL and returns the unwrapped file key.
// The innerRecipient is the age recipient string of the unwrapper (operator/server).
// All payloads are encrypted — the broker sees only opaque blobs.
//
// If the server responds with 202 Accepted, the client switches to async polling
// (Control Tower flow): it polls with the intent_id until the intent is fulfilled,
// rejected, or the local timeout elapses.
func PostToRelay(remote RemoteConfig, stanzas []*age.Stanza, innerRecipient string) ([]byte, error) {
	intentID, err := GenerateIntentID()
	if err != nil {
		return nil, err
	}

	// Always generate ephemeral keypair for response encryption.
	ephemeral, err := GenerateEphemeral()
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}
	defer ephemeral.Clear()

	ephemeralRecipient := ephemeral.RecipientString()

	// Compute outer fields.
	expiresAt := time.Now().Add(remote.TimeoutDuration()).Unix()
	tagBytes := ComputeTag(innerRecipient)
	tag := base64.RawStdEncoding.EncodeToString(tagBytes[:4])

	// Build inner stanzas.
	relayStanzas := make([]RelayStanza, len(stanzas))
	for i, s := range stanzas {
		relayStanzas[i] = RelayStanza{
			Type: s.Type,
			Args: s.Args,
			Body: base64.RawStdEncoding.EncodeToString(s.Body),
		}
	}

	// Build and encrypt inner payload.
	inner, err := BuildRequestPayload(1, "unwrap", remote.Stream, intentID, tag, expiresAt, relayStanzas, ephemeralRecipient)
	if err != nil {
		return nil, fmt.Errorf("building inner payload: %w", err)
	}

	encryptedPayload, err := EncryptPayload(*inner, innerRecipient)
	if err != nil {
		return nil, fmt.Errorf("encrypting payload: %w", err)
	}

	// Build outer request.
	req := RelayRequest{
		Version:          1,
		Action:           "unwrap",
		Stream:           remote.Stream,
		IntentID:         intentID,
		Tag:              tag,
		ExpiresAt:        expiresAt,
		EncryptedPayload: encryptedPayload,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	client, err := newHTTPClient(remote)
	if err != nil {
		return nil, fmt.Errorf("building HTTP client: %w", err)
	}

	httpReq, err := http.NewRequest("POST", remote.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Add auth token if configured.
	token := remote.AuthToken
	if token == "" {
		token = os.Getenv("AGE_PLUGIN_RELAY_AUTH_TOKEN")
	}
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("posting to relay %s: %w", remote.URL, err)
	}
	defer resp.Body.Close()

	// 202 Accepted → async flow: switch to polling.
	if resp.StatusCode == http.StatusAccepted {
		return pollForResult(client, remote, intentID, token, ephemeral)
	}

	// 409 Conflict → duplicate intent_id, should not happen with random IDs.
	if resp.StatusCode == http.StatusConflict {
		return nil, fmt.Errorf("broker rejected duplicate intent_id %s", intentID)
	}

	// Dispatch based on response content type (sync flow).
	ct := resp.Header.Get("Content-Type")
	var fileKey []byte
	if strings.HasPrefix(ct, "text/event-stream") {
		fileKey, err = readSSEResponse(resp.Body, ephemeral, intentID)
	} else {
		fileKey, err = readJSONResponse(resp, ephemeral, intentID)
	}
	if err != nil {
		return nil, err
	}
	return fileKey, nil
}

// pollForResult polls the broker for the result of an async intent until
// fulfilled, rejected, unknown (expired), or local timeout.
func pollForResult(client *http.Client, remote RemoteConfig, intentID, token string, ephemeral *EphemeralKeypair) ([]byte, error) {
	pollInterval := remote.PollIntervalDuration()
	deadline := time.Now().Add(remote.TimeoutDuration())

	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("async intent %s timed out waiting for fulfillment", intentID)
		}

		time.Sleep(pollInterval)

		pollReq := RelayRequest{
			Version:  1,
			Action:   "poll",
			IntentID: intentID,
		}
		pollBody, err := json.Marshal(pollReq)
		if err != nil {
			return nil, fmt.Errorf("marshaling poll request: %w", err)
		}

		httpReq, err := http.NewRequest("POST", remote.URL, bytes.NewReader(pollBody))
		if err != nil {
			return nil, fmt.Errorf("creating poll request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if token != "" {
			httpReq.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := client.Do(httpReq)
		if err != nil {
			// Transient network error — retry.
			continue
		}

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		if err != nil {
			continue
		}

		// 404 → intent expired or unknown — terminal failure.
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("async intent %s: unknown or expired", intentID)
		}

		if resp.StatusCode != http.StatusOK {
			// Unexpected status — retry.
			continue
		}

		var pollResp asyncPollResponse
		if err := json.Unmarshal(respBody, &pollResp); err != nil {
			continue
		}

		switch pollResp.Status {
		case "pending":
			// Keep polling.
			continue
		case "fulfilled":
			if pollResp.Response != nil {
				var fulfillReq RelayRequest
				if err := json.Unmarshal(pollResp.Response, &fulfillReq); err != nil {
					return nil, fmt.Errorf("parsing fulfill response for intent %s: %w", intentID, err)
				}
				return extractFileKey(RelayResponse{EncryptedPayload: fulfillReq.EncryptedPayload}, ephemeral, fulfillReq.Version, fulfillReq.Action, intentID)
			}
			return nil, fmt.Errorf("async intent %s: fulfilled but no response", intentID)
		case "rejected":
			return nil, fmt.Errorf("async intent %s: rejected by operator", intentID)
		default:
			// Unknown status — retry.
			continue
		}
	}
}

// readJSONResponse handles standard JSON responses (non-streaming).
func readJSONResponse(resp *http.Response, ephemeral *EphemeralKeypair, intentID string) ([]byte, error) {
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("reading relay response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var relayResp RelayResponse
		if json.Unmarshal(respBody, &relayResp) == nil && relayResp.Error != "" {
			return nil, fmt.Errorf("relay error (HTTP %d): %s", resp.StatusCode, sanitizeErrorMsg(relayResp.Error))
		}
		return nil, fmt.Errorf("relay returned HTTP %d", resp.StatusCode)
	}

	var envelope RelayRequest
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, fmt.Errorf("decoding relay response: %w", err)
	}

	// Reject: decrypt and verify outer hash, then return reject error.
	if envelope.Action == "reject" {
		return nil, verifyReject(envelope, ephemeral, intentID)
	}

	return extractFileKey(RelayResponse{EncryptedPayload: envelope.EncryptedPayload}, ephemeral, envelope.Version, envelope.Action, intentID)
}

// extractFileKey opens the age-encrypted response, verifies the outer hash,
// and returns the file key.
func extractFileKey(resp RelayResponse, ephemeral *EphemeralKeypair, version int, action, intentID string) ([]byte, error) {
	if resp.EncryptedPayload == "" {
		return nil, fmt.Errorf("relay response contains no encrypted_payload")
	}

	inner, err := OpenResponse(resp.EncryptedPayload, ephemeral.Identity)
	if err != nil {
		return nil, fmt.Errorf("opening sealed response: %w", err)
	}

	if err := VerifyResponsePayload(inner, version, action, intentID); err != nil {
		return nil, fmt.Errorf("verifying response payload: %w", err)
	}

	fileKey, err := base64.RawStdEncoding.DecodeString(inner.FileKey)
	if err != nil {
		return nil, fmt.Errorf("decoding file key from response: %w", err)
	}
	return fileKey, nil
}

// verifyReject decrypts a reject envelope's encrypted_payload, verifies the
// outer hash, and returns a reject error. This ensures the reject is authentic
// (not forged by a broker or MITM).
func verifyReject(envelope RelayRequest, ephemeral *EphemeralKeypair, intentID string) error {
	if envelope.EncryptedPayload == "" {
		return fmt.Errorf("reject response contains no encrypted_payload")
	}
	inner, err := OpenResponse(envelope.EncryptedPayload, ephemeral.Identity)
	if err != nil {
		return fmt.Errorf("opening reject payload: %w", err)
	}
	if err := VerifyResponsePayload(inner, envelope.Version, "reject", intentID); err != nil {
		return fmt.Errorf("verifying reject payload: %w", err)
	}
	return fmt.Errorf("sync intent %s: rejected (no matching identity)", intentID)
}

// readSSEResponse parses a Server-Sent Events stream, looking for a "result"
// or "error" event.
func readSSEResponse(r io.Reader, ephemeral *EphemeralKeypair, intentID string) ([]byte, error) {
	const maxSSEBytes = 1 << 20 // 1MB
	limited := io.LimitReader(r, maxSSEBytes)
	scanner := bufio.NewScanner(limited)

	var eventType string
	var dataBuf strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		// SSE comment (heartbeat) — ignore.
		if strings.HasPrefix(line, ":") {
			continue
		}

		// Empty line = end of event.
		if line == "" {
			if eventType != "" && dataBuf.Len() > 0 {
				result, done, err := handleSSEEvent(eventType, dataBuf.String(), ephemeral, intentID)
				if err != nil {
					return nil, err
				}
				if done {
					return result, nil
				}
			}
			eventType = ""
			dataBuf.Reset()
			continue
		}

		// Parse field.
		if strings.HasPrefix(line, "event:") {
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading SSE stream: %w", err)
	}

	// Stream ended without a result or error event.
	if eventType != "" && dataBuf.Len() > 0 {
		result, _, err := handleSSEEvent(eventType, dataBuf.String(), ephemeral, intentID)
		if err != nil {
			return nil, err
		}
		if result != nil {
			return result, nil
		}
	}

	return nil, fmt.Errorf("SSE stream ended without result or error event")
}

// handleSSEEvent processes a single SSE event. Returns (fileKey, done, error).
func handleSSEEvent(eventType, data string, ephemeral *EphemeralKeypair, intentID string) ([]byte, bool, error) {
	switch eventType {
	case "result":
		var envelope RelayRequest
		if err := json.Unmarshal([]byte(data), &envelope); err != nil {
			return nil, false, fmt.Errorf("decoding SSE result: %w", err)
		}
		fileKey, err := extractFileKey(RelayResponse{EncryptedPayload: envelope.EncryptedPayload}, ephemeral, envelope.Version, envelope.Action, intentID)
		if err != nil {
			return nil, false, fmt.Errorf("extracting file key from SSE: %w", err)
		}
		return fileKey, true, nil

	case "error":
		var resp RelayResponse
		if err := json.Unmarshal([]byte(data), &resp); err != nil {
			return nil, true, fmt.Errorf("relay SSE error (unparseable)")
		}
		return nil, true, fmt.Errorf("relay error: %s", sanitizeErrorMsg(resp.Error))

	case "reject":
		var envelope RelayRequest
		if err := json.Unmarshal([]byte(data), &envelope); err != nil {
			return nil, true, fmt.Errorf("relay SSE reject (unparseable)")
		}
		return nil, true, verifyReject(envelope, ephemeral, intentID)

	default:
		// Unknown event type — ignore (forward compat).
		return nil, false, nil
	}
}

// newHTTPClient builds an HTTP client from a RemoteConfig.
func newHTTPClient(remote RemoteConfig) (*http.Client, error) {
	timeout := remote.TimeoutDuration()
	if v := os.Getenv("AGE_PLUGIN_RELAY_TIMEOUT"); v != "" && remote.Timeout == "" {
		if d, err := time.ParseDuration(v); err == nil {
			timeout = d
		}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	certFile := remote.TLSCert
	keyFile := remote.TLSKey
	if certFile == "" {
		certFile = os.Getenv("AGE_PLUGIN_RELAY_TLS_CERT")
	}
	if keyFile == "" {
		keyFile = os.Getenv("AGE_PLUGIN_RELAY_TLS_KEY")
	}
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading TLS client cert/key (%s, %s): %w", certFile, keyFile, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	caFile := remote.TLSCA
	if caFile == "" {
		caFile = os.Getenv("AGE_PLUGIN_RELAY_TLS_CA")
	}
	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading TLS CA file %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("no valid certs found in CA file %s", caFile)
		}
		tlsConfig.RootCAs = pool
	}

	transport.TLSClientConfig = tlsConfig

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}, nil
}

// sanitizeErrorMsg truncates and cleans an error message from the relay server.
func sanitizeErrorMsg(msg string) string {
	const maxLen = 256
	if len(msg) > maxLen {
		msg = msg[:maxLen] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\n' {
			return -1
		}
		return r
	}, msg)
}
