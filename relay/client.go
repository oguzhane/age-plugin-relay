package relay

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"filippo.io/age"
)

// RelayRequest is the JSON body sent to the relay endpoint.
type RelayRequest struct {
	Version int           `json:"version"`
	Action  string        `json:"action"`
	Stream  bool          `json:"stream,omitempty"` // request SSE response
	Stanzas []RelayStanza `json:"stanzas"`
}

// RelayStanza is a single age stanza serialized for the relay protocol.
type RelayStanza struct {
	Type string   `json:"type"`
	Args []string `json:"args"`
	Body string   `json:"body"` // base64 raw standard encoding
}

// RelayResponse is the JSON response from the relay endpoint.
// Used for both standard JSON responses and SSE event data.
type RelayResponse struct {
	FileKey string `json:"file_key,omitempty"` // base64 raw standard encoding
	Error   string `json:"error,omitempty"`
}

// PostToRelay sends inner stanzas to the relay URL and returns the unwrapped file key.
// If the remote has Stream enabled and the server responds with text/event-stream,
// the client parses SSE events until a "result" or "error" event arrives.
func PostToRelay(remote RemoteConfig, stanzas []*age.Stanza) ([]byte, error) {
	req := RelayRequest{
		Version: 1,
		Action:  "unwrap",
		Stream:  remote.Stream,
		Stanzas: make([]RelayStanza, len(stanzas)),
	}
	for i, s := range stanzas {
		req.Stanzas[i] = RelayStanza{
			Type: s.Type,
			Args: s.Args,
			Body: base64.RawStdEncoding.EncodeToString(s.Body),
		}
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

	// Dispatch based on response content type.
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		return readSSEResponse(resp.Body)
	}
	return readJSONResponse(resp)
}

// readJSONResponse handles standard JSON responses (non-streaming).
func readJSONResponse(resp *http.Response) ([]byte, error) {
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

	var relayResp RelayResponse
	if err := json.Unmarshal(respBody, &relayResp); err != nil {
		return nil, fmt.Errorf("decoding relay response: %w", err)
	}
	if relayResp.Error != "" {
		return nil, fmt.Errorf("relay error: %s", sanitizeErrorMsg(relayResp.Error))
	}

	fileKey, err := base64.RawStdEncoding.DecodeString(relayResp.FileKey)
	if err != nil {
		return nil, fmt.Errorf("decoding file key: %w", err)
	}
	return fileKey, nil
}

// readSSEResponse parses a Server-Sent Events stream, looking for a "result"
// or "error" event. Heartbeat comments and unknown events are ignored.
//
// The total bytes read are limited to 1MB to prevent resource exhaustion from
// a malicious or misbehaving relay server.
//
// SSE format (per https://html.spec.whatwg.org/multipage/server-sent-events.html):
//
//	event: result
//	data: {"file_key": "..."}
//
//	event: error
//	data: {"error": "..."}
//
//	: heartbeat (comment, ignored)
func readSSEResponse(r io.Reader) ([]byte, error) {
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
				result, done, err := handleSSEEvent(eventType, dataBuf.String())
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
		result, _, err := handleSSEEvent(eventType, dataBuf.String())
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
func handleSSEEvent(eventType, data string) ([]byte, bool, error) {
	switch eventType {
	case "result":
		var resp RelayResponse
		if err := json.Unmarshal([]byte(data), &resp); err != nil {
			return nil, false, fmt.Errorf("decoding SSE result: %w", err)
		}
		if resp.Error != "" {
			return nil, true, fmt.Errorf("relay error: %s", sanitizeErrorMsg(resp.Error))
		}
		fileKey, err := base64.RawStdEncoding.DecodeString(resp.FileKey)
		if err != nil {
			return nil, false, fmt.Errorf("decoding file key from SSE: %w", err)
		}
		return fileKey, true, nil

	case "error":
		var resp RelayResponse
		if err := json.Unmarshal([]byte(data), &resp); err != nil {
			return nil, true, fmt.Errorf("relay SSE error (unparseable)")
		}
		return nil, true, fmt.Errorf("relay error: %s", sanitizeErrorMsg(resp.Error))

	default:
		// Unknown event type — ignore (forward compat).
		return nil, false, nil
	}
}

// newHTTPClient builds an HTTP client from a RemoteConfig.
// Per-remote settings take priority; env vars are used as fallback.
// Returns an error if configured TLS files cannot be loaded (fail-closed).
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

// sanitizeErrorMsg truncates and cleans an error message from the relay server
// to prevent information leakage or injection via crafted error strings.
func sanitizeErrorMsg(msg string) string {
	const maxLen = 256
	if len(msg) > maxLen {
		msg = msg[:maxLen] + "..."
	}
	// Strip control characters except space/tab/newline.
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\n' {
			return -1
		}
		return r
	}, msg)
}
