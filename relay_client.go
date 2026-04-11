package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"filippo.io/age"
)

// RelayRequest is the JSON body sent to the relay endpoint.
type RelayRequest struct {
	Version int           `json:"version"`
	Stanzas []RelayStanza `json:"stanzas"`
}

// RelayStanza is a single age stanza serialized for the relay protocol.
type RelayStanza struct {
	Type string   `json:"type"`
	Args []string `json:"args"`
	Body string   `json:"body"` // base64 raw standard encoding
}

// RelayResponse is the JSON response from the relay endpoint.
type RelayResponse struct {
	FileKey string `json:"file_key,omitempty"` // base64 raw standard encoding
	Error   string `json:"error,omitempty"`
}

// PostToRelay sends inner stanzas to the relay URL and returns the unwrapped file key.
func PostToRelay(relayURL string, stanzas []*age.Stanza) ([]byte, error) {
	req := RelayRequest{
		Version: 1,
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

	client := newHTTPClient()

	httpReq, err := http.NewRequest("POST", relayURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("posting to relay %s: %w", relayURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16)) // 64KB max
	if err != nil {
		return nil, fmt.Errorf("reading relay response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var relayResp RelayResponse
		if json.Unmarshal(respBody, &relayResp) == nil && relayResp.Error != "" {
			return nil, fmt.Errorf("relay error (HTTP %d): %s", resp.StatusCode, relayResp.Error)
		}
		return nil, fmt.Errorf("relay returned HTTP %d: %s", resp.StatusCode, respBody)
	}

	var relayResp RelayResponse
	if err := json.Unmarshal(respBody, &relayResp); err != nil {
		return nil, fmt.Errorf("decoding relay response: %w", err)
	}
	if relayResp.Error != "" {
		return nil, fmt.Errorf("relay error: %s", relayResp.Error)
	}

	fileKey, err := base64.RawStdEncoding.DecodeString(relayResp.FileKey)
	if err != nil {
		return nil, fmt.Errorf("decoding file key: %w", err)
	}
	return fileKey, nil
}

func newHTTPClient() *http.Client {
	timeout := 300 * time.Second
	if v := os.Getenv("AGE_PLUGIN_RELAY_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			timeout = d
		}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{}

	certFile := os.Getenv("AGE_PLUGIN_RELAY_TLS_CERT")
	keyFile := os.Getenv("AGE_PLUGIN_RELAY_TLS_KEY")
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err == nil {
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	caFile := os.Getenv("AGE_PLUGIN_RELAY_TLS_CA")
	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err == nil {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = pool
		}
	}

	transport.TLSClientConfig = tlsConfig

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}
