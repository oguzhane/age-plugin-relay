// relay-server is a minimal HTTP server that unwraps age stanzas using a local
// identity file. It implements the age-plugin-relay HTTP contract.
//
// Usage:
//
//	relay-server -identity keys.txt [-addr :9876] [-tls-cert cert.pem -tls-key key.pem] [-tls-ca ca.pem] [-auth-token TOKEN] [-hmac-key KEY]
package main

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"filippo.io/age"

	"github.com/oguzhane/age-plugin-relay/relay"
)

func main() {
	identityFile := ""
	addr := ":9876"
	tlsCert := ""
	tlsKey := ""
	tlsCA := ""
	authToken := ""
	hmacKey := ""

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-identity":
			i++
			if i < len(os.Args) {
				identityFile = os.Args[i]
			}
		case "-addr":
			i++
			if i < len(os.Args) {
				addr = os.Args[i]
			}
		case "-tls-cert":
			i++
			if i < len(os.Args) {
				tlsCert = os.Args[i]
			}
		case "-tls-key":
			i++
			if i < len(os.Args) {
				tlsKey = os.Args[i]
			}
		case "-tls-ca":
			i++
			if i < len(os.Args) {
				tlsCA = os.Args[i]
			}
		case "-auth-token":
			i++
			if i < len(os.Args) {
				authToken = os.Args[i]
			}
		case "-hmac-key":
			i++
			if i < len(os.Args) {
				hmacKey = os.Args[i]
			}
		}
	}

	if identityFile == "" {
		fmt.Fprintf(os.Stderr, "Usage: relay-server -identity <file> [-addr :9876] [options]\n")
		fmt.Fprintf(os.Stderr, "\nMinimal relay server for age-plugin-relay.\n")
		fmt.Fprintf(os.Stderr, "Serves POST /unwrap — receives age stanzas, unwraps with local identity, returns file key.\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  -tls-cert <file>    TLS server certificate (enables HTTPS)\n")
		fmt.Fprintf(os.Stderr, "  -tls-key <file>     TLS server private key (required with -tls-cert)\n")
		fmt.Fprintf(os.Stderr, "  -tls-ca <file>      CA certificate for client verification (enables mTLS)\n")
		fmt.Fprintf(os.Stderr, "  -auth-token <token>  Required Bearer token for all requests\n")
		fmt.Fprintf(os.Stderr, "  -hmac-key <key>      HMAC-SHA256 shared key for request signing + replay protection\n")
		os.Exit(1)
	}

	// Auth token from flag or env.
	if authToken == "" {
		authToken = os.Getenv("RELAY_AUTH_TOKEN")
	}

	// HMAC key from flag or env.
	if hmacKey == "" {
		hmacKey = os.Getenv("RELAY_HMAC_KEY")
	}

	// Nonce cache for HMAC replay protection.
	var (
		nonceMu    sync.Mutex
		seenNonces = make(map[string]time.Time)
	)
	if hmacKey != "" {
		go func() {
			for {
				time.Sleep(relay.HMACMaxDrift)
				nonceMu.Lock()
				now := time.Now()
				for k, t := range seenNonces {
					if now.Sub(t) > relay.HMACMaxDrift {
						delete(seenNonces, k)
					}
				}
				nonceMu.Unlock()
			}
		}()
	}

	identities, err := loadIdentities(identityFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading identities: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[relay-server] Loaded %d identity(ies) from %s\n", len(identities), identityFile)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, relay.RelayResponse{Error: "method not allowed"})
			return
		}

		// Auth token check.
		if authToken != "" {
			provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(provided), []byte(authToken)) != 1 {
				writeJSON(w, http.StatusUnauthorized, relay.RelayResponse{Error: "unauthorized"})
				return
			}
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, relay.RelayResponse{Error: "reading body: " + err.Error()})
			return
		}

		// HMAC signature verification (optional).
		if hmacKey != "" {
			sig := r.Header.Get(relay.HMACHeaderSignature)
			ts := r.Header.Get(relay.HMACHeaderTimestamp)
			nonce := r.Header.Get(relay.HMACHeaderNonce)
			if sig == "" || ts == "" || nonce == "" {
				writeJSON(w, http.StatusUnauthorized, relay.RelayResponse{Error: "missing HMAC signature headers"})
				return
			}
			if err := relay.ValidateTimestamp(ts); err != nil {
				writeJSON(w, http.StatusUnauthorized, relay.RelayResponse{Error: "HMAC: " + err.Error()})
				return
			}
			if err := relay.VerifySignature([]byte(hmacKey), ts, nonce, body, sig); err != nil {
				writeJSON(w, http.StatusUnauthorized, relay.RelayResponse{Error: "HMAC: " + err.Error()})
				return
			}
			// Reject replayed nonces.
			nonceMu.Lock()
			if _, seen := seenNonces[nonce]; seen {
				nonceMu.Unlock()
				writeJSON(w, http.StatusUnauthorized, relay.RelayResponse{Error: "HMAC: duplicate nonce"})
				return
			}
			seenNonces[nonce] = time.Now()
			nonceMu.Unlock()
		}

		var req relay.RelayRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, relay.RelayResponse{Error: "invalid JSON: " + err.Error()})
			return
		}

		fmt.Fprintf(os.Stderr, "[relay-server] Received %d stanza(s)", len(req.Stanzas))
		if len(req.Stanzas) > 0 {
			fmt.Fprintf(os.Stderr, ", type=%s", req.Stanzas[0].Type)
		}
		fmt.Fprintf(os.Stderr, ", action=%s, stream=%v, version=%d\n", req.Action, req.Stream, req.Version)

		if req.Version != 1 {
			writeJSON(w, http.StatusBadRequest, relay.RelayResponse{Error: fmt.Sprintf("unsupported protocol version: %d", req.Version)})
			return
		}

		if req.Action != "unwrap" {
			writeJSON(w, http.StatusBadRequest, relay.RelayResponse{Error: "unsupported action: " + req.Action})
			return
		}

		// Convert to age.Stanza
		stanzas := make([]*age.Stanza, len(req.Stanzas))
		for i, s := range req.Stanzas {
			bodyBytes, err := base64.RawStdEncoding.DecodeString(s.Body)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, relay.RelayResponse{Error: "invalid stanza body: " + err.Error()})
				return
			}
			stanzas[i] = &age.Stanza{
				Type: s.Type,
				Args: s.Args,
				Body: bodyBytes,
			}
		}

		// Try each identity
		for _, id := range identities {
			fileKey, err := id.Unwrap(stanzas)
			if err == nil {
				fmt.Fprintf(os.Stderr, "[relay-server] Unwrap succeeded, returning file key\n")
				fk := base64.RawStdEncoding.EncodeToString(fileKey)

				if req.Stream {
					writeSSE(w, "result", relay.RelayResponse{FileKey: fk})
				} else {
					writeJSON(w, http.StatusOK, relay.RelayResponse{FileKey: fk})
				}
				return
			}
		}

		fmt.Fprintf(os.Stderr, "[relay-server] No identity could unwrap the stanzas\n")
		if req.Stream {
			writeSSE(w, "error", relay.RelayResponse{Error: "no_matching_identity"})
		} else {
			writeJSON(w, http.StatusNotFound, relay.RelayResponse{Error: "no_matching_identity"})
		}
	})

	useTLS := tlsCert != "" && tlsKey != ""
	if useTLS {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		// If CA is provided, require and verify client certs (mTLS).
		if tlsCA != "" {
			caCert, err := os.ReadFile(tlsCA)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading CA cert: %v\n", err)
				os.Exit(1)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				fmt.Fprintf(os.Stderr, "Error: no valid certs found in CA file %s\n", tlsCA)
				os.Exit(1)
			}
			tlsConfig.ClientCAs = pool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			fmt.Fprintf(os.Stderr, "[relay-server] mTLS enabled (client certs required)\n")
		}

		server := &http.Server{
			Addr:      addr,
			TLSConfig: tlsConfig,
		}
		fmt.Fprintf(os.Stderr, "[relay-server] Listening on %s (TLS)\n", addr)
		if err := server.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "[relay-server] WARNING: TLS not configured — file keys will be transmitted in plaintext!\n")
		fmt.Fprintf(os.Stderr, "[relay-server] Use -tls-cert and -tls-key for production deployments.\n")
		fmt.Fprintf(os.Stderr, "[relay-server] Listening on %s (plaintext HTTP)\n", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}

func loadIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return age.ParseIdentities(f)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeSSE(w http.ResponseWriter, event string, v any) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	data, _ := json.Marshal(v)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}
