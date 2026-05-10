// relay-server is a minimal HTTP server that unwraps age stanzas using a local
// identity file. It implements the age-plugin-relay HTTP contract with mandatory
// encrypted payload — all requests contain age-encrypted inner payloads, all
// responses are NaCl box sealed.
//
// Usage:
//
//	relay-server -identity keys.txt [-addr :9876] [-tls-cert cert.pem -tls-key key.pem] [-tls-ca ca.pem] [-auth-token TOKEN]
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
		}
	}

	if identityFile == "" {
		fmt.Fprintf(os.Stderr, "Usage: relay-server -identity <file> [-addr :9876] [options]\n")
		fmt.Fprintf(os.Stderr, "\nMinimal relay server for age-plugin-relay.\n")
		fmt.Fprintf(os.Stderr, "Serves POST /unwrap — receives encrypted payload, decrypts, unwraps stanzas, returns sealed file key.\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  -tls-cert <file>    TLS server certificate (enables HTTPS)\n")
		fmt.Fprintf(os.Stderr, "  -tls-key <file>     TLS server private key (required with -tls-cert)\n")
		fmt.Fprintf(os.Stderr, "  -tls-ca <file>      CA certificate for client verification (enables mTLS)\n")
		fmt.Fprintf(os.Stderr, "  -auth-token <token>  Required Bearer token for all requests\n")
		os.Exit(1)
	}

	// Auth token from flag or env.
	if authToken == "" {
		authToken = os.Getenv("RELAY_AUTH_TOKEN")
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

		var req relay.RelayRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, relay.RelayResponse{Error: "invalid JSON: " + err.Error()})
			return
		}

		fmt.Fprintf(os.Stderr, "[relay-server] Received action=%s, version=%d, stream=%v\n", req.Action, req.Version, req.Stream)

		if req.Version != 1 {
			writeJSON(w, http.StatusBadRequest, relay.RelayResponse{Error: fmt.Sprintf("unsupported protocol version: %d", req.Version)})
			return
		}

		if req.Action != "unwrap" {
			writeJSON(w, http.StatusBadRequest, relay.RelayResponse{Error: "unsupported action: " + req.Action})
			return
		}

		if req.EncryptedPayload == "" {
			writeJSON(w, http.StatusBadRequest, relay.RelayResponse{Error: "missing encrypted_payload"})
			return
		}

		// 1. Decrypt the encrypted payload using our identity.
		inner, err := relay.DecryptPayload(req.EncryptedPayload, identities)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, relay.RelayResponse{Error: "decrypting payload: " + err.Error()})
			return
		}

		// 2. Verify outer hash and expiry.
		if err := relay.VerifyRequestPayload(inner, req.Version, req.Action, req.IntentID, req.Tag, req.ExpiresAt); err != nil {
			writeJSON(w, http.StatusBadRequest, relay.RelayResponse{Error: "payload verification: " + err.Error()})
			return
		}

		// 3. Extract stanzas and ephemeral key.
		stanzas := make([]*age.Stanza, len(inner.Stanzas))
		for i, s := range inner.Stanzas {
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

		ephKeyBytes, err := base64.RawStdEncoding.DecodeString(inner.EphemeralKey)
		if err != nil || len(ephKeyBytes) != 32 {
			writeJSON(w, http.StatusBadRequest, relay.RelayResponse{Error: "invalid ephemeral key in payload"})
			return
		}
		var clientPub [32]byte
		copy(clientPub[:], ephKeyBytes)

		// 4. Try each identity to unwrap.
		for _, id := range identities {
			fileKey, err := id.Unwrap(stanzas)
			if err == nil {
				fmt.Fprintf(os.Stderr, "[relay-server] Unwrap succeeded, sealing response\n")

				// 5. Build response inner payload.
				respInner, err := relay.BuildResponsePayload(req.IntentID, fileKey)
				clear(fileKey)
				if err != nil {
					writeJSON(w, http.StatusInternalServerError, relay.RelayResponse{Error: "building response payload"})
					return
				}

				// 6. Seal with NaCl box to plugin's ephemeral key.
				sealed, err := relay.SealResponse(*respInner, clientPub)
				if err != nil {
					writeJSON(w, http.StatusInternalServerError, relay.RelayResponse{Error: "sealing response"})
					return
				}

				resp := relay.RelayResponse{EncryptedPayload: sealed}

				if req.Stream {
					writeSSE(w, "result", resp)
				} else {
					writeJSON(w, http.StatusOK, resp)
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
		fmt.Fprintf(os.Stderr, "[relay-server] WARNING: TLS not configured — use -tls-cert and -tls-key for production.\n")
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
