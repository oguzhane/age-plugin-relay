// relay-server is a minimal HTTP server that unwraps age stanzas using a local
// identity file. It implements the age-plugin-relay HTTP contract.
//
// Usage:
//
//	relay-server -identity keys.txt [-addr :9876]
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"filippo.io/age"

	"github.com/oguzhane/age-plugin-relay/relay"
)

func main() {
	identityFile := ""
	addr := ":9876"

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
		}
	}

	if identityFile == "" {
		fmt.Fprintf(os.Stderr, "Usage: relay-server -identity <file> [-addr :9876]\n")
		fmt.Fprintf(os.Stderr, "\nMinimal relay server for age-plugin-relay.\n")
		fmt.Fprintf(os.Stderr, "Serves POST /unwrap — receives age stanzas, unwraps with local identity, returns file key.\n")
		os.Exit(1)
	}

	identities, err := loadIdentities(identityFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading identities: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[relay-server] Loaded %d identity(ies) from %s\n", len(identities), identityFile)

	http.HandleFunc("/unwrap", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, relay.RelayResponse{Error: "method not allowed"})
			return
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

		fmt.Fprintf(os.Stderr, "[relay-server] Received %d stanza(s)", len(req.Stanzas))
		if len(req.Stanzas) > 0 {
			fmt.Fprintf(os.Stderr, ", type=%s", req.Stanzas[0].Type)
		}
		fmt.Fprintf(os.Stderr, "\n")

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
				writeJSON(w, http.StatusOK, relay.RelayResponse{
					FileKey: base64.RawStdEncoding.EncodeToString(fileKey),
				})
				return
			}
		}

		fmt.Fprintf(os.Stderr, "[relay-server] No identity could unwrap the stanzas\n")
		writeJSON(w, http.StatusNotFound, relay.RelayResponse{Error: "no_matching_identity"})
	})

	fmt.Fprintf(os.Stderr, "[relay-server] Listening on %s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
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
