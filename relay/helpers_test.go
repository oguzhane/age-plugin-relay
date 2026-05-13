package relay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"filippo.io/age"
)

// newMockRelayServer starts a mock that handles encrypted payload: decrypt, verify,
// unwrap, build response, seal.
func newMockRelayServer(t *testing.T, identity *age.X25519Identity) *httptest.Server {
	t.Helper()
	recipientStr := identity.Recipient().String()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req RelayRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			json.NewEncoder(w).Encode(RelayResponse{Error: err.Error()})
			return
		}

		if req.EncryptedPayload == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(RelayResponse{Error: "missing encrypted_payload"})
			return
		}

		// Decrypt inner payload.
		inner, err := DecryptPayload(req.EncryptedPayload, []age.Identity{identity})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(RelayResponse{Error: "decrypt: " + err.Error()})
			return
		}

		// Verify.
		if err := VerifyRequestPayload(inner, req.Version, req.Action, req.Stream, req.IntentID, req.Tag, req.ExpiresAt); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(RelayResponse{Error: "verify: " + err.Error()})
			return
		}

		// Extract stanzas.
		stanzas := make([]*age.Stanza, len(inner.Stanzas))
		for i, s := range inner.Stanzas {
			body, _ := base64.RawStdEncoding.DecodeString(s.Body)
			stanzas[i] = &age.Stanza{Type: s.Type, Args: s.Args, Body: body}
		}

		fileKey, err := identity.Unwrap(stanzas)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(RelayResponse{Error: err.Error()})
			return
		}

		// Build and seal response.
		respInner, _ := BuildResponsePayload(1, "fulfill", req.IntentID, fileKey)
		sealed, _ := SealResponse(*respInner, inner.EphemeralKey)

		resp := RelayRequest{Version: 1, Action: "fulfill", IntentID: req.IntentID, EncryptedPayload: sealed}
		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, ": heartbeat\n\n")
			data, _ := json.Marshal(resp)
			fmt.Fprintf(w, "event: result\ndata: %s\n\n", data)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		} else {
			json.NewEncoder(w).Encode(resp)
		}
		_ = recipientStr
	}))
}
