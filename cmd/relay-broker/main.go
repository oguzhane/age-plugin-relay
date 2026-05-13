// relay-broker is a zero-trust stateful queue that bridges age-plugin-relay
// plugins and remote operators for async unwrap flows.
//
// The broker holds no age identity and no key material. It stores opaque,
// encrypted payloads keyed by plugin-supplied intent IDs, indexed by tag.
// Access control uses a single shared Bearer token.
//
// Usage:
//
//	relay-broker [-addr :8443] [-auth-token TOKEN] [-max-ttl 10m]
package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oguzhane/age-plugin-relay/relay"
	"github.com/oguzhane/age-plugin-relay/relay/broker"
)

func main() {
	addr := ":8443"
	authToken := ""
	maxTTL := 10 * time.Minute

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-addr":
			i++
			if i < len(os.Args) {
				addr = os.Args[i]
			}
		case "-auth-token":
			i++
			if i < len(os.Args) {
				authToken = os.Args[i]
			}
		case "-max-ttl":
			i++
			if i < len(os.Args) {
				if d, err := time.ParseDuration(os.Args[i]); err == nil {
					maxTTL = d
				}
			}
		}
	}

	if authToken == "" {
		authToken = os.Getenv("RELAY_BROKER_AUTH_TOKEN")
	}

	sweepInterval := maxTTL / 2
	if sweepInterval < 10*time.Second {
		sweepInterval = 10 * time.Second
	}
	queue := broker.NewQueue(maxTTL, sweepInterval)
	defer queue.Stop()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}

		// Bearer token check.
		if authToken != "" {
			provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(provided), []byte(authToken)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reading body"})
			return
		}

		var req relay.RelayRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}

		if req.Version != 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("unsupported version: %d", req.Version)})
			return
		}

		switch req.Action {
		case "unwrap":
			handleUnwrap(w, body, &req, queue)
		case "poll":
			handlePoll(w, &req, queue)
		case "pull":
			handlePull(w, &req, queue)
		case "fulfill":
			handleFulfill(w, body, &req, queue)
		case "reject":
			handleReject(w, body, &req, queue)
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported action: " + req.Action})
		}
	})

	fmt.Fprintf(os.Stderr, "[relay-broker] max-ttl=%s\n", maxTTL)
	fmt.Fprintf(os.Stderr, "[relay-broker] Listening on %s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// handleUnwrap queues a plugin's unwrap request and returns 202.
func handleUnwrap(w http.ResponseWriter, body []byte, req *relay.RelayRequest, q *broker.Queue) {
	if req.IntentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing intent_id"})
		return
	}
	if req.IntentClaimPub == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing intent_claim_pub"})
		return
	}

	tag := req.Tag

	if err := q.Submit(req.IntentID, tag, body, req.IntentClaimPub); err != nil {
		switch err.Error() {
		case "duplicate_intent":
			writeJSON(w, http.StatusConflict, map[string]string{"error": "duplicate_intent"})
		case "missing_intent_claim_pub":
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing intent_claim_pub"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}

	fmt.Fprintf(os.Stderr, "[relay-broker] Queued intent %s (tag=%s)\n", req.IntentID, tag)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(broker.AsyncAccepted{})
}

// handlePoll returns the current state of an intent to the plugin.
// Requires intent_claim_sig for authentication.
func handlePoll(w http.ResponseWriter, req *relay.RelayRequest, q *broker.Queue) {
	if req.IntentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing intent_id"})
		return
	}
	if req.IntentClaimSig == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing intent_claim_sig"})
		return
	}

	resp, err := q.PollWithClaim(req.IntentID, req.IntentClaimSig, req.Version)
	if err != nil {
		errMsg := err.Error()
		switch errMsg {
		case "unknown_intent":
			writeJSON(w, http.StatusNotFound, map[string]string{"error": errMsg})
		case "invalid_claim_sig":
			writeJSON(w, http.StatusForbidden, map[string]string{"error": errMsg})
		default:
			writeJSON(w, http.StatusForbidden, map[string]string{"error": errMsg})
		}
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// handlePull returns all pending intents for a tag to the operator.
func handlePull(w http.ResponseWriter, req *relay.RelayRequest, q *broker.Queue) {
	if req.Tag == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing tag"})
		return
	}

	resp := q.Pull(req.Tag)
	writeJSON(w, http.StatusOK, resp)
}

// handleFulfill marks an intent as fulfilled with the operator's response body.
func handleFulfill(w http.ResponseWriter, body []byte, req *relay.RelayRequest, q *broker.Queue) {
	if req.IntentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing intent_id"})
		return
	}
	if req.EncryptedPayload == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing encrypted_payload"})
		return
	}
	if req.IntentClaimSig == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing intent_claim_sig"})
		return
	}

	if err := q.Fulfill(req.IntentID, body, req.IntentClaimSig, req.Version, req.Action, req.EncryptedPayload); err != nil {
		switch err.Error() {
		case "unknown_intent":
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_intent"})
		case "intent_already_terminal":
			writeJSON(w, http.StatusConflict, map[string]string{"error": "intent_already_terminal"})
		case "invalid_claim_sig":
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid_claim_sig"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}

	fmt.Fprintf(os.Stderr, "[relay-broker] Fulfilled intent %s\n", req.IntentID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReject marks an intent as rejected.
func handleReject(w http.ResponseWriter, body []byte, req *relay.RelayRequest, q *broker.Queue) {
	if req.IntentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing intent_id"})
		return
	}
	if req.IntentClaimSig == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing intent_claim_sig"})
		return
	}

	encryptedPayload := req.EncryptedPayload // may be empty for reject, but canonical still hashes it

	if err := q.Reject(req.IntentID, body, req.IntentClaimSig, req.Version, req.Action, encryptedPayload); err != nil {
		switch err.Error() {
		case "unknown_intent":
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_intent"})
		case "intent_already_terminal":
			writeJSON(w, http.StatusConflict, map[string]string{"error": "intent_already_terminal"})
		case "invalid_claim_sig":
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid_claim_sig"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}

	fmt.Fprintf(os.Stderr, "[relay-broker] Rejected intent %s\n", req.IntentID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
