package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
)

// ── GenerateIntentID ────────────────────────────────────────────────────────

func TestGenerateIntentIDFormat(t *testing.T) {
	id, err := GenerateIntentID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 32 {
		t.Fatalf("expected 32 hex chars, got %d: %q", len(id), id)
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("non-hex char in intent ID: %c", c)
		}
	}
}

func TestGenerateIntentIDUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := GenerateIntentID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("duplicate intent ID: %s", id)
		}
		seen[id] = true
	}
}

// ── sanitizeErrorMsg ────────────────────────────────────────────────────────

func TestSanitizeErrorMsgShort(t *testing.T) {
	if got := sanitizeErrorMsg("hello"); got != "hello" {
		t.Fatalf("expected 'hello', got %q", got)
	}
}

func TestSanitizeErrorMsgTruncation(t *testing.T) {
	long := strings.Repeat("x", 300)
	got := sanitizeErrorMsg(long)
	if len(got) != 256+3 {
		t.Fatalf("expected length 259, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatal("expected '...' suffix")
	}
}

func TestSanitizeErrorMsgControlChars(t *testing.T) {
	got := sanitizeErrorMsg("hello\x00world\x01foo\tbar\nqux\x1f")
	if strings.ContainsAny(got, "\x00\x01\x1f") {
		t.Fatalf("control chars not stripped: %q", got)
	}
	if !strings.Contains(got, "\t") || !strings.Contains(got, "\n") {
		t.Fatal("tabs/newlines should be preserved")
	}
}

func TestSanitizeErrorMsgEmpty(t *testing.T) {
	if got := sanitizeErrorMsg(""); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

// ── extractFileKey ──────────────────────────────────────────────────────────

func TestExtractFileKeyEmpty(t *testing.T) {
	ek, _ := GenerateEphemeral()
	_, err := extractFileKey(RelayResponse{}, ek, "unwrap", "some-intent")
	if err == nil {
		t.Fatal("expected error for empty response")
	}
}

func TestExtractFileKeyBadBase64(t *testing.T) {
	ek, _ := GenerateEphemeral()
	resp := RelayResponse{EncryptedPayload: "not-valid-base64!!!"}
	_, err := extractFileKey(resp, ek, "unwrap", "intent123")
	if err == nil {
		t.Fatal("expected error for bad base64")
	}
}

func TestExtractFileKeyWrongKey(t *testing.T) {
	intentID := "test-intent"
	fileKey := make([]byte, 16)
	rand.Read(fileKey)

	respInner, _ := BuildResponsePayload("unwrap", intentID, fileKey)
	ek1, _ := GenerateEphemeral()
	sealed, _ := SealResponse(*respInner, ek1.RecipientString())

	ek2, _ := GenerateEphemeral()
	resp := RelayResponse{EncryptedPayload: sealed}
	_, err := extractFileKey(resp, ek2, "unwrap", intentID)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestExtractFileKeyWrongIntentID(t *testing.T) {
	fileKey := make([]byte, 16)
	rand.Read(fileKey)

	respInner, _ := BuildResponsePayload("unwrap", "intent-A", fileKey)
	ek, _ := GenerateEphemeral()
	sealed, _ := SealResponse(*respInner, ek.RecipientString())

	resp := RelayResponse{EncryptedPayload: sealed}
	_, err := extractFileKey(resp, ek, "unwrap", "intent-B")
	if err == nil {
		t.Fatal("expected error for wrong intent_id (outer_hash mismatch)")
	}
	if !strings.Contains(err.Error(), "outer_hash") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestFileKeyRecoveryVariousSizes(t *testing.T) {
	for _, size := range []int{0, 1, 15, 16, 32, 64} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			fileKey := make([]byte, size)
			rand.Read(fileKey)
			intentID := "test-intent"

			respInner, _ := BuildResponsePayload("unwrap", intentID, fileKey)
			ek, _ := GenerateEphemeral()
			sealed, _ := SealResponse(*respInner, ek.RecipientString())

			resp := RelayResponse{EncryptedPayload: sealed}
			recovered, err := extractFileKey(resp, ek, "unwrap", intentID)
			if err != nil {
				t.Fatalf("size %d: %v", size, err)
			}
			if !bytes.Equal(recovered, fileKey) {
				t.Fatalf("size %d: mismatch", size)
			}
		})
	}
}

// ── PostToRelay: HTTP error handling ────────────────────────────────────────

func TestPostToRelay5xxError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(RelayResponse{Error: "internal server error"})
	}))
	defer server.Close()

	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()
	relayRecipient, _ := NewRelayRecipient([]byte(recipientStr))
	fileKey := make([]byte, 16)
	rand.Read(fileKey)
	stanzas, _ := relayRecipient.Wrap(fileKey)

	var innerStanzas []*age.Stanza
	tag := ComputeTag(recipientStr)
	for _, s := range stanzas {
		if s.Type == "relay" && len(s.Args) >= 2 {
			tagBytes, _ := base64.RawStdEncoding.DecodeString(s.Args[0])
			if bytes.Equal(tagBytes, tag[:]) {
				innerStanzas = append(innerStanzas, &age.Stanza{
					Type: s.Args[1], Args: s.Args[2:], Body: s.Body,
				})
			}
		}
	}

	remote := RemoteConfig{URL: server.URL, UnwrapRecipient: recipientStr, Timeout: "5s"}
	_, err := PostToRelay(remote, innerStanzas, recipientStr)
	if err == nil {
		t.Fatal("expected error for 5xx")
	}
	t.Logf("Got expected error: %v", err)
}

func TestPostToRelayServerReturnsErrorInJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(RelayResponse{Error: "decrypt failed"})
	}))
	defer server.Close()

	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	stanza := &age.Stanza{Type: "X25519", Args: []string{"arg1"}, Body: []byte("body")}
	remote := RemoteConfig{URL: server.URL, UnwrapRecipient: recipientStr, Timeout: "5s"}
	_, err := PostToRelay(remote, []*age.Stanza{stanza}, recipientStr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "decrypt failed") {
		t.Fatalf("error should contain server message, got: %v", err)
	}
}

// ── PostToRelay: SSE edge cases ─────────────────────────────────────────────

func TestSSEHeartbeatOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, ": heartbeat\n\n")
		fmt.Fprintf(w, ": heartbeat\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer server.Close()

	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	stanza := &age.Stanza{Type: "X25519", Args: []string{"arg1"}, Body: []byte("body")}
	remote := RemoteConfig{URL: server.URL, Stream: true, UnwrapRecipient: recipientStr, Timeout: "5s"}
	_, err := PostToRelay(remote, []*age.Stanza{stanza}, recipientStr)
	if err == nil {
		t.Fatal("expected error for heartbeat-only stream")
	}
	t.Logf("Got expected error: %v", err)
}

func TestSSEErrorEvent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		errResp, _ := json.Marshal(RelayResponse{Error: "identity not found"})
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", errResp)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer server.Close()

	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	stanza := &age.Stanza{Type: "X25519", Args: []string{"arg1"}, Body: []byte("body")}
	remote := RemoteConfig{URL: server.URL, Stream: true, UnwrapRecipient: recipientStr, Timeout: "5s"}
	_, err := PostToRelay(remote, []*age.Stanza{stanza}, recipientStr)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "identity not found") {
		t.Fatalf("wrong error: %v", err)
	}
}

// ── PostToRelay: Auth token ─────────────────────────────────────────────────

func TestAuthTokenSentAsBearer(t *testing.T) {
	var gotAuth string
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(RelayResponse{Error: "test"})
	}))
	defer server.Close()

	stanza := &age.Stanza{Type: "X25519", Args: []string{"a"}, Body: []byte("b")}
	remote := RemoteConfig{URL: server.URL, AuthToken: "my-secret-token", UnwrapRecipient: recipientStr, Timeout: "5s"}
	PostToRelay(remote, []*age.Stanza{stanza}, recipientStr)

	if gotAuth != "Bearer my-secret-token" {
		t.Fatalf("expected 'Bearer my-secret-token', got %q", gotAuth)
	}
}

func TestNoAuthTokenOmitsHeader(t *testing.T) {
	var gotAuth string
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(RelayResponse{Error: "test"})
	}))
	defer server.Close()

	stanza := &age.Stanza{Type: "X25519", Args: []string{"a"}, Body: []byte("b")}
	remote := RemoteConfig{URL: server.URL, UnwrapRecipient: recipientStr, Timeout: "5s"}
	PostToRelay(remote, []*age.Stanza{stanza}, recipientStr)

	if gotAuth != "" {
		t.Fatalf("expected no Authorization header, got %q", gotAuth)
	}
}

// ── PostToRelay: Wire format ────────────────────────────────────────────────

func TestWireFormatRequestFields(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	var capturedReq RelayRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&capturedReq)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(RelayResponse{Error: "test"})
	}))
	defer server.Close()

	stanza := &age.Stanza{Type: "X25519", Args: []string{"a"}, Body: []byte("b")}
	remote := RemoteConfig{URL: server.URL, UnwrapRecipient: recipientStr, Timeout: "5s"}
	PostToRelay(remote, []*age.Stanza{stanza}, recipientStr)

	if capturedReq.Version != 1 {
		t.Fatalf("expected version 1, got %d", capturedReq.Version)
	}
	if capturedReq.Action != "unwrap" {
		t.Fatalf("expected action 'unwrap', got %q", capturedReq.Action)
	}
	if len(capturedReq.IntentID) != 32 {
		t.Fatalf("intent_id should be 32 hex chars, got %d", len(capturedReq.IntentID))
	}
	if capturedReq.Tag == "" {
		t.Fatal("tag should not be empty")
	}
	if capturedReq.ExpiresAt == 0 {
		t.Fatal("expires_at should not be zero")
	}
	if capturedReq.EncryptedPayload == "" {
		t.Fatal("encrypted_payload should not be empty")
	}
	// No cleartext stanzas in outer request
	reqJSON, _ := json.Marshal(capturedReq)
	if strings.Contains(string(reqJSON), `"stanzas"`) {
		t.Fatal("outer request should not contain stanzas field")
	}
}

// ── PostToRelay: Async E2E ──────────────────────────────────────────────────

func TestEncryptedPayloadAsyncE2E(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	var mu sync.Mutex
	var storedReq *RelayRequest
	var fulfillPayload string
	fulfilled := false

	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req RelayRequest
		json.NewDecoder(r.Body).Decode(&req)

		mu.Lock()
		defer mu.Unlock()

		switch req.Action {
		case "unwrap":
			storedReq = &req
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{})

		case "poll":
			if fulfilled && req.IntentID == storedReq.IntentID {
				// Return the full operator fulfill body as verbatim "response".
				fulfillBody := RelayRequest{
					Version:          1,
					Action:           "fulfill",
					IntentID:         storedReq.IntentID,
					EncryptedPayload: fulfillPayload,
				}
				json.NewEncoder(w).Encode(map[string]interface{}{
					"status":   "fulfilled",
					"response": fulfillBody,
				})
			} else if storedReq != nil && req.IntentID == storedReq.IntentID {
				json.NewEncoder(w).Encode(map[string]interface{}{"status": "pending"})
			} else {
				w.WriteHeader(404)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "unknown_intent"})
			}
		}
	}))
	defer broker.Close()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientStr))
	fileKey := make([]byte, 16)
	rand.Read(fileKey)
	stanzas, _ := relayRecipient.Wrap(fileKey)

	tag := ComputeTag(recipientStr)
	var innerStanzas []*age.Stanza
	for _, s := range stanzas {
		if s.Type == "relay" && len(s.Args) >= 2 {
			tagBytes, _ := base64.RawStdEncoding.DecodeString(s.Args[0])
			if bytes.Equal(tagBytes, tag[:]) {
				innerStanzas = append(innerStanzas, &age.Stanza{
					Type: s.Args[1], Args: s.Args[2:], Body: s.Body,
				})
			}
		}
	}

	remote := RemoteConfig{
		URL:             broker.URL,
		UnwrapRecipient: recipientStr,
		Timeout:         "10s",
		PollInterval:    "200ms",
	}

	type result struct {
		key []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		k, e := PostToRelay(remote, innerStanzas, recipientStr)
		ch <- result{k, e}
	}()

	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	if storedReq == nil {
		mu.Unlock()
		t.Fatal("broker never received intent")
	}
	reqCopy := *storedReq
	mu.Unlock()

	// Operator: decrypt, verify, unwrap, seal, fulfill
	inner, err := DecryptPayload(reqCopy.EncryptedPayload, []age.Identity{identity})
	if err != nil {
		t.Fatalf("operator decrypt: %v", err)
	}
	if err := VerifyRequestPayload(inner, reqCopy.Version, reqCopy.Action, reqCopy.IntentID, reqCopy.Tag, reqCopy.ExpiresAt); err != nil {
		t.Fatalf("operator verify: %v", err)
	}

	opStanzas := make([]*age.Stanza, len(inner.Stanzas))
	for i, s := range inner.Stanzas {
		body, _ := base64.RawStdEncoding.DecodeString(s.Body)
		opStanzas[i] = &age.Stanza{Type: s.Type, Args: s.Args, Body: body}
	}
	unwrappedKey, _ := identity.Unwrap(opStanzas)

	respInner, _ := BuildResponsePayload("fulfill", reqCopy.IntentID, unwrappedKey)
	sealed, _ := SealResponse(*respInner, inner.EphemeralKey)

	mu.Lock()
	fulfillPayload = sealed
	fulfilled = true
	mu.Unlock()

	res := <-ch
	if res.err != nil {
		t.Fatalf("PostToRelay: %v", res.err)
	}
	if !bytes.Equal(res.key, fileKey) {
		t.Fatalf("file key mismatch: got %x, want %x", res.key, fileKey)
	}
}
