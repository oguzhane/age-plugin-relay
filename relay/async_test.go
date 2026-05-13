package relay_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/oguzhane/age-plugin-relay/relay"
	"github.com/oguzhane/age-plugin-relay/relay/broker"
)

// mockBroker simulates a relay-broker for testing. It routes actions to an
// in-memory queue and stores opaque encrypted payloads.
type mockBroker struct {
	queue     *broker.Queue
	authToken string
}

func newMockBroker(maxTTL time.Duration) *mockBroker {
	return &mockBroker{
		queue:     broker.NewQueue(maxTTL, maxTTL/2),
		authToken: "test-token",
	}
}

func (b *mockBroker) stop() { b.queue.Stop() }

func (b *mockBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	var req relay.RelayRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeAsyncTestJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}

	switch req.Action {
	case "unwrap":
		if err := b.queue.Submit(req.IntentID, req.Tag, body); err != nil {
			if err.Error() == "duplicate_intent" {
				writeAsyncTestJSON(w, http.StatusConflict, map[string]string{"error": "duplicate_intent"})
				return
			}
			writeAsyncTestJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(broker.AsyncAccepted{})

	case "poll":
		resp := b.queue.Poll(req.IntentID)
		if resp == nil {
			writeAsyncTestJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_intent"})
			return
		}
		writeAsyncTestJSON(w, http.StatusOK, resp)

	case "pull":
		resp := b.queue.Pull(req.Tag)
		writeAsyncTestJSON(w, http.StatusOK, resp)

	case "fulfill":
		if err := b.queue.Fulfill(req.IntentID, body); err != nil {
			if err.Error() == "unknown_intent" {
				writeAsyncTestJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_intent"})
			} else {
				writeAsyncTestJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			}
			return
		}
		writeAsyncTestJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	case "reject":
		if err := b.queue.Reject(req.IntentID, body); err != nil {
			if err.Error() == "unknown_intent" {
				writeAsyncTestJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_intent"})
			} else {
				writeAsyncTestJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			}
			return
		}
		writeAsyncTestJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	default:
		writeAsyncTestJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action"})
	}
}

func writeAsyncTestJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// TestAsyncEndToEnd tests the full async flow:
// plugin submits encrypted unwrap → broker queues → operator pulls, decrypts,
// verifies, unwraps, seals response → broker stores → plugin polls → plugin decrypts.
func TestAsyncEndToEnd(t *testing.T) {
	operatorIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipientStr := operatorIdentity.Recipient().String()

	mb := newMockBroker(2 * time.Minute)
	defer mb.stop()
	brokerServer := httptest.NewServer(mb)
	defer brokerServer.Close()

	tagBytes := relay.ComputeTag(recipientStr)
	tag := base64.RawStdEncoding.EncodeToString(tagBytes[:4])

	fileKey := make([]byte, 16)
	copy(fileKey, "test-file-key!!!")
	stanzas, err := operatorIdentity.Recipient().Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	// Build relay stanzas for the inner payload.
	relayStanzas := make([]relay.RelayStanza, len(stanzas))
	for i, s := range stanzas {
		relayStanzas[i] = relay.RelayStanza{
			Type: s.Type,
			Args: s.Args,
			Body: base64.RawStdEncoding.EncodeToString(s.Body),
		}
	}

	intentID, err := relay.GenerateIntentID()
	if err != nil {
		t.Fatal(err)
	}

	ephemeral, err := relay.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer ephemeral.Clear()
	ephemeralRecipient := ephemeral.RecipientString()

	expiresAt := time.Now().Add(5 * time.Minute).Unix()

	// Build and encrypt inner payload.
	innerReq, err := relay.BuildRequestPayload(1, "unwrap", false, intentID, tag, expiresAt, relayStanzas, ephemeralRecipient)
	if err != nil {
		t.Fatal(err)
	}
	encryptedPayload, err := relay.EncryptPayload(*innerReq, recipientStr)
	if err != nil {
		t.Fatal(err)
	}

	// Submit to broker.
	relayReq := relay.RelayRequest{
		Version:          1,
		Action:           "unwrap",
		IntentID:         intentID,
		Tag:              tag,
		ExpiresAt:        expiresAt,
		EncryptedPayload: encryptedPayload,
	}
	reqBody, _ := json.Marshal(relayReq)

	httpReq, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", resp.StatusCode)
	}
	t.Logf("Plugin submitted intent %s -> 202 Accepted", intentID)

	// Operator pulls.
	pullReq := relay.RelayRequest{Version: 1, Action: "pull", Tag: tag}
	pullBody, _ := json.Marshal(pullReq)
	pullHTTP, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(pullBody))
	pullHTTP.Header.Set("Content-Type", "application/json")
	pullResp, _ := http.DefaultClient.Do(pullHTTP)
	pullRespBody, _ := io.ReadAll(pullResp.Body)
	pullResp.Body.Close()

	var pullResult broker.PullResponse
	json.Unmarshal(pullRespBody, &pullResult)
	if len(pullResult.Intents) != 1 {
		t.Fatalf("expected 1 pending intent, got %d", len(pullResult.Intents))
	}
	intent := pullResult.Intents[0]
	t.Logf("Operator pulled intent %s", intent.IntentID)

	// Operator unmarshals the verbatim request.
	var intentReq relay.RelayRequest
	if err := json.Unmarshal(intent.Request, &intentReq); err != nil {
		t.Fatalf("Operator unmarshal request: %v", err)
	}

	// Operator decrypts the encrypted payload.
	inner, err := relay.DecryptPayload(intentReq.EncryptedPayload, []age.Identity{operatorIdentity})
	if err != nil {
		t.Fatalf("Operator decrypt failed: %v", err)
	}
	t.Log("Operator decrypted inner payload")

	// Operator verifies outer hash.
	if err := relay.VerifyRequestPayload(inner, intentReq.Version, intentReq.Action, intentReq.Stream, intentReq.IntentID, intentReq.Tag, intentReq.ExpiresAt); err != nil {
		t.Fatalf("Operator verification failed: %v", err)
	}
	t.Log("Operator verified outer hash")

	// Operator unwraps stanzas.
	ageStanzas := make([]*age.Stanza, len(inner.Stanzas))
	for i, s := range inner.Stanzas {
		body, _ := base64.RawStdEncoding.DecodeString(s.Body)
		ageStanzas[i] = &age.Stanza{Type: s.Type, Args: s.Args, Body: body}
	}
	recoveredFileKey, err := operatorIdentity.Unwrap(ageStanzas)
	if err != nil {
		t.Fatalf("Operator unwrap failed: %v", err)
	}
	t.Log("Operator unwrapped file key")

	// Operator seals response to plugin's ephemeral recipient.
	respInner, _ := relay.BuildResponsePayload(1, "fulfill", intentID, recoveredFileKey)
	sealed, err := relay.SealResponse(*respInner, inner.EphemeralKey)
	if err != nil {
		t.Fatalf("Operator seal failed: %v", err)
	}
	t.Log("Operator sealed response")

	// Operator fulfills.
	fulfillReq := relay.RelayRequest{Version: 1, Action: "fulfill", IntentID: intentID, EncryptedPayload: sealed}
	fulfillBody, _ := json.Marshal(fulfillReq)
	fulfillHTTP, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(fulfillBody))
	fulfillHTTP.Header.Set("Content-Type", "application/json")
	fulfillResp, _ := http.DefaultClient.Do(fulfillHTTP)
	fulfillResp.Body.Close()
	if fulfillResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on fulfill, got %d", fulfillResp.StatusCode)
	}
	t.Log("Operator fulfilled")

	// Plugin polls.
	pollReq := relay.RelayRequest{Version: 1, Action: "poll", IntentID: intentID}
	pollBody, _ := json.Marshal(pollReq)
	pollHTTP, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(pollBody))
	pollHTTP.Header.Set("Content-Type", "application/json")
	pollResp, _ := http.DefaultClient.Do(pollHTTP)
	pollRespBody, _ := io.ReadAll(pollResp.Body)
	pollResp.Body.Close()

	var pollResult broker.PollResponse
	json.Unmarshal(pollRespBody, &pollResult)
	if pollResult.Status != "fulfilled" {
		t.Fatalf("expected fulfilled, got %s", pollResult.Status)
	}
	t.Log("Plugin polled -> fulfilled")

	// Plugin decrypts the response — unmarshal the verbatim operator body.
	var operatorBody relay.RelayRequest
	if err := json.Unmarshal(pollResult.Response, &operatorBody); err != nil {
		t.Fatalf("Plugin unmarshal poll response: %v", err)
	}
	respPayload, err := relay.OpenResponse(operatorBody.EncryptedPayload, ephemeral.Identity)
	if err != nil {
		t.Fatalf("Plugin decrypt failed: %v", err)
	}
	if err := relay.VerifyResponsePayload(respPayload, 1, "fulfill", intentID); err != nil {
		t.Fatalf("Plugin response verification failed: %v", err)
	}
	decryptedFileKey, err := base64.RawStdEncoding.DecodeString(respPayload.FileKey)
	if err != nil {
		t.Fatalf("decoding file key: %v", err)
	}
	if !bytes.Equal(decryptedFileKey, fileKey) {
		t.Fatalf("file key mismatch:\n  got:  %x\n  want: %x", decryptedFileKey, fileKey)
	}
	t.Log("Plugin decrypted file key — matches original")
}

// TestAsyncRejectionFlow tests that operator rejection propagates to plugin.
func TestAsyncRejectionFlow(t *testing.T) {
	mb := newMockBroker(2 * time.Minute)
	defer mb.stop()
	brokerServer := httptest.NewServer(mb)
	defer brokerServer.Close()

	intentID := "reject-test-001"

	// Submit an intent with encrypted payload.
	req := relay.RelayRequest{
		Version:          1,
		Action:           "unwrap",
		IntentID:         intentID,
		Tag:              "test-tag",
		EncryptedPayload: "opaque-encrypted-data",
	}
	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(httpReq)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", resp.StatusCode)
	}

	// Operator rejects.
	rejectReq := relay.RelayRequest{Version: 1, Action: "reject", IntentID: intentID, EncryptedPayload: "opaque-reject"}
	rejectBody, _ := json.Marshal(rejectReq)
	rejectHTTP, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(rejectBody))
	rejectHTTP.Header.Set("Content-Type", "application/json")
	rejectResp, _ := http.DefaultClient.Do(rejectHTTP)
	rejectResp.Body.Close()
	if rejectResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on reject, got %d", rejectResp.StatusCode)
	}

	// Plugin polls and sees rejected.
	pollReq := relay.RelayRequest{Version: 1, Action: "poll", IntentID: intentID}
	pollBody, _ := json.Marshal(pollReq)
	pollHTTP, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(pollBody))
	pollHTTP.Header.Set("Content-Type", "application/json")
	pollResp, _ := http.DefaultClient.Do(pollHTTP)
	pollRespBody, _ := io.ReadAll(pollResp.Body)
	pollResp.Body.Close()

	var result broker.PollResponse
	json.Unmarshal(pollRespBody, &result)
	if result.Status != "rejected" {
		t.Fatalf("expected rejected, got %s", result.Status)
	}
}

// TestAsyncDuplicateIntentReturns409 tests that submitting the same intent_id twice
// returns 409 Conflict.
func TestAsyncDuplicateIntentReturns409(t *testing.T) {
	mb := newMockBroker(2 * time.Minute)
	defer mb.stop()
	brokerServer := httptest.NewServer(mb)
	defer brokerServer.Close()

	req := relay.RelayRequest{
		Version:          1,
		Action:           "unwrap",
		IntentID:         "dup-409",
		Tag:              "tag",
		EncryptedPayload: "opaque",
	}
	body, _ := json.Marshal(req)

	// First submission.
	r1, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(body))
	r1.Header.Set("Content-Type", "application/json")
	resp1, _ := http.DefaultClient.Do(r1)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusAccepted {
		t.Fatalf("first submit: expected 202, got %d", resp1.StatusCode)
	}

	// Second submission — same intent_id.
	r2, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(body))
	r2.Header.Set("Content-Type", "application/json")
	resp2, _ := http.DefaultClient.Do(r2)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("second submit: expected 409, got %d", resp2.StatusCode)
	}
}

// TestAsyncPollUnknownReturns404 tests that polling a nonexistent intent_id returns 404.
func TestAsyncPollUnknownReturns404(t *testing.T) {
	mb := newMockBroker(2 * time.Minute)
	defer mb.stop()
	brokerServer := httptest.NewServer(mb)
	defer brokerServer.Close()

	req := relay.RelayRequest{Version: 1, Action: "poll", IntentID: "nonexistent"}
	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(httpReq)
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// TestAsyncFulfillAfterRejectReturns409 tests that fulfilling an already-rejected
// intent returns 409 Conflict.
func TestAsyncFulfillAfterRejectReturns409(t *testing.T) {
	mb := newMockBroker(2 * time.Minute)
	defer mb.stop()
	brokerServer := httptest.NewServer(mb)
	defer brokerServer.Close()

	// Submit.
	submit := relay.RelayRequest{Version: 1, Action: "unwrap", IntentID: "terminal-test", Tag: "t", EncryptedPayload: "opaque"}
	sb, _ := json.Marshal(submit)
	sr, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(sb))
	sr.Header.Set("Content-Type", "application/json")
	sResp, _ := http.DefaultClient.Do(sr)
	sResp.Body.Close()

	// Reject.
	reject := relay.RelayRequest{Version: 1, Action: "reject", IntentID: "terminal-test", EncryptedPayload: "opaque-reject"}
	rb, _ := json.Marshal(reject)
	rr, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(rb))
	rr.Header.Set("Content-Type", "application/json")
	rResp, _ := http.DefaultClient.Do(rr)
	rResp.Body.Close()

	// Try to fulfill — should fail.
	fulfill := relay.RelayRequest{Version: 1, Action: "fulfill", IntentID: "terminal-test", EncryptedPayload: "data"}
	fb, _ := json.Marshal(fulfill)
	fr, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(fb))
	fr.Header.Set("Content-Type", "application/json")
	fResp, _ := http.DefaultClient.Do(fr)
	fResp.Body.Close()

	if fResp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 on fulfill after reject, got %d", fResp.StatusCode)
	}
}

// TestAsyncPollAfterExpiry tests that polling after TTL returns 404.
func TestAsyncPollAfterExpiry(t *testing.T) {
	mb := newMockBroker(50 * time.Millisecond)
	defer mb.stop()
	brokerServer := httptest.NewServer(mb)
	defer brokerServer.Close()

	req := relay.RelayRequest{Version: 1, Action: "unwrap", IntentID: "expire-test", Tag: "t", EncryptedPayload: "opaque"}
	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(httpReq)
	resp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	poll := relay.RelayRequest{Version: 1, Action: "poll", IntentID: "expire-test"}
	pb, _ := json.Marshal(poll)
	pr, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(pb))
	pr.Header.Set("Content-Type", "application/json")
	pResp, _ := http.DefaultClient.Do(pr)
	pResp.Body.Close()

	if pResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after expiry, got %d", pResp.StatusCode)
	}
}

// TestAsyncPluginPollingLoop tests the full PostToRelay async branch:
// broker returns 202 → plugin polls automatically → operator fulfills → plugin gets file key.
func TestAsyncPluginPollingLoop(t *testing.T) {
	operatorIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipientStr := operatorIdentity.Recipient().String()

	mb := newMockBroker(2 * time.Minute)
	defer mb.stop()
	brokerServer := httptest.NewServer(mb)
	defer brokerServer.Close()

	remote := relay.RemoteConfig{
		URL:             brokerServer.URL,
		UnwrapRecipient: recipientStr,
		Timeout:         "10s",
		PollInterval:    "50ms",
	}

	// Wrap a file key using the operator's recipient.
	fileKey := make([]byte, 16)
	copy(fileKey, "polling-test-key")
	innerStanzas, err := operatorIdentity.Recipient().Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	// Start plugin's PostToRelay in background — it'll submit then poll.
	var pluginFileKey []byte
	var pluginErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		pluginFileKey, pluginErr = relay.PostToRelay(remote, innerStanzas, recipientStr)
	}()

	// Give the plugin time to submit.
	time.Sleep(200 * time.Millisecond)

	// Pull all pending intents using the same tag computation as PostToRelay.
	tagBytes := relay.ComputeTag(recipientStr)
	tagStr := base64.RawStdEncoding.EncodeToString(tagBytes[:4])
	pullReq := relay.RelayRequest{Version: 1, Action: "pull", Tag: tagStr}
	pullBody, _ := json.Marshal(pullReq)
	pullHTTP, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(pullBody))
	pullHTTP.Header.Set("Content-Type", "application/json")
	pullResp, _ := http.DefaultClient.Do(pullHTTP)
	pullRespBody, _ := io.ReadAll(pullResp.Body)
	pullResp.Body.Close()

	var pullResult broker.PullResponse
	json.Unmarshal(pullRespBody, &pullResult)

	if len(pullResult.Intents) == 0 {
		t.Fatal("no pending intents found for operator")
	}

	intent := pullResult.Intents[0]
	t.Logf("Operator found intent %s", intent.IntentID)

	// Operator unmarshals the verbatim request.
	var intentReq relay.RelayRequest
	if err := json.Unmarshal(intent.Request, &intentReq); err != nil {
		t.Fatalf("operator unmarshal: %v", err)
	}

	// Operator decrypts the encrypted payload.
	inner, err := relay.DecryptPayload(intentReq.EncryptedPayload, []age.Identity{operatorIdentity})
	if err != nil {
		t.Fatalf("operator decrypt: %v", err)
	}

	// Operator verifies.
	if err := relay.VerifyRequestPayload(inner, intentReq.Version, intentReq.Action, intentReq.Stream, intentReq.IntentID, intentReq.Tag, intentReq.ExpiresAt); err != nil {
		t.Fatalf("operator verify: %v", err)
	}

	// Operator unwraps.
	ageStanzas := make([]*age.Stanza, len(inner.Stanzas))
	for i, s := range inner.Stanzas {
		b, _ := base64.RawStdEncoding.DecodeString(s.Body)
		ageStanzas[i] = &age.Stanza{Type: s.Type, Args: s.Args, Body: b}
	}
	opFileKey, err := operatorIdentity.Unwrap(ageStanzas)
	if err != nil {
		t.Fatalf("operator unwrap: %v", err)
	}

	// Operator seals response to plugin's ephemeral recipient.
	respInner, _ := relay.BuildResponsePayload(1, "fulfill", intent.IntentID, opFileKey)
	sealed, err := relay.SealResponse(*respInner, inner.EphemeralKey)
	if err != nil {
		t.Fatal(err)
	}

	// Operator fulfills.
	fulfillReq := relay.RelayRequest{Version: 1, Action: "fulfill", IntentID: intent.IntentID, EncryptedPayload: sealed}
	fb, _ := json.Marshal(fulfillReq)
	fh, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(fb))
	fh.Header.Set("Content-Type", "application/json")
	fResp, _ := http.DefaultClient.Do(fh)
	fResp.Body.Close()

	// Wait for plugin to finish polling.
	wg.Wait()

	if pluginErr != nil {
		t.Fatalf("plugin PostToRelay error: %v", pluginErr)
	}

	if !bytes.Equal(pluginFileKey, fileKey) {
		t.Fatalf("file key mismatch:\n  got:  %x\n  want: %x", pluginFileKey, fileKey)
	}
	t.Logf("Plugin recovered correct file key via async polling")
}

// TestAsyncPluginPollingLoopRejected tests that PostToRelay returns an error
// when the operator rejects.
func TestAsyncPluginPollingLoopRejected(t *testing.T) {
	operatorIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipientStr := operatorIdentity.Recipient().String()

	mb := newMockBroker(2 * time.Minute)
	defer mb.stop()
	brokerServer := httptest.NewServer(mb)
	defer brokerServer.Close()

	remote := relay.RemoteConfig{
		URL:             brokerServer.URL,
		UnwrapRecipient: recipientStr,
		Timeout:         "5s",
		PollInterval:    "50ms",
	}

	fileKey := make([]byte, 16)
	copy(fileKey, "reject-test-key!")
	innerStanzas, err := operatorIdentity.Recipient().Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	var pluginErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, pluginErr = relay.PostToRelay(remote, innerStanzas, recipientStr)
	}()

	time.Sleep(200 * time.Millisecond)

	// Find the intent by pulling with the computed tag.
	tagBytes := relay.ComputeTag(recipientStr)
	tagStr := base64.RawStdEncoding.EncodeToString(tagBytes[:4])
	pullReq := relay.RelayRequest{Version: 1, Action: "pull", Tag: tagStr}
	pb, _ := json.Marshal(pullReq)
	ph, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(pb))
	ph.Header.Set("Content-Type", "application/json")
	pResp, _ := http.DefaultClient.Do(ph)
	pBody, _ := io.ReadAll(pResp.Body)
	pResp.Body.Close()
	var pr broker.PullResponse
	json.Unmarshal(pBody, &pr)

	if len(pr.Intents) == 0 {
		t.Fatal("no intents")
	}

	// Decrypt the original request to get the ephemeral key.
	var origReq relay.RelayRequest
	json.Unmarshal(pr.Intents[0].Request, &origReq)
	inner, err := relay.DecryptPayload(origReq.EncryptedPayload, []age.Identity{operatorIdentity})
	if err != nil {
		t.Fatalf("decrypting request payload: %v", err)
	}

	// Build authenticated reject with encrypted payload.
	rejectInner, err := relay.BuildResponsePayload(1, "reject", pr.Intents[0].IntentID, nil)
	if err != nil {
		t.Fatalf("building reject payload: %v", err)
	}
	rejectSealed, err := relay.SealResponse(*rejectInner, inner.EphemeralKey)
	if err != nil {
		t.Fatalf("sealing reject payload: %v", err)
	}

	// Reject.
	rejectReq := relay.RelayRequest{Version: 1, Action: "reject", IntentID: pr.Intents[0].IntentID, EncryptedPayload: rejectSealed}
	rb, _ := json.Marshal(rejectReq)
	rh, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(rb))
	rh.Header.Set("Content-Type", "application/json")
	rResp, _ := http.DefaultClient.Do(rh)
	rResp.Body.Close()

	wg.Wait()

	if pluginErr == nil {
		t.Fatal("expected error from PostToRelay on rejection")
	}
	if !bytes.Contains([]byte(pluginErr.Error()), []byte("rejected")) {
		t.Fatalf("expected rejection error, got: %v", pluginErr)
	}
	t.Logf("Plugin correctly received rejection error: %v", pluginErr)
}
// TestAsyncBrokerDoesNotSeeFileKey verifies the broker only stores opaque
// encrypted payloads and never has access to plaintext stanzas or file keys.
func TestAsyncBrokerDoesNotSeeFileKey(t *testing.T) {
	operatorIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipientStr := operatorIdentity.Recipient().String()

	mb := newMockBroker(2 * time.Minute)
	defer mb.stop()
	brokerServer := httptest.NewServer(mb)
	defer brokerServer.Close()

	// Create a file key and wrap it.
	fileKey := make([]byte, 16)
	copy(fileKey, "broker-blind-key")

	innerStanzas, err := operatorIdentity.Recipient().Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	// Build encrypted payload as the plugin would.
	intentID := "blind-test-001"
	tagBytes := relay.ComputeTag(recipientStr)
	tag := base64.RawStdEncoding.EncodeToString(tagBytes[:])
	expiresAt := time.Now().Add(5 * time.Minute).Unix()

	relayStanzas := make([]relay.RelayStanza, len(innerStanzas))
	for i, s := range innerStanzas {
		relayStanzas[i] = relay.RelayStanza{
			Type: s.Type,
			Args: s.Args,
			Body: base64.RawStdEncoding.EncodeToString(s.Body),
		}
	}

	eph, _ := relay.GenerateEphemeral()
	defer eph.Clear()
	ephRecipient := eph.RecipientString()

	innerReq, _ := relay.BuildRequestPayload(1, "unwrap", false, intentID, tag, expiresAt, relayStanzas, ephRecipient)
	encPayload, _ := relay.EncryptPayload(*innerReq, recipientStr)

	// Submit to broker.
	req := relay.RelayRequest{
		Version:          1,
		Action:           "unwrap",
		IntentID:         intentID,
		Tag:              tag,
		ExpiresAt:        expiresAt,
		EncryptedPayload: encPayload,
	}
	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(httpReq)
	resp.Body.Close()

	// Verify broker cannot see plaintext stanzas — the outer request has no Stanzas field,
	// only encrypted_payload. Pull the intent and verify it's opaque.
	pullReq := relay.RelayRequest{Version: 1, Action: "pull", Tag: tag}
	pb, _ := json.Marshal(pullReq)
	ph, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(pb))
	ph.Header.Set("Content-Type", "application/json")
	pResp, _ := http.DefaultClient.Do(ph)
	pBody, _ := io.ReadAll(pResp.Body)
	pResp.Body.Close()

	var pullResult broker.PullResponse
	json.Unmarshal(pBody, &pullResult)
	if len(pullResult.Intents) != 1 {
		t.Fatalf("expected 1 intent, got %d", len(pullResult.Intents))
	}

	// The broker's view of the request should have encrypted_payload but NOT plaintext stanzas.
	var pulledReq relay.RelayRequest
	if err := json.Unmarshal(pullResult.Intents[0].Request, &pulledReq); err != nil {
		t.Fatalf("unmarshal pulled request: %v", err)
	}
	if pulledReq.EncryptedPayload == "" {
		t.Fatal("SECURITY: broker should store encrypted_payload")
	}

	// Operator fulfills with sealed key.
	inner, _ := relay.DecryptPayload(pulledReq.EncryptedPayload, []age.Identity{operatorIdentity})
	ageStanzas := make([]*age.Stanza, len(inner.Stanzas))
	for i, s := range inner.Stanzas {
		b, _ := base64.RawStdEncoding.DecodeString(s.Body)
		ageStanzas[i] = &age.Stanza{Type: s.Type, Args: s.Args, Body: b}
	}
	opFileKey, _ := operatorIdentity.Unwrap(ageStanzas)

	respInner, _ := relay.BuildResponsePayload(1, "fulfill", intentID, opFileKey)
	sealed, _ := relay.SealResponse(*respInner, inner.EphemeralKey)

	fulfillReq := relay.RelayRequest{Version: 1, Action: "fulfill", IntentID: intentID, EncryptedPayload: sealed}
	fb, _ := json.Marshal(fulfillReq)
	fh, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(fb))
	fh.Header.Set("Content-Type", "application/json")
	fResp, _ := http.DefaultClient.Do(fh)
	fResp.Body.Close()

	// Poll to get the stored sealed payload.
	pollReq := relay.RelayRequest{Version: 1, Action: "poll", IntentID: intentID}
	pollBody, _ := json.Marshal(pollReq)
	pollHTTP, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(pollBody))
	pollHTTP.Header.Set("Content-Type", "application/json")
	pollResp, _ := http.DefaultClient.Do(pollHTTP)
	pollRespBody, _ := io.ReadAll(pollResp.Body)
	pollResp.Body.Close()

	var pollResult broker.PollResponse
	json.Unmarshal(pollRespBody, &pollResult)

	// The broker stored the operator's verbatim body — verify it's NOT the plaintext file key.
	fileKeyB64 := base64.RawStdEncoding.EncodeToString(fileKey)
	var pollFulfillReq relay.RelayRequest
	if err := json.Unmarshal(pollResult.Response, &pollFulfillReq); err != nil {
		t.Fatalf("unmarshal poll response: %v", err)
	}
	if pollFulfillReq.EncryptedPayload == fileKeyB64 {
		t.Fatal("SECURITY: broker stored plaintext file key!")
	}

	// But the plugin CAN decrypt it.
	decryptedResp, err := relay.OpenResponse(pollFulfillReq.EncryptedPayload, eph.Identity)
	if err != nil {
		t.Fatalf("plugin decrypt: %v", err)
	}
	decryptedFileKey, _ := base64.RawStdEncoding.DecodeString(decryptedResp.FileKey)
	if !bytes.Equal(decryptedFileKey, fileKey) {
		t.Fatal("decrypted file key doesn't match original")
	}
	t.Log("Broker only stores opaque encrypted payloads; plugin decrypts correctly")
}

// TestAsyncOuterHashTamperDetection verifies that the operator detects tampered
// outer fields via outer_hash mismatch in the encrypted payload.
func TestAsyncOuterHashTamperDetection(t *testing.T) {
	operatorIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipientStr := operatorIdentity.Recipient().String()

	mb := newMockBroker(2 * time.Minute)
	defer mb.stop()
	brokerServer := httptest.NewServer(mb)
	defer brokerServer.Close()

	intentID := "tamper-1"
	tagBytes := relay.ComputeTag(recipientStr)
	tag := base64.RawStdEncoding.EncodeToString(tagBytes[:])
	expiresAt := time.Now().Add(5 * time.Minute).Unix()

	// Build inner payload with correct outer hash.
	eph, _ := relay.GenerateEphemeral()
	defer eph.Clear()
	ephRecipient := eph.RecipientString()

	innerReq, _ := relay.BuildRequestPayload(1, "unwrap", false, intentID, tag, expiresAt, nil, ephRecipient)
	encPayload, _ := relay.EncryptPayload(*innerReq, recipientStr)

	// Submit with correct outer fields.
	req := relay.RelayRequest{
		Version:          1,
		Action:           "unwrap",
		IntentID:         intentID,
		Tag:              tag,
		ExpiresAt:        expiresAt,
		EncryptedPayload: encPayload,
	}
	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(httpReq)
	resp.Body.Close()

	// Pull the intent.
	pullReq := relay.RelayRequest{Version: 1, Action: "pull", Tag: tag}
	pb, _ := json.Marshal(pullReq)
	ph, _ := http.NewRequest("POST", brokerServer.URL, bytes.NewReader(pb))
	ph.Header.Set("Content-Type", "application/json")
	pResp, _ := http.DefaultClient.Do(ph)
	pBody, _ := io.ReadAll(pResp.Body)
	pResp.Body.Close()

	var pr broker.PullResponse
	json.Unmarshal(pBody, &pr)
	if len(pr.Intents) != 1 {
		t.Fatalf("expected 1 intent, got %d", len(pr.Intents))
	}

	intent := pr.Intents[0]

	// Operator unmarshals the verbatim request.
	var intentReq relay.RelayRequest
	if err := json.Unmarshal(intent.Request, &intentReq); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Operator decrypts.
	inner, err := relay.DecryptPayload(intentReq.EncryptedPayload, []age.Identity{operatorIdentity})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	// Verify with correct outer fields — should pass.
	err = relay.VerifyRequestPayload(inner, 1, "unwrap", false, intentID, tag, expiresAt)
	if err != nil {
		t.Fatalf("valid verification should pass: %v", err)
	}
	t.Log("Valid outer hash verified")

	// Verify with tampered intent_id — should fail.
	err = relay.VerifyRequestPayload(inner, 1, "unwrap", false, "tampered-intent", tag, expiresAt)
	if err == nil {
		t.Fatal("SECURITY: tampered intent_id should fail verification")
	}
	t.Log("Tampered intent_id correctly rejected")

	// Verify with tampered tag — should fail.
	err = relay.VerifyRequestPayload(inner, 1, "unwrap", false, intentID, "tampered-tag", expiresAt)
	if err == nil {
		t.Fatal("SECURITY: tampered tag should fail verification")
	}
	t.Log("Tampered tag correctly rejected")

	// Verify with tampered expires_at — should fail.
	err = relay.VerifyRequestPayload(inner, 1, "unwrap", false, intentID, tag, expiresAt+1000)
	if err == nil {
		t.Fatal("SECURITY: tampered expires_at should fail verification")
	}
	t.Log("Tampered expires_at correctly rejected")
}
