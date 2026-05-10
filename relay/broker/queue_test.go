package broker

import (
	"testing"
	"time"
)

func TestSubmitAndPoll(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	headers := PluginHeaders{
		Timestamp:    "1234567890",
		Nonce:        "abc123",
		Signature:    "sig",
		EphemeralKey: "eph",
	}

	err := q.Submit("intent-1", "tag-a", []byte(`{"test":true}`), headers)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	resp := q.Poll("intent-1")
	if resp == nil {
		t.Fatal("expected non-nil poll response")
	}
	if resp.Status != "pending" {
		t.Fatalf("expected pending, got %s", resp.Status)
	}
	if resp.EncryptedFileKey != "" {
		t.Fatal("expected empty encrypted_file_key for pending")
	}
}

func TestSubmitDuplicateReturnsError(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	headers := PluginHeaders{}
	if err := q.Submit("dup-1", "tag-a", []byte(`{}`), headers); err != nil {
		t.Fatalf("first Submit: %v", err)
	}

	err := q.Submit("dup-1", "tag-a", []byte(`{}`), headers)
	if err == nil {
		t.Fatal("expected error on duplicate intent_id")
	}
	if err.Error() != "duplicate_intent" {
		t.Fatalf("expected duplicate_intent error, got: %v", err)
	}
}

func TestPollUnknownReturnsNil(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	resp := q.Poll("nonexistent")
	if resp != nil {
		t.Fatal("expected nil for unknown intent_id")
	}
}

func TestFulfillAndPoll(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	headers := PluginHeaders{}
	q.Submit("intent-f", "tag-a", []byte(`{}`), headers)

	err := q.Fulfill("intent-f", "sealed-key-data")
	if err != nil {
		t.Fatalf("Fulfill: %v", err)
	}

	resp := q.Poll("intent-f")
	if resp == nil {
		t.Fatal("expected non-nil response after fulfill")
	}
	if resp.Status != "fulfilled" {
		t.Fatalf("expected fulfilled, got %s", resp.Status)
	}
	if resp.EncryptedFileKey != "sealed-key-data" {
		t.Fatalf("expected sealed-key-data, got %s", resp.EncryptedFileKey)
	}
}

func TestRejectAndPoll(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	headers := PluginHeaders{}
	q.Submit("intent-r", "tag-a", []byte(`{}`), headers)

	err := q.Reject("intent-r")
	if err != nil {
		t.Fatalf("Reject: %v", err)
	}

	resp := q.Poll("intent-r")
	if resp == nil {
		t.Fatal("expected non-nil response after reject")
	}
	if resp.Status != "rejected" {
		t.Fatalf("expected rejected, got %s", resp.Status)
	}
}

func TestFulfillUnknownReturnsError(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	err := q.Fulfill("nonexistent", "data")
	if err == nil {
		t.Fatal("expected error for unknown intent")
	}
	if err.Error() != "unknown_intent" {
		t.Fatalf("expected unknown_intent, got: %v", err)
	}
}

func TestRejectUnknownReturnsError(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	err := q.Reject("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown intent")
	}
	if err.Error() != "unknown_intent" {
		t.Fatalf("expected unknown_intent, got: %v", err)
	}
}

func TestFulfillAlreadyFulfilledReturnsError(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	headers := PluginHeaders{}
	q.Submit("intent-ff", "tag-a", []byte(`{}`), headers)
	q.Fulfill("intent-ff", "data")

	err := q.Fulfill("intent-ff", "data2")
	if err == nil {
		t.Fatal("expected error for already-terminal intent")
	}
	if err.Error() != "intent_already_terminal" {
		t.Fatalf("expected intent_already_terminal, got: %v", err)
	}
}

func TestRejectAlreadyRejectedReturnsError(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	headers := PluginHeaders{}
	q.Submit("intent-rr", "tag-a", []byte(`{}`), headers)
	q.Reject("intent-rr")

	err := q.Reject("intent-rr")
	if err == nil {
		t.Fatal("expected error for already-terminal intent")
	}
	if err.Error() != "intent_already_terminal" {
		t.Fatalf("expected intent_already_terminal, got: %v", err)
	}
}

func TestFulfillAfterRejectReturnsError(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	headers := PluginHeaders{}
	q.Submit("intent-rf", "tag-a", []byte(`{}`), headers)
	q.Reject("intent-rf")

	err := q.Fulfill("intent-rf", "data")
	if err == nil {
		t.Fatal("expected error for already-terminal intent")
	}
}

func TestPullReturnsOnlyPendingForTag(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	headers := PluginHeaders{Timestamp: "1", Nonce: "n1", Signature: "s1"}

	// Two intents for tag-a, one for tag-b.
	q.Submit("a1", "tag-a", []byte(`{"version":1,"action":"unwrap","intent_id":"a1"}`), headers)
	q.Submit("a2", "tag-a", []byte(`{"version":1,"action":"unwrap","intent_id":"a2"}`), headers)
	q.Submit("b1", "tag-b", []byte(`{"version":1,"action":"unwrap","intent_id":"b1"}`), headers)

	// Fulfill a2 — should no longer appear in pull.
	q.Fulfill("a2", "sealed")

	resp := q.Pull("tag-a")
	if len(resp.Intents) != 1 {
		t.Fatalf("expected 1 pending intent for tag-a, got %d", len(resp.Intents))
	}
	if resp.Intents[0].IntentID != "a1" {
		t.Fatalf("expected intent a1, got %s", resp.Intents[0].IntentID)
	}

	// Pull for tag-b should return 1.
	respB := q.Pull("tag-b")
	if len(respB.Intents) != 1 {
		t.Fatalf("expected 1 pending intent for tag-b, got %d", len(respB.Intents))
	}

	// Pull for unknown tag should return empty.
	respC := q.Pull("tag-c")
	if len(respC.Intents) != 0 {
		t.Fatalf("expected 0 intents for unknown tag, got %d", len(respC.Intents))
	}
}

func TestPullForwardsPluginHeaders(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	headers := PluginHeaders{
		Timestamp:    "1700000000",
		Nonce:        "deadbeef",
		Signature:    "hmac-sig-value",
		EphemeralKey: "eph-pub-b64",
	}

	q.Submit("h1", "tag-a", []byte(`{"version":1,"action":"unwrap","intent_id":"h1"}`), headers)

	resp := q.Pull("tag-a")
	if len(resp.Intents) != 1 {
		t.Fatalf("expected 1 intent, got %d", len(resp.Intents))
	}

	got := resp.Intents[0].PluginHeaders
	if got.Timestamp != headers.Timestamp {
		t.Fatalf("timestamp mismatch: %s vs %s", got.Timestamp, headers.Timestamp)
	}
	if got.Nonce != headers.Nonce {
		t.Fatalf("nonce mismatch: %s vs %s", got.Nonce, headers.Nonce)
	}
	if got.Signature != headers.Signature {
		t.Fatalf("signature mismatch: %s vs %s", got.Signature, headers.Signature)
	}
	if got.EphemeralKey != headers.EphemeralKey {
		t.Fatalf("ephemeral key mismatch: %s vs %s", got.EphemeralKey, headers.EphemeralKey)
	}
}

func TestTTLExpiresIntents(t *testing.T) {
	// Very short TTL for testing.
	q := NewQueue(50*time.Millisecond, 10*time.Millisecond)
	defer q.Stop()

	headers := PluginHeaders{}
	q.Submit("expire-1", "tag-a", []byte(`{}`), headers)

	// Immediately should be pending.
	resp := q.Poll("expire-1")
	if resp == nil || resp.Status != "pending" {
		t.Fatal("expected pending immediately after submit")
	}

	// Wait for TTL to expire.
	time.Sleep(100 * time.Millisecond)

	resp = q.Poll("expire-1")
	if resp != nil {
		t.Fatalf("expected nil after TTL expiry, got status=%s", resp.Status)
	}
}

func TestTTLExpiresPullResults(t *testing.T) {
	q := NewQueue(50*time.Millisecond, 10*time.Millisecond)
	defer q.Stop()

	headers := PluginHeaders{}
	q.Submit("expire-p", "tag-a", []byte(`{"version":1,"action":"unwrap","intent_id":"expire-p"}`), headers)

	time.Sleep(100 * time.Millisecond)

	resp := q.Pull("tag-a")
	if len(resp.Intents) != 0 {
		t.Fatalf("expected 0 intents after TTL, got %d", len(resp.Intents))
	}
}

func TestFulfillAfterTTLReturnsUnknown(t *testing.T) {
	q := NewQueue(50*time.Millisecond, 10*time.Millisecond)
	defer q.Stop()

	headers := PluginHeaders{}
	q.Submit("expire-f", "tag-a", []byte(`{}`), headers)

	time.Sleep(100 * time.Millisecond)

	err := q.Fulfill("expire-f", "data")
	if err == nil {
		t.Fatal("expected error fulfilling expired intent")
	}
	if err.Error() != "unknown_intent" {
		t.Fatalf("expected unknown_intent, got: %v", err)
	}
}

func TestRejectAfterTTLReturnsUnknown(t *testing.T) {
	q := NewQueue(50*time.Millisecond, 10*time.Millisecond)
	defer q.Stop()

	headers := PluginHeaders{}
	q.Submit("expire-r", "tag-a", []byte(`{}`), headers)

	time.Sleep(100 * time.Millisecond)

	err := q.Reject("expire-r")
	if err == nil {
		t.Fatal("expected error rejecting expired intent")
	}
	if err.Error() != "unknown_intent" {
		t.Fatalf("expected unknown_intent, got: %v", err)
	}
}

func TestSweepCleansExpiredIntents(t *testing.T) {
	// Short TTL, very short sweep interval.
	q := NewQueue(30*time.Millisecond, 10*time.Millisecond)
	defer q.Stop()

	headers := PluginHeaders{}
	q.Submit("sweep-1", "tag-a", []byte(`{}`), headers)
	q.Submit("sweep-2", "tag-a", []byte(`{}`), headers)

	// Wait for sweep to clean up.
	time.Sleep(80 * time.Millisecond)

	// Both should be gone.
	if resp := q.Poll("sweep-1"); resp != nil {
		t.Fatal("expected sweep-1 to be cleaned up")
	}
	if resp := q.Poll("sweep-2"); resp != nil {
		t.Fatal("expected sweep-2 to be cleaned up")
	}

	// New submits should work (IDs freed).
	if err := q.Submit("sweep-1", "tag-a", []byte(`{}`), headers); err != nil {
		t.Fatalf("re-submit after sweep: %v", err)
	}
}

func TestMultipleTagsIsolation(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	headers := PluginHeaders{}
	q.Submit("iso-1", "alpha", []byte(`{"version":1,"action":"unwrap","intent_id":"iso-1"}`), headers)
	q.Submit("iso-2", "beta", []byte(`{"version":1,"action":"unwrap","intent_id":"iso-2"}`), headers)
	q.Submit("iso-3", "alpha", []byte(`{"version":1,"action":"unwrap","intent_id":"iso-3"}`), headers)

	alpha := q.Pull("alpha")
	if len(alpha.Intents) != 2 {
		t.Fatalf("expected 2 alpha intents, got %d", len(alpha.Intents))
	}

	beta := q.Pull("beta")
	if len(beta.Intents) != 1 {
		t.Fatalf("expected 1 beta intent, got %d", len(beta.Intents))
	}

	// Fulfilling alpha intent doesn't affect beta.
	q.Fulfill("iso-1", "sealed")
	beta2 := q.Pull("beta")
	if len(beta2.Intents) != 1 {
		t.Fatalf("beta should still have 1 intent, got %d", len(beta2.Intents))
	}
}
