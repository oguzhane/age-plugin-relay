package broker

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/oguzhane/age-plugin-relay/relay"
)

func testClaimKeypair(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := relay.GenerateIntentClaim()
	if err != nil {
		t.Fatalf("GenerateIntentClaim: %v", err)
	}
	return relay.EncodeIntentClaimPub(pub), priv
}

func TestSubmitAndPoll(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	pubKey, _ := testClaimKeypair(t)
	err := q.Submit("intent-1", "tag-a", []byte(`{"test":true}`), pubKey)
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
	if resp.Response != nil {
		t.Fatal("expected nil response for pending")
	}
}

func TestSubmitDuplicateReturnsError(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	pubKey, _ := testClaimKeypair(t)
	if err := q.Submit("dup-1", "tag-a", []byte(`{}`), pubKey); err != nil {
		t.Fatalf("first Submit: %v", err)
	}

	err := q.Submit("dup-1", "tag-a", []byte(`{}`), pubKey)
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

	pubKey, priv := testClaimKeypair(t)
	q.Submit("intent-f", "tag-a", []byte(`{}`), pubKey)

	fulfillBody := []byte(`{"version":1,"action":"fulfill","intent_id":"intent-f","encrypted_payload":"sealed-payload-data"}`)
	sig := relay.SignIntentClaim(priv, 1, "fulfill", "intent-f", "sealed-payload-data")
	err := q.Fulfill("intent-f", fulfillBody, sig, 1, "fulfill", "sealed-payload-data")
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
	// Response should be the verbatim fulfill body.
	if !json.Valid(resp.Response) {
		t.Fatal("expected valid JSON in response")
	}
	var parsed map[string]interface{}
	json.Unmarshal(resp.Response, &parsed)
	if parsed["encrypted_payload"] != "sealed-payload-data" {
		t.Fatalf("expected sealed-payload-data in response, got %v", parsed["encrypted_payload"])
	}
}

func TestRejectAndPoll(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	pubKey, priv := testClaimKeypair(t)
	q.Submit("intent-r", "tag-a", []byte(`{}`), pubKey)

	sig := relay.SignIntentClaim(priv, 1, "reject", "intent-r", "")
	err := q.Reject("intent-r", []byte(`{"version":1,"action":"reject","intent_id":"intent-r"}`), sig, 1, "reject", "")
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
	if resp.Response == nil {
		t.Fatal("expected non-nil response field for rejected intent")
	}
}

func TestFulfillUnknownReturnsError(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	err := q.Fulfill("nonexistent", []byte("data"), "dummy-sig", 1, "fulfill", "")
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

	err := q.Reject("nonexistent", []byte(`{}`), "dummy-sig", 1, "reject", "")
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

	pubKey, priv := testClaimKeypair(t)
	q.Submit("intent-ff", "tag-a", []byte(`{}`), pubKey)

	sig := relay.SignIntentClaim(priv, 1, "fulfill", "intent-ff", "data")
	q.Fulfill("intent-ff", []byte("data"), sig, 1, "fulfill", "data")

	err := q.Fulfill("intent-ff", []byte("data2"), "dummy-sig", 1, "fulfill", "data2")
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

	pubKey, priv := testClaimKeypair(t)
	q.Submit("intent-rr", "tag-a", []byte(`{}`), pubKey)

	sig := relay.SignIntentClaim(priv, 1, "reject", "intent-rr", "")
	q.Reject("intent-rr", []byte(`{}`), sig, 1, "reject", "")

	err := q.Reject("intent-rr", []byte(`{}`), "dummy-sig", 1, "reject", "")
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

	pubKey, priv := testClaimKeypair(t)
	q.Submit("intent-rf", "tag-a", []byte(`{}`), pubKey)

	sig := relay.SignIntentClaim(priv, 1, "reject", "intent-rf", "")
	q.Reject("intent-rf", []byte(`{}`), sig, 1, "reject", "")

	err := q.Fulfill("intent-rf", []byte("data"), "dummy-sig", 1, "fulfill", "")
	if err == nil {
		t.Fatal("expected error for already-terminal intent")
	}
}

func TestPullReturnsOnlyPendingForTag(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	pubKey, priv := testClaimKeypair(t)
	q.Submit("a1", "tag-a", []byte(`{"version":1,"action":"unwrap","intent_id":"a1"}`), pubKey)
	q.Submit("a2", "tag-a", []byte(`{"version":1,"action":"unwrap","intent_id":"a2"}`), pubKey)

	pubKeyB, _ := testClaimKeypair(t)
	q.Submit("b1", "tag-b", []byte(`{"version":1,"action":"unwrap","intent_id":"b1"}`), pubKeyB)

	// Fulfill a2 — should no longer appear in pull.
	sig := relay.SignIntentClaim(priv, 1, "fulfill", "a2", "sealed")
	q.Fulfill("a2", []byte("sealed"), sig, 1, "fulfill", "sealed")

	resp := q.Pull("tag-a")
	if len(resp.Intents) != 1 {
		t.Fatalf("expected 1 pending intent for tag-a, got %d", len(resp.Intents))
	}
	if resp.Intents[0].IntentID != "a1" {
		t.Fatalf("expected intent a1, got %s", resp.Intents[0].IntentID)
	}

	respB := q.Pull("tag-b")
	if len(respB.Intents) != 1 {
		t.Fatalf("expected 1 pending intent for tag-b, got %d", len(respB.Intents))
	}

	respC := q.Pull("tag-c")
	if len(respC.Intents) != 0 {
		t.Fatalf("expected 0 intents for unknown tag, got %d", len(respC.Intents))
	}
}

func TestTTLExpiresIntents(t *testing.T) {
	q := NewQueue(50*time.Millisecond, 10*time.Millisecond)
	defer q.Stop()

	pubKey, _ := testClaimKeypair(t)
	q.Submit("expire-1", "tag-a", []byte(`{}`), pubKey)

	resp := q.Poll("expire-1")
	if resp == nil || resp.Status != "pending" {
		t.Fatal("expected pending immediately after submit")
	}

	time.Sleep(100 * time.Millisecond)

	resp = q.Poll("expire-1")
	if resp != nil {
		t.Fatalf("expected nil after TTL expiry, got status=%s", resp.Status)
	}
}

func TestTTLExpiresPullResults(t *testing.T) {
	q := NewQueue(50*time.Millisecond, 10*time.Millisecond)
	defer q.Stop()

	pubKey, _ := testClaimKeypair(t)
	q.Submit("expire-p", "tag-a", []byte(`{"version":1,"action":"unwrap","intent_id":"expire-p"}`), pubKey)

	time.Sleep(100 * time.Millisecond)

	resp := q.Pull("tag-a")
	if len(resp.Intents) != 0 {
		t.Fatalf("expected 0 intents after TTL, got %d", len(resp.Intents))
	}
}

func TestFulfillAfterTTLReturnsUnknown(t *testing.T) {
	q := NewQueue(50*time.Millisecond, 10*time.Millisecond)
	defer q.Stop()

	pubKey, _ := testClaimKeypair(t)
	q.Submit("expire-f", "tag-a", []byte(`{}`), pubKey)

	time.Sleep(100 * time.Millisecond)

	err := q.Fulfill("expire-f", []byte("data"), "dummy-sig", 1, "fulfill", "")
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

	pubKey, _ := testClaimKeypair(t)
	q.Submit("expire-r", "tag-a", []byte(`{}`), pubKey)

	time.Sleep(100 * time.Millisecond)

	err := q.Reject("expire-r", []byte(`{}`), "dummy-sig", 1, "reject", "")
	if err == nil {
		t.Fatal("expected error rejecting expired intent")
	}
	if err.Error() != "unknown_intent" {
		t.Fatalf("expected unknown_intent, got: %v", err)
	}
}

func TestSweepCleansExpiredIntents(t *testing.T) {
	q := NewQueue(30*time.Millisecond, 10*time.Millisecond)
	defer q.Stop()

	pubKey, _ := testClaimKeypair(t)
	q.Submit("sweep-1", "tag-a", []byte(`{}`), pubKey)
	q.Submit("sweep-2", "tag-a", []byte(`{}`), pubKey)

	time.Sleep(80 * time.Millisecond)

	if resp := q.Poll("sweep-1"); resp != nil {
		t.Fatal("expected sweep-1 to be cleaned up")
	}
	if resp := q.Poll("sweep-2"); resp != nil {
		t.Fatal("expected sweep-2 to be cleaned up")
	}

	if err := q.Submit("sweep-1", "tag-a", []byte(`{}`), pubKey); err != nil {
		t.Fatalf("re-submit after sweep: %v", err)
	}
}

func TestMultipleTagsIsolation(t *testing.T) {
	q := NewQueue(1*time.Minute, 30*time.Second)
	defer q.Stop()

	pubKey, priv := testClaimKeypair(t)
	q.Submit("iso-1", "alpha", []byte(`{"version":1,"action":"unwrap","intent_id":"iso-1"}`), pubKey)

	pubKey2, _ := testClaimKeypair(t)
	q.Submit("iso-2", "beta", []byte(`{"version":1,"action":"unwrap","intent_id":"iso-2"}`), pubKey2)
	q.Submit("iso-3", "alpha", []byte(`{"version":1,"action":"unwrap","intent_id":"iso-3"}`), pubKey)

	alpha := q.Pull("alpha")
	if len(alpha.Intents) != 2 {
		t.Fatalf("expected 2 alpha intents, got %d", len(alpha.Intents))
	}

	beta := q.Pull("beta")
	if len(beta.Intents) != 1 {
		t.Fatalf("expected 1 beta intent, got %d", len(beta.Intents))
	}

	sig := relay.SignIntentClaim(priv, 1, "fulfill", "iso-1", "sealed")
	q.Fulfill("iso-1", []byte("sealed"), sig, 1, "fulfill", "sealed")
	beta2 := q.Pull("beta")
	if len(beta2.Intents) != 1 {
		t.Fatalf("beta should still have 1 intent, got %d", len(beta2.Intents))
	}
}
