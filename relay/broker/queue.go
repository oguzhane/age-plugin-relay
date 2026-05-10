package broker

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/oguzhane/age-plugin-relay/relay"
)

// Queue is a thread-safe in-memory intent queue with TTL-based expiry.
type Queue struct {
	mu      sync.Mutex
	intents map[string]*Intent // keyed by intent_id
	maxTTL  time.Duration

	// stopSweep signals the background goroutine to stop.
	stopSweep chan struct{}
}

// NewQueue creates a new intent queue. The sweepInterval controls how often
// expired intents are cleaned up. maxTTL is the broker's internal TTL ceiling.
func NewQueue(maxTTL time.Duration, sweepInterval time.Duration) *Queue {
	q := &Queue{
		intents:   make(map[string]*Intent),
		maxTTL:    maxTTL,
		stopSweep: make(chan struct{}),
	}

	go q.sweepLoop(sweepInterval)
	return q
}

// Stop terminates the background sweep goroutine.
func (q *Queue) Stop() {
	close(q.stopSweep)
}

// Submit stores a new intent. Returns an error if the intent_id already exists (409).
func (q *Queue) Submit(intentID, tag string, requestBody []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if _, exists := q.intents[intentID]; exists {
		return fmt.Errorf("duplicate_intent")
	}

	q.intents[intentID] = &Intent{
		IntentID:  intentID,
		Tag:       tag,
		Request:   requestBody,
		Status:    StatusPending,
		CreatedAt: time.Now(),
	}
	return nil
}

// Poll returns the current state of an intent. Returns nil if the intent
// does not exist (expired or never created — collapsed to 404).
func (q *Queue) Poll(intentID string) *PollResponse {
	q.mu.Lock()
	defer q.mu.Unlock()

	intent, ok := q.intents[intentID]
	if !ok {
		return nil
	}

	// Check TTL inline.
	if time.Since(intent.CreatedAt) > q.maxTTL {
		delete(q.intents, intentID)
		return nil
	}

	resp := &PollResponse{
		Status: string(intent.Status),
	}
	if intent.Status == StatusFulfilled {
		resp.EncryptedPayload = intent.EncryptedPayload
	}
	return resp
}

// Pull returns all pending intents matching the given tag. The request body is
// returned verbatim so the operator can decrypt and verify the encrypted payload.
func (q *Queue) Pull(tag string) *PullResponse {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	resp := &PullResponse{
		Intents: []PullIntent{},
	}

	for id, intent := range q.intents {
		// Expire inline.
		if now.Sub(intent.CreatedAt) > q.maxTTL {
			delete(q.intents, id)
			continue
		}

		if intent.Tag != tag || intent.Status != StatusPending {
			continue
		}

		var req relay.RelayRequest
		if err := json.Unmarshal(intent.Request, &req); err != nil {
			// Skip malformed stored requests (should not happen).
			continue
		}

		resp.Intents = append(resp.Intents, PullIntent{
			IntentID: intent.IntentID,
			Request:  req,
		})
	}

	return resp
}

// Fulfill marks an intent as fulfilled with the operator's encrypted payload.
// Returns an error if the intent doesn't exist, is expired, or is already terminal.
func (q *Queue) Fulfill(intentID, encryptedPayload string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	intent, ok := q.intents[intentID]
	if !ok {
		return fmt.Errorf("unknown_intent")
	}

	if time.Since(intent.CreatedAt) > q.maxTTL {
		delete(q.intents, intentID)
		return fmt.Errorf("unknown_intent")
	}

	if intent.Status != StatusPending {
		return fmt.Errorf("intent_already_terminal")
	}

	intent.Status = StatusFulfilled
	intent.EncryptedPayload = encryptedPayload
	return nil
}

// Reject marks an intent as rejected.
// Returns an error if the intent doesn't exist, is expired, or is already terminal.
func (q *Queue) Reject(intentID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	intent, ok := q.intents[intentID]
	if !ok {
		return fmt.Errorf("unknown_intent")
	}

	if time.Since(intent.CreatedAt) > q.maxTTL {
		delete(q.intents, intentID)
		return fmt.Errorf("unknown_intent")
	}

	if intent.Status != StatusPending {
		return fmt.Errorf("intent_already_terminal")
	}

	intent.Status = StatusRejected
	return nil
}

// sweepLoop periodically removes expired intents.
func (q *Queue) sweepLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-q.stopSweep:
			return
		case <-ticker.C:
			q.sweep()
		}
	}
}

func (q *Queue) sweep() {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	for id, intent := range q.intents {
		if now.Sub(intent.CreatedAt) > q.maxTTL {
			delete(q.intents, id)
		}
	}
}
