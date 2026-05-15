# Testing

## Running tests

```bash
go test ./...                                  # all tests
go test ./relay -v                             # core package
go test ./relay/broker -v                      # broker queue
go test ./relay -run 'TestE2E' -v              # E2E tests
go test ./relay -run TestAsync -v              # async (broker) tests
```

## Unit tests

### Encoding tests (`encoding_test.go`)

| Test | What it validates |
|---|---|
| `TestComputeTagDeterministic` | Same input always produces same 16-byte tag |
| `TestComputeTagDifferent` | Different inputs produce different tags |
| `TestEncodeDecodeRecipient` | `age1relay1...` round-trips through Bech32 encode/decode |
| `TestEncodeDecodeIdentity` | `AGE-PLUGIN-RELAY-1...` round-trips with tag and remote name preserved |
| `TestWrapProducesRelayStanzas` | `Wrap()` produces stanzas with type `relay`, correct tag, inner type `X25519` |

### Identity tests (`identity_test.go`)

| Test | What it validates |
|---|---|
| `TestEndToEndWithMockRelay` | Full flow: wrap, encrypted payload to mock server, server decrypts/verifies/unwraps/seals, file key matches |
| `TestEndToEndWithSSERelay` | Full wrap/unwrap flow over SSE with encrypted payload |
| `TestSSERelayError` | Error event from SSE relay (wrong identity) |
| `TestUnwrapNoMatchingStanza` | Non-matching stanzas return `age.ErrIncorrectIdentity` |
| `TestUnwrapMissingUnwrapRecipient` | Clear error when `unwrap_recipient` is not set |
| `TestResolveRemoteNamedNotFound` | Named remote without config returns error |
| `TestConcurrentUnwrapRequests` | 10 concurrent unwrap requests all succeed |

### Client tests (`client_test.go`)

| Test | What it validates |
|---|---|
| `TestGenerateIntentIDFormat` | Intent ID is 32 lowercase hex chars |
| `TestGenerateIntentIDUniqueness` | 100 generated intent IDs are all unique |
| `TestSanitizeErrorMsgShort` | Short messages pass through unchanged |
| `TestSanitizeErrorMsgTruncation` | Messages > 256 chars truncated with `...` |
| `TestSanitizeErrorMsgControlChars` | Control chars stripped, tabs/newlines preserved |
| `TestSanitizeErrorMsgEmpty` | Empty string returns empty |
| `TestExtractFileKeyEmpty` | Empty response returns error |
| `TestExtractFileKeyBadBase64` | Invalid base64 returns error |
| `TestExtractFileKeyWrongKey` | Wrong ephemeral key returns error |
| `TestExtractFileKeyWrongIntentID` | Wrong intent_id detected via outer_hash mismatch |
| `TestFileKeyRecoveryVariousSizes` | Round-trip with 0, 1, 15, 16, 32, 64-byte file keys |
| `TestPostToRelay5xxError` | Server 500 returns error |
| `TestPostToRelayServerReturnsErrorInJSON` | Server 200 with error JSON returns error |
| `TestSSEHeartbeatOnly` | Heartbeat-only stream (no result) returns error |
| `TestSSEErrorEvent` | SSE error event propagates error message |
| `TestAuthTokenSentAsBearer` | Auth token sent as `Authorization: Bearer` header |
| `TestNoAuthTokenOmitsHeader` | No auth token omits header entirely |
| `TestWireFormatRequestFields` | Request has version, action, intent_id, tag, expires_at, encrypted_payload; no outer stanzas |
| `TestEncryptedPayloadAsyncE2E` | Full async flow: submit → 202 → poll → operator fulfills → plugin recovers file key |

### Config tests (`config_test.go`)

| Test | What it validates |
|---|---|
| `TestLoadConfigInvalidYAML` | Invalid YAML returns parse error |
| `TestLoadConfigMissing` | Missing config file returns nil (not error) |
| `TestLookupRemoteEmptyURL` | Remote with empty URL returns error |
| `TestLookupRemoteNilConfig` | Nil config returns error |
| `TestLookupRemoteNotFound` | Missing remote name returns error with available list |
| `TestTimeoutDurationDefault` | Default timeout is 5 minutes |
| `TestTimeoutDurationInvalid` | Invalid duration falls back to 5 minutes |
| `TestTimeoutDurationCustom` | Custom duration `30s` parsed correctly |
| `TestPollIntervalDefault` | Default: `min(timeout/60, 5s)` with 500ms floor; explicit override works |

### Payload encryption tests (`payload_test.go`)

| Test | What it validates |
|---|---|
| `TestOuterHashRequestDeterminism` | Same inputs produce same hash (known-answer test) |
| `TestOuterHashResponseDeterminism` | Same intent_id produces same hash (known-answer test) |
| `TestOuterHashRequestDifferentFields` | Different fields produce different hashes |
| `TestEncryptDecryptPayloadRoundTrip` | Encrypt → decrypt round-trip preserves inner payload |
| `TestDecryptPayloadWrongIdentityFails` | Decryption with wrong identity fails |
| `TestVerifyRequestPayloadValid` | Valid outer hash passes verification |
| `TestVerifyRequestPayloadTamperedHash` | Tampered outer fields detected |
| `TestVerifyRequestPayloadExpired` | Expired `expires_at` rejected |
| `TestVerifyResponsePayloadValid` | Valid response hash passes |
| `TestVerifyResponsePayloadTamperedHash` | Tampered response hash detected |
| `TestBuildRequestPayload` | Request payload has correct fields, 32-char hex nonce |
| `TestBuildResponsePayload` | Response payload has correct fields, base64-encoded file key |
| `TestNonceUniqueness` | Two encryptions of same payload produce different ciphertext |
| `TestEncryptDecryptFullFlow` | End-to-end: build → encrypt → decrypt → verify |
| `TestResponsePayloadFullFlow` | Build response → verify → decode file key |
| `TestParseRecipientStringValid` | Valid X25519 recipient parses successfully |
| `TestParseRecipientStringUnsupported` | Non-age recipient returns unsupported error |
| `TestParseRecipientStringInvalid` | Invalid age1 string returns parse error |
| `TestOuterHashTamperDetectionTag` | Encrypt → decrypt → verify with tampered tag fails |
| `TestOuterHashTamperDetectionIntentID` | Encrypt → decrypt → verify with tampered intent_id fails |
| `TestExpiresAtEnforcement` | Encrypt → decrypt → verify with expired timestamp fails |

### Intent Claim tests (`claim_test.go`)

| Test | What it validates |
|---|---|
| `TestGenerateIntentClaim` | Keypair generation produces valid 32-byte public key and 64-byte private key |
| `TestEncodeDecodeIntentClaimSecret` | Round-trip encode/decode of Ed25519 private key seed |
| `TestSignAndVerifyRoundTrip` | Sign → verify round-trip succeeds |
| `TestVerifyWrongKey` | Verification fails with a different public key |
| `TestVerifyTamperedAction` | Verification fails when action is tampered |
| `TestVerifyTamperedIntentID` | Verification fails when intent_id is tampered |
| `TestVerifyTamperedPayload` | Verification fails when encrypted_payload is tampered |
| `TestIntentClaimCanonicalDeterminism` | Same inputs produce same canonical string |
| `TestVerifyIntentClaimInvalidBase64` | Invalid base64 inputs return errors |

### Envelope tests (`envelope_test.go`)

| Test | What it validates |
|---|---|
| `TestSealOpenResponse` | Age seal/open round-trip with structured inner response |
| `TestOpenResponseWrongKey` | Envelope rejects wrong ephemeral identity |
| `TestOpenResponseTruncated` | Envelope rejects truncated sealed data |
| `TestOpenResponseBadBase64` | Invalid base64 returns error |
| `TestOpenResponseTamperedCiphertext` | Flipped byte in ciphertext detected |
| `TestSealResponseDifferentEachTime` | Two seals produce different ciphertext |
| `TestEphemeralClear` | Identity and recipient are nil after `Clear()` |
| `TestEphemeralKeypairsAreUnique` | 50 generated keypairs are all unique |
| `TestSealOpenResponseVariousSizes` | Round-trip with 0, 1, 15, 16, 32, 64-byte file keys |

## Broker queue tests

```bash
go test -v ./relay/broker/
```

| Test | What it validates |
|---|---|
| `TestSubmitAndPoll` | Submit intent, poll returns pending status |
| `TestSubmitDuplicateReturnsError` | Duplicate intent_id returns `duplicate_intent` error |
| `TestPollUnknownReturnsNil` | Polling nonexistent intent returns nil |
| `TestFulfillAndPoll` | Fulfill transitions intent to `fulfilled` with encrypted payload |
| `TestRejectAndPoll` | Reject transitions intent to `rejected` |
| `TestFulfillUnknownReturnsError` | Fulfilling unknown intent returns `unknown_intent` |
| `TestRejectUnknownReturnsError` | Rejecting unknown intent returns `unknown_intent` |
| `TestFulfillAlreadyFulfilledReturnsError` | Double-fulfill returns `intent_already_terminal` |
| `TestRejectAlreadyRejectedReturnsError` | Double-reject returns `intent_already_terminal` |
| `TestFulfillAfterRejectReturnsError` | Fulfill after reject returns error |
| `TestPullReturnsOnlyPendingForTag` | Pull filters by tag and returns only pending intents |
| `TestTTLExpiresIntents` | Intents expire after TTL, poll returns nil |
| `TestTTLExpiresPullResults` | Expired intents excluded from pull results |
| `TestFulfillAfterTTLReturnsUnknown` | Fulfilling expired intent returns `unknown_intent` |
| `TestRejectAfterTTLReturnsUnknown` | Rejecting expired intent returns `unknown_intent` |
| `TestSweepCleansExpiredIntents` | Background sweep removes expired intents, IDs freed for reuse |
| `TestMultipleTagsIsolation` | Different tags are fully isolated |

## Async (broker) tests

```bash
go test -v ./relay/ -run TestAsync
```

| Test | What it validates |
|---|---|
| `TestAsyncEndToEnd` | Full flow: submit encrypted → pull → decrypt → verify → unwrap → seal → fulfill → poll → decrypt response |
| `TestAsyncRejectionFlow` | Operator rejection propagates to plugin poll |
| `TestAsyncDuplicateIntentReturns409` | Broker returns 409 on duplicate intent_id |
| `TestAsyncPollUnknownReturns404` | Polling nonexistent intent returns 404 |
| `TestAsyncFulfillAfterRejectReturns409` | Fulfill on already-terminal intent returns 409 |
| `TestAsyncPollAfterExpiry` | TTL expiry causes 404 on poll |
| `TestAsyncPluginPollingLoop` | Full `PostToRelay` async branch with background operator fulfill |
| `TestAsyncPluginPollingLoopRejected` | `PostToRelay` returns error on operator rejection |
| `TestAsyncBrokerDoesNotSeeFileKey` | Broker only stores opaque encrypted payloads, never plaintext stanzas or file keys |
| `TestAsyncOuterHashTamperDetection` | Outer hash detects tampered intent_id, tag, and expires_at |

## Integration tests

| Test | What it validates |
|---|---|
| `TestIntegrationConfigMode` | Full encrypt/decrypt with remote name resolved from config |
| `TestIntegrationConfigMissingRemote` | Clear error for non-existent remote (lists available) |
| `TestIntegrationRelayServerDown` | Clean error when relay endpoint unreachable |
| `TestIntegrationWrongIdentity` | Clean error when relay has wrong key |
| `TestIntegrationEncryptedPayloadE2E` | Full encrypted payload end-to-end with mock server |
| `TestIntegrationMissingUnwrapRecipient` | Clear error when `unwrap_recipient` is not configured |
| `TestEncryptedPayloadSyncE2E` | Full `age.Encrypt` → `age.Decrypt` with encrypted payloads (JSON) |
| `TestEncryptedPayloadSyncE2EWithSSE` | Full `age.Encrypt` → `age.Decrypt` with encrypted payloads (SSE) |
| `TestBrokerBlindnessVerification` | Broker cannot parse or decrypt encrypted payloads; wrong identity fails |
| `TestResponseOuterHashTamperingE2E` | Server returning wrong intent_id in response detected via outer_hash |

## E2E tests

E2E tests build all binaries and run the full encrypt → relay → decrypt flow using real processes.

### Sync flow (`e2e_test.go`)

| Test | What it validates |
|---|---|
| `TestE2EConfigMode` | Full encrypt → relay → decrypt flow with real binaries (config mode) |
| `TestE2ESSEStream` | Same with SSE streaming enabled |

### TLS (`e2e_tls_test.go`)

| Test | What it validates |
|---|---|
| `TestE2ETLSSync` | Sync flow over TLS (server certificate verification) |
| `TestE2EMTLSSync` | Sync flow with mutual TLS (client certificate required) |

### Async flow (`e2e_async_test.go`)

| Test | What it validates |
|---|---|
| `TestE2EAsyncHappyPath` | Full async encrypt → broker → operator → decrypt flow |
| `TestE2EAsyncOperatorRejectsWrongKey` | Operator rejects when it doesn't hold the matching identity |
| `TestE2EAsyncIntentExpiry` | Broker expires intents after TTL |
| `TestE2EAsyncMultipleIdentities` | Operator with multiple identities unwraps the correct one |
| `TestE2EAsyncWithAuthToken` | Async flow with Bearer token authentication |
| `TestE2EAsyncWrongAuthToken` | Broker rejects requests with invalid auth token |
| `TestE2EAsyncOneShotOperator` | Operator in one-shot mode (no `--loop`) processes and exits |

### Error handling (`e2e_errors_test.go`)

| Test | What it validates |
|---|---|
| `TestE2EAuthTokenSync` | Sync relay rejects requests with wrong/missing auth token |
| `TestE2ESyncServerDown` | Plugin returns error when relay server is unreachable |
| `TestE2ESyncWrongKey` | Sync relay rejects when identity doesn't match the stanzas |
| `TestE2EAsyncBrokerDown` | Plugin returns error when broker is unreachable |
