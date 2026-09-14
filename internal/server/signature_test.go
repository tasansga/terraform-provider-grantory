package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/api/client"
	apiservice "github.com/tasansga/terraform-provider-grantory/api/service"
	"github.com/tasansga/terraform-provider-grantory/internal/cluster/raft"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

func sendTestRequestRaw(t *testing.T, app *fiber.App, method, path string, headers map[string]string, body []byte) *http.Response {
	t.Helper()

	var buf io.Reader
	if body != nil {
		buf = bytes.NewReader(body)
	}

	req := httptest.NewRequest(method, path, buf)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := app.Test(req)
	require.NoError(t, err)
	return res
}

func sign(priv ed25519.PrivateKey, timestamp, nonce, method, path, body string) string {
	content := fmt.Sprintf("%s:%s:%s:%s:%s", timestamp, nonce, method, path, body)
	sig := ed25519.Sign(priv, []byte(content))
	return base64.StdEncoding.EncodeToString(sig)
}

func TestSignatureVerification(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	// 1. Generate Ed25519 key pair
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	pubHex := hex.EncodeToString(pub)

	// 2. Create a host with the public key
	hostPayload := map[string]any{
		"unique_key": "signed-host",
		"public_key": pubHex,
		"labels":     map[string]string{"env": "secure"},
	}
	res := sendTestRequest(t, app, http.MethodPost, "/hosts", nil, hostPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode)
	var host client.Host
	err = json.NewDecoder(res.Body).Decode(&host)
	require.NoError(t, err)
	hostID := host.ID

	// 3. Try to create a request WITHOUT a signature - should fail
	reqPayload := map[string]any{
		"host_id": hostID,
		"mutable": true,
		"payload": map[string]any{"data": "secret"},
	}
	res = sendTestRequest(t, app, http.MethodPost, "/requests", nil, reqPayload)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "should fail without signature")

	// 4. Create a request WITH a signature
	now := time.Now().Unix()
	timestamp := fmt.Sprintf("%d", now)
	nonce := "nonce1"

	bodyBytes, _ := json.Marshal(reqPayload)
	sigBase64 := sign(priv, timestamp, nonce, http.MethodPost, "/requests", string(bodyBytes))

	headers := map[string]string{
		"X-Grantory-Timestamp": timestamp,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sigBase64,
	}

	res = sendTestRequestRaw(t, app, http.MethodPost, "/requests", headers, bodyBytes)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "should succeed with valid signature")
	createdReq := decodeJSON[client.Request](t, res)
	reqID := createdReq.ID

	// 5. Try with wrong key
	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	wrongSigBase64 := sign(wrongPriv, timestamp, nonce, http.MethodPost, "/requests", string(bodyBytes))
	wrongHeaders := map[string]string{
		"X-Grantory-Timestamp": timestamp,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": wrongSigBase64,
	}
	res = sendTestRequestRaw(t, app, http.MethodPost, "/requests", wrongHeaders, bodyBytes)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "should fail with wrong signature")

	// 6. Update request WITH signature
	updatePayload := map[string]any{
		"payload": map[string]any{"data": "updated-secret"},
	}
	now = time.Now().Unix()
	timestamp = fmt.Sprintf("%d", now)
	nonce = "nonce-update"
	bodyBytes, _ = json.Marshal(updatePayload)
	path := fmt.Sprintf("/requests/%s", reqID)
	sigBase64 = sign(priv, timestamp, nonce, http.MethodPatch, path, string(bodyBytes))

	headers = map[string]string{
		"X-Grantory-Timestamp": timestamp,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sigBase64,
	}
	res = sendTestRequestRaw(t, app, http.MethodPatch, path, headers, bodyBytes)
	assert.Equal(t, http.StatusOK, res.StatusCode, "update should succeed with valid signature")

	// 7. Delete request WITH signature
	now = time.Now().Unix()
	timestamp = fmt.Sprintf("%d", now)
	nonce = "nonce-delete"
	sigBase64 = sign(priv, timestamp, nonce, http.MethodDelete, path, "")

	headers = map[string]string{
		"X-Grantory-Timestamp": timestamp,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sigBase64,
	}
	res = sendTestRequestRaw(t, app, http.MethodDelete, path, headers, nil)
	assert.Equal(t, http.StatusNoContent, res.StatusCode, "delete should succeed with valid signature")

	// 8. Test edge cases
	// 8a. Expired timestamp (6 minutes ago)
	expiredTs := fmt.Sprintf("%d", time.Now().Unix()-360)
	nonce = "nonce-expired"
	bodyBytes, _ = json.Marshal(reqPayload)
	sigBase64 = sign(priv, expiredTs, nonce, http.MethodPost, "/requests", string(bodyBytes))
	expiredHeaders := map[string]string{
		"X-Grantory-Timestamp": expiredTs,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sigBase64,
	}
	res = sendTestRequestRaw(t, app, http.MethodPost, "/requests", expiredHeaders, bodyBytes)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "should fail with expired timestamp")

	// 8b. Future timestamp (6 minutes ahead)
	futureTs := fmt.Sprintf("%d", time.Now().Unix()+360)
	nonce = "nonce-future"
	sigBase64 = sign(priv, futureTs, nonce, http.MethodPost, "/requests", string(bodyBytes))
	futureHeaders := map[string]string{
		"X-Grantory-Timestamp": futureTs,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sigBase64,
	}
	res = sendTestRequestRaw(t, app, http.MethodPost, "/requests", futureHeaders, bodyBytes)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "should fail with future timestamp")

	// 8c. Body tampering
	now = time.Now().Unix()
	timestamp = fmt.Sprintf("%d", now)
	nonce = "nonce-tamper"
	sigBase64 = sign(priv, timestamp, nonce, http.MethodPost, "/requests", string(bodyBytes))
	tamperedPayload := map[string]any{
		"host_id": hostID,
		"mutable": true,
		"payload": map[string]any{"data": "tampered"},
	}
	tamperedBytes, _ := json.Marshal(tamperedPayload)
	headers = map[string]string{
		"X-Grantory-Timestamp": timestamp,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sigBase64,
	}
	res = sendTestRequestRaw(t, app, http.MethodPost, "/requests", headers, tamperedBytes)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "should fail with tampered body")

	// 8d. Method tampering (signed as POST, sent as PATCH)
	now = time.Now().Unix()
	timestamp = fmt.Sprintf("%d", now)
	nonce = "nonce-method-tamper"
	bodyBytes, _ = json.Marshal(reqPayload)
	sigBase64 = sign(priv, timestamp, nonce, http.MethodPost, "/requests", string(bodyBytes))
	res = sendTestRequestRaw(t, app, http.MethodPost, "/requests",
		map[string]string{
			"X-Grantory-Timestamp": timestamp,
			"X-Grantory-Nonce":     nonce,
			"X-Grantory-Signature": sigBase64,
		}, bodyBytes)
	require.Equal(t, http.StatusCreated, res.StatusCode)
	newReqID := decodeJSON[client.Request](t, res).ID

	now = time.Now().Unix()
	timestamp = fmt.Sprintf("%d", now)
	nonce = "nonce-method-tamper-2"
	path = fmt.Sprintf("/requests/%s", newReqID)
	// Sign as POST but send as PATCH
	sigBase64 = sign(priv, timestamp, nonce, http.MethodPost, path, string(bodyBytes))
	headers = map[string]string{
		"X-Grantory-Timestamp": timestamp,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sigBase64,
	}
	res = sendTestRequestRaw(t, app, http.MethodPatch, path, headers, bodyBytes)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "should fail with tampered method")

	// 9. Host WITHOUT public key should NOT require signature
	hostPayloadNoKey := map[string]any{
		"unique_key": "unsigned-host",
		"labels":     map[string]string{"env": "open"},
	}
	res = sendTestRequest(t, app, http.MethodPost, "/hosts", nil, hostPayloadNoKey)
	assert.Equal(t, http.StatusCreated, res.StatusCode)
	var hostNoKey client.Host
	err = json.NewDecoder(res.Body).Decode(&hostNoKey)
	require.NoError(t, err)
	unsignedHostID := hostNoKey.ID

	reqPayloadUnsigned := map[string]any{
		"host_id": unsignedHostID,
		"payload": map[string]any{"data": "public"},
	}
	res = sendTestRequest(t, app, http.MethodPost, "/requests", nil, reqPayloadUnsigned)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "should succeed without signature for host without key")
}

func TestNonceReuse(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	pub, priv, _ := ed25519.GenerateKey(nil)
	hostPayload := map[string]any{
		"unique_key": "nonce-test",
		"public_key": hex.EncodeToString(pub),
	}
	res := sendTestRequest(t, app, http.MethodPost, "/hosts", nil, hostPayload)
	require.Equal(t, http.StatusCreated, res.StatusCode)
	host := decodeJSON[client.Host](t, res)

	reqPayload := map[string]any{
		"host_id": host.ID,
		"payload": map[string]any{"data": "nonce"},
	}
	bodyBytes, _ := json.Marshal(reqPayload)

	now := time.Now().Unix()
	timestamp := fmt.Sprintf("%d", now)
	nonce := "reused-nonce"

	sigBase64 := sign(priv, timestamp, nonce, http.MethodPost, "/requests", string(bodyBytes))

	headers := map[string]string{
		"X-Grantory-Timestamp": timestamp,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sigBase64,
	}

	// First use - success
	res = sendTestRequestRaw(t, app, http.MethodPost, "/requests", headers, bodyBytes)
	assert.Equal(t, http.StatusCreated, res.StatusCode)

	// Second use - fail
	res = sendTestRequestRaw(t, app, http.MethodPost, "/requests", headers, bodyBytes)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	body, _ := io.ReadAll(res.Body)
	assert.Contains(t, string(body), "replay detected")
}

// TestTimestampMonotonicity verifies that incoming request timestamps must be monotonic
// within a 30-second grace window to accommodate concurrent requests, and that the stored
// timestamp only advances forward.
func TestTimestampMonotonicity(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	pub, priv, _ := ed25519.GenerateKey(nil)
	hostPayload := map[string]any{
		"unique_key": "monotonic-test",
		"public_key": hex.EncodeToString(pub),
	}
	res := sendTestRequest(t, app, http.MethodPost, "/hosts", nil, hostPayload)
	require.Equal(t, http.StatusCreated, res.StatusCode)
	host := decodeJSON[client.Host](t, res)

	reqPayload := map[string]any{
		"host_id": host.ID,
		"payload": map[string]any{"data": "monotonic"},
	}
	bodyBytes, _ := json.Marshal(reqPayload)

	now := time.Now().Unix()

	// First request at 'now'
	timestamp := fmt.Sprintf("%d", now)
	nonce1 := "nonce1"
	sig1Base64 := sign(priv, timestamp, nonce1, http.MethodPost, "/requests", string(bodyBytes))
	headers1 := map[string]string{
		"X-Grantory-Timestamp": timestamp,
		"X-Grantory-Nonce":     nonce1,
		"X-Grantory-Signature": sig1Base64,
	}
	res = sendTestRequestRaw(t, app, http.MethodPost, "/requests", headers1, bodyBytes)
	assert.Equal(t, http.StatusCreated, res.StatusCode)

	// Second request at 'now - 10' (within 30s grace window) - should succeed
	inGraceTs := fmt.Sprintf("%d", now-10)
	nonce2 := "nonce2"
	sig2Base64 := sign(priv, inGraceTs, nonce2, http.MethodPost, "/requests", string(bodyBytes))
	headers2 := map[string]string{
		"X-Grantory-Timestamp": inGraceTs,
		"X-Grantory-Nonce":     nonce2,
		"X-Grantory-Signature": sig2Base64,
	}
	res = sendTestRequestRaw(t, app, http.MethodPost, "/requests", headers2, bodyBytes)
	assert.Equal(t, http.StatusCreated, res.StatusCode)

	// Third request at 'now - 35' (beyond 30s grace window) - should fail with timestamp regressed
	oldTs := fmt.Sprintf("%d", now-35)
	nonce3 := "nonce3"
	sig3Base64 := sign(priv, oldTs, nonce3, http.MethodPost, "/requests", string(bodyBytes))
	headers3 := map[string]string{
		"X-Grantory-Timestamp": oldTs,
		"X-Grantory-Nonce":     nonce3,
		"X-Grantory-Signature": sig3Base64,
	}
	res = sendTestRequestRaw(t, app, http.MethodPost, "/requests", headers3, bodyBytes)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	body, _ := io.ReadAll(res.Body)
	assert.Contains(t, string(body), "timestamp regressed")
}

func TestHostPublicKeyValidation(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	// 1. Invalid hex
	hostPayload := map[string]any{
		"unique_key": "invalid-hex",
		"public_key": "not-hex",
	}
	res := sendTestRequest(t, app, http.MethodPost, "/hosts", nil, hostPayload)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	body, _ := io.ReadAll(res.Body)
	assert.Contains(t, string(body), "must be hex")

	// 2. Wrong length
	hostPayload = map[string]any{
		"unique_key": "wrong-length",
		"public_key": "aabbcc",
	}
	res = sendTestRequest(t, app, http.MethodPost, "/hosts", nil, hostPayload)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	body, _ = io.ReadAll(res.Body)
	assert.Contains(t, string(body), "invalid public key size")
}

func TestRequireSignaturesEnforcement(t *testing.T) {
	t.Parallel()

	// Setup app manually to enable RequireSignatures
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	store, _ := storage.New(context.Background(), ":memory:")
	_ = store.Migrate(context.Background())
	svc := apiservice.New(apiservice.NewStorageStore(store))
	srv := &Server{cfg: config.Config{RequireSignatures: true}}

	api := app.Group("/", func(c *fiber.Ctx) error {
		c.Locals(storeCtxKey, store)
		c.Locals(namespaceCtxKey, "default")
		c.Locals(requireSignaturesCtxKey, true)
		defer c.Locals(storeCtxKey, nil)
		return c.Next()
	})
	registerHostRoutes(api)
	registerRequestRoutes(api)

	defer func() { _ = store.Close() }()

	// 1. Create host without key - should be allowed to bootstrap
	hostPayload := map[string]any{"unique_key": "h1"}
	res := sendTestRequest(t, app, http.MethodPost, "/hosts", nil, hostPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode)
	host := decodeJSON[client.Host](t, res)

	// 2. Try to create a request for this host WITHOUT signature - should fail
	reqPayload := map[string]any{
		"host_id": host.ID,
		"payload": map[string]any{"data": "forbidden"},
	}
	res = sendTestRequest(t, app, http.MethodPost, "/requests", nil, reqPayload)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

	_ = svc
	_ = srv
}

type mockRecordSignatureStore struct {
	storage.Store
	recordErr error
}

func (m *mockRecordSignatureStore) RecordSignature(ctx context.Context, hostID string, timestamp int64, nonce string, expiresAt time.Time) error {
	return m.recordErr
}

func TestVerifySignatureMiddleware_FiberErrorPropagation(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	pubHex := hex.EncodeToString(pub)

	baseStore, err := storage.New(context.Background(), ":memory:")
	require.NoError(t, err)
	defer func() { _ = baseStore.Close() }()
	require.NoError(t, baseStore.Migrate(context.Background()))

	host, err := baseStore.CreateHost(context.Background(), storage.Host{
		UniqueKey: "sig-err-host",
		PublicKey: pubHex,
	})
	require.NoError(t, err)

	mockStore := &mockRecordSignatureStore{
		Store:     baseStore,
		recordErr: fiber.NewError(fiber.StatusServiceUnavailable, "cluster leader failover in progress"),
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	api := app.Group("/", func(c *fiber.Ctx) error {
		c.Locals(storeCtxKey, mockStore)
		c.Locals(namespaceCtxKey, "default")
		c.Locals(requireSignaturesCtxKey, true)
		defer c.Locals(storeCtxKey, nil)
		return c.Next()
	})
	registerRequestRoutes(api)

	ts := fmt.Sprintf("%d", time.Now().Unix())
	nonce := "test-fiber-err-nonce"
	reqPayload := `{"host_id":"` + host.ID + `","payload":{"action":"test"}}`
	sig := sign(priv, ts, nonce, http.MethodPost, "/requests", reqPayload)

	headers := map[string]string{
		"X-Grantory-Timestamp": ts,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sig,
	}

	// 1. When RecordSignature returns *fiber.Error (e.g. 503), it should propagate cleanly
	res := sendTestRequestRaw(t, app, http.MethodPost, "/requests", headers, []byte(reqPayload))
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)

	// 2. When RecordSignature returns a generic error, it falls back to 500
	mockStore.recordErr = errors.New("database disk full")
	sig2 := sign(priv, ts, "nonce-2", http.MethodPost, "/requests", reqPayload)
	headers["X-Grantory-Nonce"] = "nonce-2"
	headers["X-Grantory-Signature"] = sig2
	res2 := sendTestRequestRaw(t, app, http.MethodPost, "/requests", headers, []byte(reqPayload))
	assert.Equal(t, http.StatusInternalServerError, res2.StatusCode)
}

func TestSignatureVerificationBundledClusteredMode(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	pubHex := hex.EncodeToString(pub)

	baseStore, err := storage.New(context.Background(), ":memory:")
	require.NoError(t, err)
	defer func() { _ = baseStore.Close() }()
	require.NoError(t, baseStore.Migrate(context.Background()))

	host, err := baseStore.CreateHost(context.Background(), storage.Host{
		UniqueKey: "sig-bundled-host",
		PublicKey: pubHex,
	})
	require.NoError(t, err)

	mutator := raft.NewMutator(baseStore)
	proposer := &mockProposer{
		dispatch: mutator,
	}
	raftStore := newRaftStore(baseStore, proposer, "default")
	assert.True(t, raftStore.SupportsSignatureBundling())

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	api := app.Group("/", func(c *fiber.Ctx) error {
		c.Locals(storeCtxKey, raftStore)
		c.Locals(namespaceCtxKey, "default")
		c.Locals(requireSignaturesCtxKey, true)
		defer c.Locals(storeCtxKey, nil)
		return c.Next()
	})
	registerRequestRoutes(api)

	now := time.Now().Unix()
	tsStr := fmt.Sprintf("%d", now)
	nonce := "nonce-bundled-single-proposal"
	reqPayload := `{"host_id":"` + host.ID + `","payload":{"action":"run"}}`
	sig := sign(priv, tsStr, nonce, http.MethodPost, "/requests", reqPayload)

	headers := map[string]string{
		"X-Grantory-Timestamp": tsStr,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sig,
	}

	// 1. Initial signed write request executes in exactly ONE Raft proposal
	res := sendTestRequestRaw(t, app, http.MethodPost, "/requests", headers, []byte(reqPayload))
	assert.Equal(t, http.StatusCreated, res.StatusCode)
	assert.Equal(t, 1, proposer.proposals, "expected exactly 1 Raft proposal (bundled signature), not 2")
	require.NotNil(t, proposer.lastCmd.Signature, "bundled signature should be present on Raft command")
	assert.Equal(t, host.ID, proposer.lastCmd.Signature.HostID)
	assert.Equal(t, now, proposer.lastCmd.Signature.Timestamp)
	assert.Equal(t, nonce, proposer.lastCmd.Signature.Nonce)
	assert.False(t, proposer.lastCmd.Signature.ExpiresAt.IsZero())

	// 2. Replay of same nonce must fail with HTTP 401 Unauthorized ("replay detected: nonce already used")
	resReplay := sendTestRequestRaw(t, app, http.MethodPost, "/requests", headers, []byte(reqPayload))
	assert.Equal(t, http.StatusUnauthorized, resReplay.StatusCode)
	bodyBytes, _ := io.ReadAll(resReplay.Body)
	assert.Contains(t, string(bodyBytes), "replay detected: nonce already used")
	assert.Equal(t, 2, proposer.proposals, "replay proposed to Raft and rejected by Mutator.Dispatch")

	// 3. Timestamp regression beyond grace period must fail with HTTP 401 Unauthorized ("timestamp regressed")
	regressedTs := fmt.Sprintf("%d", now-45)
	regressedNonce := "nonce-regressed-ts"
	sigRegressed := sign(priv, regressedTs, regressedNonce, http.MethodPost, "/requests", reqPayload)
	headersRegressed := map[string]string{
		"X-Grantory-Timestamp": regressedTs,
		"X-Grantory-Nonce":     regressedNonce,
		"X-Grantory-Signature": sigRegressed,
	}
	resRegressed := sendTestRequestRaw(t, app, http.MethodPost, "/requests", headersRegressed, []byte(reqPayload))
	assert.Equal(t, http.StatusUnauthorized, resRegressed.StatusCode)
	bodyBytesRegressed, _ := io.ReadAll(resRegressed.Body)
	assert.Contains(t, string(bodyBytesRegressed), "timestamp regressed")
}

func TestSignatureVerificationBundledDeleteRequest(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	pubHex := hex.EncodeToString(pub)

	baseStore, err := storage.New(context.Background(), ":memory:")
	require.NoError(t, err)
	defer func() { _ = baseStore.Close() }()
	require.NoError(t, baseStore.Migrate(context.Background()))

	host, err := baseStore.CreateHost(context.Background(), storage.Host{
		UniqueKey: "sig-delete-host",
		PublicKey: pubHex,
	})
	require.NoError(t, err)

	mutator := raft.NewMutator(baseStore)
	proposer := &mockProposer{
		dispatch: mutator,
	}
	raftStore := newRaftStore(baseStore, proposer, "default")

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	api := app.Group("/", func(c *fiber.Ctx) error {
		c.Locals(storeCtxKey, raftStore)
		c.Locals(namespaceCtxKey, "default")
		c.Locals(requireSignaturesCtxKey, true)
		defer c.Locals(storeCtxKey, nil)
		return c.Next()
	})
	registerRequestRoutes(api)

	// Create request directly in base store
	req, err := baseStore.CreateRequest(context.Background(), storage.Request{
		HostID:    host.ID,
		Payload:   map[string]any{"action": "delete-me"},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	proposer.proposals = 0

	now := time.Now().Unix()
	tsStr := fmt.Sprintf("%d", now)
	nonce := "nonce-delete-request"
	sig := sign(priv, tsStr, nonce, http.MethodDelete, "/requests/"+req.ID, "")

	headers := map[string]string{
		"X-Grantory-Timestamp": tsStr,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sig,
	}

	res := sendTestRequestRaw(t, app, http.MethodDelete, "/requests/"+req.ID, headers, nil)
	assert.Equal(t, http.StatusNoContent, res.StatusCode)
	assert.Equal(t, 1, proposer.proposals, "expected exactly 1 Raft proposal for delete")
	require.NotNil(t, proposer.lastCmd.Signature)
	assert.Equal(t, host.ID, proposer.lastCmd.Signature.HostID)
	assert.Equal(t, nonce, proposer.lastCmd.Signature.Nonce)
}

type customUnwrapDecorator struct {
	storage.Store
}

func (d *customUnwrapDecorator) Unwrap() storage.Store {
	return d.Store
}

func TestSignatureVerificationBundledCustomUnwrapDecorator(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	pubHex := hex.EncodeToString(pub)

	baseStore, err := storage.New(context.Background(), ":memory:")
	require.NoError(t, err)
	defer func() { _ = baseStore.Close() }()
	require.NoError(t, baseStore.Migrate(context.Background()))

	host, err := baseStore.CreateHost(context.Background(), storage.Host{
		UniqueKey: "sig-custom-unwrap-host",
		PublicKey: pubHex,
	})
	require.NoError(t, err)

	mutator := raft.NewMutator(baseStore)
	proposer := &mockProposer{
		dispatch: mutator,
	}
	raftStore := newRaftStore(baseStore, proposer, "default")
	wrappedStore := &customUnwrapDecorator{Store: raftStore}

	// Verify direct checkSignatureBundling on customUnwrapDecorator
	assert.True(t, checkSignatureBundling(wrappedStore), "checkSignatureBundling must resolve true through Unwrap() chain")

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	api := app.Group("/", func(c *fiber.Ctx) error {
		c.Locals(storeCtxKey, wrappedStore)
		c.Locals(namespaceCtxKey, "default")
		c.Locals(requireSignaturesCtxKey, true)
		defer c.Locals(storeCtxKey, nil)
		return c.Next()
	})
	registerRequestRoutes(api)

	now := time.Now().Unix()
	tsStr := fmt.Sprintf("%d", now)
	nonce := "nonce-custom-unwrap"
	reqPayload := `{"host_id":"` + host.ID + `","payload":{"action":"wrapped-bundle"}}`
	sig := sign(priv, tsStr, nonce, http.MethodPost, "/requests", reqPayload)

	headers := map[string]string{
		"X-Grantory-Timestamp": tsStr,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sig,
	}

	res := sendTestRequestRaw(t, app, http.MethodPost, "/requests", headers, []byte(reqPayload))
	assert.Equal(t, http.StatusCreated, res.StatusCode)
	assert.Equal(t, 1, proposer.proposals, "expected exactly 1 Raft proposal (bundled signature) with wrapped store")
	require.NotNil(t, proposer.lastCmd.Signature, "bundled signature should be present on Raft command")
	assert.Equal(t, host.ID, proposer.lastCmd.Signature.HostID)
	assert.Equal(t, now, proposer.lastCmd.Signature.Timestamp)
	assert.Equal(t, nonce, proposer.lastCmd.Signature.Nonce)
}

func TestCheckSignatureBundling_Stores(t *testing.T) {
	t.Parallel()

	// 1. sqliteStore directly and via unclosableStore
	sqliteStore, err := storage.New(context.Background(), ":memory:")
	require.NoError(t, err)
	defer func() { _ = sqliteStore.Close() }()

	assert.True(t, checkSignatureBundling(sqliteStore), "sqliteStore should support signature bundling")
	assert.True(t, checkSignatureBundling(unclosableStore{Store: sqliteStore}), "unclosableStore wrapping sqliteStore should support signature bundling")

	// 2. postgresStore directly and via unclosableStore
	pgStore := storage.NewPostgresFromDB(nil)
	assert.True(t, checkSignatureBundling(pgStore), "postgresStore should support signature bundling")
	assert.True(t, checkSignatureBundling(unclosableStore{Store: pgStore}), "unclosableStore wrapping postgresStore should support signature bundling")

	// 3. nil and non-bundling types
	assert.False(t, checkSignatureBundling(nil), "nil store should not support signature bundling")
	assert.False(t, checkSignatureBundling("unsupported"), "unsupported type should not support signature bundling")
	assert.False(t, checkSignatureBundling(customUnwrapDecorator{Store: nil}), "unwrapping to nil should not support signature bundling")
}

func TestStandaloneSignatureBundling_RollbackOnFailedMutation(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	pubHex := hex.EncodeToString(pub)

	// Create host
	res := sendTestRequest(t, app, http.MethodPost, "/hosts", nil, map[string]any{
		"unique_key": "rollback-test-host",
		"public_key": pubHex,
	})
	require.Equal(t, http.StatusCreated, res.StatusCode)
	var host client.Host
	require.NoError(t, json.NewDecoder(res.Body).Decode(&host))

	// Pre-create a request with unique_key "req-unique-conflict" with valid signature
	now := time.Now().Unix()
	tsStr := fmt.Sprintf("%d", now)
	initPayload := `{"host_id":"` + host.ID + `","unique_key":"req-unique-conflict","payload":{"data":"initial"}}`
	initSig := sign(priv, tsStr, "nonce-initial", http.MethodPost, "/requests", initPayload)
	initHeaders := map[string]string{
		"X-Grantory-Timestamp": tsStr,
		"X-Grantory-Nonce":     "nonce-initial",
		"X-Grantory-Signature": initSig,
	}
	res = sendTestRequestRaw(t, app, http.MethodPost, "/requests", initHeaders, []byte(initPayload))
	require.Equal(t, http.StatusCreated, res.StatusCode)

	// Send a signed request that triggers a unique_key duplicate conflict on storage.CreateRequest
	now = time.Now().Unix()
	tsStr = fmt.Sprintf("%d", now)
	nonce := "nonce-rollback-standalone"
	failingPayload := `{"host_id":"` + host.ID + `","unique_key":"req-unique-conflict","payload":{"data":"should-rollback"}}`
	sigFailing := sign(priv, tsStr, nonce, http.MethodPost, "/requests", failingPayload)

	headersFailing := map[string]string{
		"X-Grantory-Timestamp": tsStr,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sigFailing,
	}

	resConflict := sendTestRequestRaw(t, app, http.MethodPost, "/requests", headersFailing, []byte(failingPayload))
	assert.Equal(t, http.StatusConflict, resConflict.StatusCode)

	// Because signature bundling is enabled in standalone SQLite mode, the nonce was rolled back!
	// Re-sending with the SAME nonce and timestamp for a valid non-conflicting mutation must succeed.
	validPayload := `{"host_id":"` + host.ID + `","unique_key":"req-unique-success","payload":{"data":"success"}}`
	sigValid := sign(priv, tsStr, nonce, http.MethodPost, "/requests", validPayload)
	headersValid := map[string]string{
		"X-Grantory-Timestamp": tsStr,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sigValid,
	}

	resSuccess := sendTestRequestRaw(t, app, http.MethodPost, "/requests", headersValid, []byte(validPayload))
	assert.Equal(t, http.StatusCreated, resSuccess.StatusCode, "mutation with same nonce must succeed because previous failed mutation rolled back nonce")

	// Third attempt with the same nonce must now fail with 401 Unauthorized because the successful mutation committed it
	resReplay := sendTestRequestRaw(t, app, http.MethodPost, "/requests", headersValid, []byte(validPayload))
	assert.Equal(t, http.StatusUnauthorized, resReplay.StatusCode)
	bodyBytes, _ := io.ReadAll(resReplay.Body)
	assert.Contains(t, string(bodyBytes), "replay detected: nonce already used")
}

func TestVerifySignatureMiddleware_FallbackStorageErrors(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	pubHex := hex.EncodeToString(pub)

	baseStore, err := storage.New(context.Background(), ":memory:")
	require.NoError(t, err)
	defer func() { _ = baseStore.Close() }()
	require.NoError(t, baseStore.Migrate(context.Background()))

	host, err := baseStore.CreateHost(context.Background(), storage.Host{
		UniqueKey: "sig-fallback-err-host",
		PublicKey: pubHex,
	})
	require.NoError(t, err)

	mockStore := &mockRecordSignatureStore{
		Store: baseStore,
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	api := app.Group("/", func(c *fiber.Ctx) error {
		c.Locals(storeCtxKey, mockStore)
		c.Locals(namespaceCtxKey, "default")
		c.Locals(requireSignaturesCtxKey, true)
		defer c.Locals(storeCtxKey, nil)
		return c.Next()
	})
	registerRequestRoutes(api)

	ts := fmt.Sprintf("%d", time.Now().Unix())
	reqPayload := `{"host_id":"` + host.ID + `","payload":{"action":"test"}}`

	// 1. When RecordSignature returns storage.ErrReplayDetected, return 401 Unauthorized
	mockStore.recordErr = storage.ErrReplayDetected
	sigReplay := sign(priv, ts, "nonce-replay", http.MethodPost, "/requests", reqPayload)
	headersReplay := map[string]string{
		"X-Grantory-Timestamp": ts,
		"X-Grantory-Nonce":     "nonce-replay",
		"X-Grantory-Signature": sigReplay,
	}
	resReplay := sendTestRequestRaw(t, app, http.MethodPost, "/requests", headersReplay, []byte(reqPayload))
	assert.Equal(t, http.StatusUnauthorized, resReplay.StatusCode)
	bodyBytes, err := io.ReadAll(resReplay.Body)
	require.NoError(t, err)
	assert.Contains(t, string(bodyBytes), "replay detected: nonce already used")

	// 2. When RecordSignature returns storage.ErrTimestampRegressed, return 401 Unauthorized
	mockStore.recordErr = storage.ErrTimestampRegressed
	sigRegressed := sign(priv, ts, "nonce-regressed", http.MethodPost, "/requests", reqPayload)
	headersRegressed := map[string]string{
		"X-Grantory-Timestamp": ts,
		"X-Grantory-Nonce":     "nonce-regressed",
		"X-Grantory-Signature": sigRegressed,
	}
	resRegressed := sendTestRequestRaw(t, app, http.MethodPost, "/requests", headersRegressed, []byte(reqPayload))
	assert.Equal(t, http.StatusUnauthorized, resRegressed.StatusCode)
	bodyBytes, err = io.ReadAll(resRegressed.Body)
	require.NoError(t, err)
	assert.Contains(t, string(bodyBytes), "timestamp regressed")
}
