package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

	// Second request at 'now - 10' - fail
	oldTs := fmt.Sprintf("%d", now-10)
	nonce2 := "nonce2"
	sig2Base64 := sign(priv, oldTs, nonce2, http.MethodPost, "/requests", string(bodyBytes))
	headers2 := map[string]string{
		"X-Grantory-Timestamp": oldTs,
		"X-Grantory-Nonce":     nonce2,
		"X-Grantory-Signature": sig2Base64,
	}
	res = sendTestRequestRaw(t, app, http.MethodPost, "/requests", headers2, bodyBytes)
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
	svc := apiservice.New(newServiceStoreAdapter(store))
	srv := &Server{cfg: config.Config{RequireSignatures: true}}

	api := app.Group("/", func(c *fiber.Ctx) error {
		c.Locals(storeCtxKey, localStore{store: store})
		c.Locals(namespaceCtxKey, "default")
		c.Locals(requireSignaturesCtxKey, true)
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
