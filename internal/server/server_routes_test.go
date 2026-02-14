package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

func newTestApp(t *testing.T) (*fiber.App, func()) {
	t.Helper()

	cfg := config.Config{DataDir: t.TempDir()}
	srv, err := New(context.Background(), cfg)
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}

	dataDir := filepath.Join(t.TempDir(), "api")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		if cerr := srv.Close(); cerr != nil {
			t.Errorf("close server: %v", cerr)
		}
		assert.NoError(t, err, "mkdir data dir")
		t.FailNow()
	}

	storePath := filepath.Join(dataDir, "cli-test.db")
	store, err := storage.New(context.Background(), storePath)
	if err != nil {
		if cerr := srv.Close(); cerr != nil {
			t.Errorf("close server: %v", cerr)
		}
		assert.NoError(t, err, "storage.New() error")
		t.FailNow()
	}
	store.SetNamespace(DefaultNamespace)

	if err := store.Migrate(context.Background()); err != nil {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("close store: %v", cerr)
		}
		if cerr := srv.Close(); cerr != nil {
			t.Errorf("close server: %v", cerr)
		}
		assert.NoError(t, err, "store.Migrate() error")
		t.FailNow()
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/healthz", srv.handleHealth)
	app.Get("/readyz", srv.handleReadiness)
	app.Use(requestLoggingMiddleware())

	api := app.Group("/", func(c *fiber.Ctx) error {
		namespace := c.Get("REMOTE_USER")
		if namespace == "" {
			namespace = DefaultNamespace
		}
		c.Locals(storeCtxKey, localStore{store: store})
		c.Locals(namespaceCtxKey, namespace)
		return c.Next()
	})
	registerHostRoutes(api)
	registerRequestRoutes(api)
	registerRegisterRoutes(api)
	registerGrantRoutes(api)
	api.Get("/metrics", srv.handleMetrics)

	cleanup := func() {
		if err := store.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
		if err := srv.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	}

	return app, cleanup
}

func sendTestRequest(t *testing.T, app *fiber.App, method, path string, headers map[string]string, body any) *http.Response {
	t.Helper()

	var buf io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			assert.NoError(t, err, "marshal body")
			t.FailNow()
		}
		buf = bytes.NewReader(data)
	}

	req := httptest.NewRequest(method, path, buf)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := app.Test(req)
	if err != nil {
		assert.NoError(t, err, "test request error")
		t.FailNow()
	}
	return res
}

func sendRawTestRequest(t *testing.T, app *fiber.App, method, path string, headers map[string]string, rawBody []byte) *http.Response {
	t.Helper()

	var buf io.Reader
	if len(rawBody) > 0 {
		buf = bytes.NewReader(rawBody)
	}

	req := httptest.NewRequest(method, path, buf)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if len(rawBody) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := app.Test(req)
	if err != nil {
		assert.NoError(t, err, "test request error")
		t.FailNow()
	}
	return res
}

func decodeJSON[T any](t *testing.T, res *http.Response) T {
	t.Helper()
	defer func() {
		if err := res.Body.Close(); err != nil {
			t.Errorf("close response body: %v", err)
		}
	}()

	var result T
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		assert.NoError(t, err, "decode response")
		t.FailNow()
	}
	return result
}

func TestAPIEndpoints(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	const namespaceHeader = "cli-user"
	headers := map[string]string{"REMOTE_USER": namespaceHeader}

	res := sendTestRequest(t, app, http.MethodGet, "/healthz", headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "healthz status")

	res = sendTestRequest(t, app, http.MethodGet, "/readyz", headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "readyz status")

	res = sendTestRequest(t, app, http.MethodGet, "/hosts", headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "list hosts status")
	hostsBefore := decodeJSON[[]storage.Host](t, res)
	assert.Len(t, hostsBefore, 0, "expected no hosts initially")

	hostPayload := map[string]any{"labels": map[string]string{"env": "test"}}
	res = sendTestRequest(t, app, http.MethodPost, "/hosts", headers, hostPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create host status")
	host := decodeJSON[storage.Host](t, res)
	res = sendTestRequest(t, app, http.MethodGet, fmt.Sprintf("/hosts/%s", host.ID), headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "get host status")
	decodeJSON[storage.Host](t, res)

	labelsUpdate := map[string]any{"labels": map[string]string{"env": "prod"}}
	res = sendTestRequest(t, app, http.MethodPatch, fmt.Sprintf("/hosts/%s/labels", host.ID), headers, labelsUpdate)
	assert.Equal(t, http.StatusOK, res.StatusCode, "update host labels status")
	updatedHost := decodeJSON[storage.Host](t, res)
	assert.Equal(t, "prod", updatedHost.Labels["env"], "labels should update")

	res = sendTestRequest(t, app, http.MethodGet, "/hosts", headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "list hosts status")
	hostsAfter := decodeJSON[[]storage.Host](t, res)
	assert.Len(t, hostsAfter, 1, "expected one host after creation")

	reqPayload := map[string]any{
		"host_id": host.ID,
		"payload": map[string]string{
			"name": "db request",
		},
	}
	res = sendTestRequest(t, app, http.MethodPost, "/requests", headers, reqPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create request status")
	req := decodeJSON[storage.Request](t, res)
	assert.Equal(t, host.ID, req.HostID, "request should reference host")
	assert.NotEmpty(t, req.ID, "request should report generated ID")
	reqID := req.ID

	res = sendTestRequest(t, app, http.MethodGet, "/requests", headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "list requests status")
	reqList := decodeJSON[[]storage.Request](t, res)
	assert.Len(t, reqList, 1, "expected one request")
	assert.Equal(t, reqID, reqList[0].ID, "listed request should match created ID")

	res = sendTestRequest(t, app, http.MethodGet, fmt.Sprintf("/requests/%s", reqID), headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "get request status")
	decodedReq := decodeJSON[storage.Request](t, res)
	assert.False(t, decodedReq.HasGrant, "new request should not yet have a grant")

	reqLabelUpdate := map[string]any{"labels": map[string]string{"env": "staging"}}
	res = sendTestRequest(t, app, http.MethodPatch, fmt.Sprintf("/requests/%s", reqID), headers, reqLabelUpdate)
	assert.Equal(t, http.StatusOK, res.StatusCode, "update request labels status")
	updatedReqLabels := decodeJSON[storage.Request](t, res)
	assert.Equal(t, "staging", updatedReqLabels.Labels["env"], "request labels should update")

	grantPayload := map[string]any{
		"request_id": reqID,
		"payload":    map[string]string{"detail": "payload"},
	}
	res = sendTestRequest(t, app, http.MethodPost, "/grants", headers, grantPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create grant status")
	grant := decodeJSON[storage.Grant](t, res)
	assert.Equal(t, reqID, grant.RequestID, "grant should reference request")
	assert.NotEmpty(t, grant.ID, "grant should expose generated ID")

	res = sendTestRequest(t, app, http.MethodGet, fmt.Sprintf("/requests/%s", reqID), headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "get request after grant")
	updatedReq := decodeJSON[requestResponse](t, res)
	assert.True(t, updatedReq.HasGrant, "request should report grant presence")
	if assert.NotNil(t, updatedReq.Grant, "grant payload should be included") {
		if payload, ok := updatedReq.Grant["detail"]; ok {
			assert.Equal(t, "payload", payload, "grant payload detail should match")
		}
	}

	regPayload := map[string]any{"host_id": host.ID, "payload": map[string]string{"ip": "10.1.1.1"}}
	res = sendTestRequest(t, app, http.MethodPost, "/registers", headers, regPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create register status")
	reg := decodeJSON[storage.Register](t, res)
	assert.NotEmpty(t, reg.ID, "register should expose generated ID")

	res = sendTestRequest(t, app, http.MethodGet, "/registers", headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "list registers status")
	regList := decodeJSON[[]storage.Register](t, res)
	assert.Len(t, regList, 1, "expected one register")

	res = sendTestRequest(t, app, http.MethodGet, fmt.Sprintf("/registers/%s", reg.ID), headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "get register status")
	getRegister := decodeJSON[storage.Register](t, res)
	assert.Equal(t, host.ID, getRegister.HostID, "register should reference host")

	labelUpdate := map[string]any{"labels": map[string]string{"env": "prod"}}
	res = sendTestRequest(t, app, http.MethodPatch, fmt.Sprintf("/registers/%s", reg.ID), headers, labelUpdate)
	assert.Equal(t, http.StatusOK, res.StatusCode, "update register status")
	updatedRegister := decodeJSON[storage.Register](t, res)
	assert.Equal(t, "prod", updatedRegister.Labels["env"], "register labels should update")

	delPayload := map[string]any{"host_id": host.ID, "payload": map[string]string{}}
	res = sendTestRequest(t, app, http.MethodPost, "/registers", headers, delPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create register for delete status")
	delReg := decodeJSON[storage.Register](t, res)
	res = sendTestRequest(t, app, http.MethodDelete, fmt.Sprintf("/registers/%s", delReg.ID), headers, nil)
	assert.Equal(t, http.StatusNoContent, res.StatusCode, "delete register status")
	res = sendTestRequest(t, app, http.MethodGet, fmt.Sprintf("/registers/%s", delReg.ID), headers, nil)
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "register should be missing after delete")

	res = sendTestRequest(t, app, http.MethodGet, "/grants", headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "list grants status")
	grants := decodeJSON[[]storage.Grant](t, res)
	assert.Len(t, grants, 1, "expected one grant")

	res = sendTestRequest(t, app, http.MethodGet, fmt.Sprintf("/grants/%s", grant.ID), headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "get grant status")
	getGrant := decodeJSON[storage.Grant](t, res)
	assert.Equal(t, reqID, getGrant.RequestID, "grant should reference the request")

	res = sendTestRequest(t, app, http.MethodDelete, fmt.Sprintf("/grants/%s", grant.ID), headers, nil)
	assert.Equal(t, http.StatusNoContent, res.StatusCode, "delete grant status")

	res = sendTestRequest(t, app, http.MethodGet, fmt.Sprintf("/grants/%s", grant.ID), headers, nil)
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "grant should be missing after delete")

	res = sendTestRequest(t, app, http.MethodDelete, fmt.Sprintf("/requests/%s", reqID), headers, nil)
	assert.Equal(t, http.StatusNoContent, res.StatusCode, "delete request status")

	res = sendTestRequest(t, app, http.MethodGet, fmt.Sprintf("/requests/%s", reqID), headers, nil)
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "request should be missing after delete")

	res = sendTestRequest(t, app, http.MethodGet, "/metrics", headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "metrics status")
	metrics := decodeJSON[map[string]map[string]int64](t, res)
	assert.Contains(t, metrics, "requests", "metrics should include requests")
	assert.Contains(t, metrics, "grants", "metrics should include grants")
	assert.Contains(t, metrics, "registers", "metrics should include registers")
	assert.EqualValues(t, 1, metrics["registers"]["total"], "register count")

	res = sendTestRequest(t, app, http.MethodDelete, fmt.Sprintf("/hosts/%s", host.ID), headers, nil)
	assert.Equal(t, http.StatusNoContent, res.StatusCode, "delete host status")
	res = sendTestRequest(t, app, http.MethodGet, fmt.Sprintf("/hosts/%s", host.ID), headers, nil)
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "host should be missing after delete")
}

func TestRequestHandlerListNoFilters(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	const namespaceHeader = "cli-user"
	headers := map[string]string{"REMOTE_USER": namespaceHeader}

	hostPayload := map[string]any{"labels": map[string]string{"env": "test"}}
	res := sendTestRequest(t, app, http.MethodPost, "/hosts", headers, hostPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create host status")
	host := decodeJSON[storage.Host](t, res)

	reqPayload := map[string]any{
		"host_id": host.ID,
		"payload": map[string]string{"name": "no-filter"},
	}
	res = sendTestRequest(t, app, http.MethodPost, "/requests", headers, reqPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create request status")
	created := decodeJSON[storage.Request](t, res)

	res = sendTestRequest(t, app, http.MethodGet, "/requests", headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "list requests status without filters")
	var reqList []storage.Request
	assert.NoError(t, json.NewDecoder(res.Body).Decode(&reqList), "decode requests list")
	assert.Len(t, reqList, 1, "should return created request even without has_grant")
	assert.Equal(t, created.ID, reqList[0].ID, "listed request ID should match created one")
}

func TestRequestGrantField(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	headers := map[string]string{"REMOTE_USER": "grant-field"}

	// ensure the host exists before creating the request
	hostPayload := map[string]any{"labels": map[string]string{}}
	res := sendTestRequest(t, app, http.MethodPost, "/hosts", headers, hostPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create host status")
	host := decodeJSON[storage.Host](t, res)

	reqPayload := map[string]any{
		"host_id": host.ID,
		"payload": map[string]string{"purpose": "grant-test"},
	}
	res = sendTestRequest(t, app, http.MethodPost, "/requests", headers, reqPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create request status")
	created := decodeJSON[storage.Request](t, res)
	reqID := created.ID

	res = sendTestRequest(t, app, http.MethodGet, fmt.Sprintf("/requests/%s", reqID), headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "get request status")
	prereq := decodeJSON[map[string]any](t, res)
	grantValue, ok := prereq["grant"]
	assert.True(t, ok, "grant field should be present")
	assert.Nil(t, grantValue, "grant should be null before being applied")

	grantPayload := map[string]any{
		"request_id": reqID,
		"payload":    map[string]string{"detail": "payload"},
	}
	res = sendTestRequest(t, app, http.MethodPost, "/grants", headers, grantPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create grant status")

	res = sendTestRequest(t, app, http.MethodGet, fmt.Sprintf("/requests/%s", reqID), headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "get request after grant")
	applied := decodeJSON[map[string]any](t, res)
	grantValue, ok = applied["grant"]
	assert.True(t, ok, "grant field should still be present")
	grantPayloadValue, ok := grantValue.(map[string]any)
	assert.True(t, ok, "grant should be an object")
	if grantIDValue, ok := grantPayloadValue["grant_id"].(string); assert.True(t, ok, "grant should include grant_id") {
		assert.NotEmpty(t, grantIDValue, "grant_id should not be empty")
	}
	payloadValue, ok := grantPayloadValue["payload"].(map[string]any)
	assert.True(t, ok, "grant.payload should be an object")
	assert.Equal(t, "payload", payloadValue["detail"], "grant payload detail")
}

func TestRequestHandlerListWithFilters(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	headers := map[string]string{"REMOTE_USER": "filter-user"}
	hostPayload := map[string]any{"labels": map[string]string{"env": "filter"}}
	res := sendTestRequest(t, app, http.MethodPost, "/hosts", headers, hostPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create host status")
	host := decodeJSON[storage.Host](t, res)

	reqPayload := map[string]any{
		"host_id": host.ID,
		"payload": map[string]string{"name": "filtered"},
		"labels":  map[string]string{"env": "filter"},
	}
	res = sendTestRequest(t, app, http.MethodPost, "/requests", headers, reqPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create request status")

	res = sendTestRequest(t, app, http.MethodGet, "/requests?has_grant=false&label=env=filter", headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "filtered list should succeed")
	var reqList []storage.Request
	assert.NoError(t, json.NewDecoder(res.Body).Decode(&reqList), "decode requests list")
	assert.Len(t, reqList, 1, "should return filtered request")
}

func TestRequestHandlerListInvalidLabelFilter(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	headers := map[string]string{"REMOTE_USER": "label-error"}
	res := sendTestRequest(t, app, http.MethodGet, "/requests?label=badfilter", headers, nil)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "invalid label filter should fail")
}

func TestRequestHandlerListInvalidHasGrant(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	headers := map[string]string{"REMOTE_USER": "grant-error"}
	res := sendTestRequest(t, app, http.MethodGet, "/requests?has_grant=notbool", headers, nil)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "invalid has_grant should fail")
}

func TestHandlersRejectInvalidJSON(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	headers := map[string]string{"REMOTE_USER": "invalid-json"}
	invalid := []byte("{invalid")

	res := sendRawTestRequest(t, app, http.MethodPost, "/hosts", headers, invalid)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "host handler should reject bad json")

	res = sendRawTestRequest(t, app, http.MethodPost, "/requests", headers, invalid)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "request handler should reject bad json")

	res = sendRawTestRequest(t, app, http.MethodPost, "/registers", headers, invalid)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "register handler should reject bad json")

	res = sendRawTestRequest(t, app, http.MethodPost, "/grants", headers, invalid)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "grant handler should reject bad json")
}

func TestGrantHandlerMissingFields(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	headers := map[string]string{"REMOTE_USER": "grant-missing"}
	res := sendTestRequest(t, app, http.MethodPost, "/grants", headers, map[string]any{
		"payload": map[string]string{"detail": "value"},
	})
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "grant handler should require request_id")

	res = sendTestRequest(t, app, http.MethodPost, "/grants", headers, map[string]any{
		"request_id": "missing",
	})
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "grant handler should require payload")
}

func TestHandlersRejectEmptyLabelUpdates(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	headers := map[string]string{"REMOTE_USER": "label-validator"}
	hostPayload := map[string]any{"labels": map[string]string{"env": "test"}}
	res := sendTestRequest(t, app, http.MethodPost, "/hosts", headers, hostPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create host")
	host := decodeJSON[storage.Host](t, res)

	reqPayload := map[string]any{"host_id": host.ID, "payload": map[string]string{"name": "label"}}
	res = sendTestRequest(t, app, http.MethodPost, "/requests", headers, reqPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create request")
	req := decodeJSON[storage.Request](t, res)

	regPayload := map[string]any{"host_id": host.ID, "payload": map[string]string{"ip": "1.1.1.1"}}
	res = sendTestRequest(t, app, http.MethodPost, "/registers", headers, regPayload)
	assert.Equal(t, http.StatusCreated, res.StatusCode, "create register")
	reg := decodeJSON[storage.Register](t, res)

	emptyBody := map[string]any{}
	res = sendTestRequest(t, app, http.MethodPatch, fmt.Sprintf("/hosts/%s/labels", host.ID), headers, emptyBody)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "host update should require labels")

	res = sendTestRequest(t, app, http.MethodPatch, fmt.Sprintf("/requests/%s", req.ID), headers, emptyBody)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "request update should require labels")

	res = sendTestRequest(t, app, http.MethodPatch, fmt.Sprintf("/registers/%s", reg.ID), headers, emptyBody)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "register update should require labels")
}

func TestMissingResourcesReturnNotFound(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	headers := map[string]string{"REMOTE_USER": "missing-resource"}

	res := sendTestRequest(t, app, http.MethodGet, "/hosts/unknown", headers, nil)
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "missing host get should 404")
	res = sendTestRequest(t, app, http.MethodDelete, "/hosts/unknown", headers, nil)
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "missing host delete should 404")

	res = sendTestRequest(t, app, http.MethodGet, "/registers/unknown", headers, nil)
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "missing register get should 404")
	res = sendTestRequest(t, app, http.MethodDelete, "/registers/unknown", headers, nil)
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "missing register delete should 404")
	res = sendTestRequest(t, app, http.MethodPatch, "/registers/unknown", headers, map[string]any{"labels": map[string]string{"env": "x"}})
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "missing register update should 404")

	res = sendTestRequest(t, app, http.MethodGet, "/requests/unknown", headers, nil)
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "missing request get should 404")
	res = sendTestRequest(t, app, http.MethodDelete, "/requests/unknown", headers, nil)
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "missing request delete should 404")
	res = sendTestRequest(t, app, http.MethodPatch, "/requests/unknown", headers, map[string]any{"labels": map[string]string{"env": "x"}})
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "missing request update should 404")

	res = sendTestRequest(t, app, http.MethodDelete, "/grants/unknown", headers, nil)
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "missing grant delete should 404")
	res = sendTestRequest(t, app, http.MethodGet, "/grants/unknown", headers, nil)
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "missing grant get should 404")
}

func TestHandlersReturnInternalServerErrorWhenStoreClosed(t *testing.T) {
	t.Parallel()

	cfg := config.Config{DataDir: t.TempDir()}
	srv, err := New(context.Background(), cfg)
	require.NoError(t, err)
	defer func() {
		if err := srv.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	}()

	store, err := srv.nsStore.StoreFor(context.Background(), DefaultNamespace)
	require.NoError(t, err)
	require.NoError(t, store.Close())

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(requestLoggingMiddleware())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(storeCtxKey, localStore{store: store})
		c.Locals(namespaceCtxKey, DefaultNamespace)
		return c.Next()
	})
	registerHostRoutes(app)
	registerRequestRoutes(app)
	registerRegisterRoutes(app)
	registerGrantRoutes(app)

	headers := map[string]string{"REMOTE_USER": "cli-user"}
	scenarios := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPost, "/hosts", map[string]any{"labels": map[string]string{"env": "x"}}},
		{http.MethodGet, "/hosts", nil},
		{http.MethodGet, "/hosts/any", nil},
		{http.MethodPatch, "/hosts/any/labels", map[string]any{"labels": map[string]string{"env": "x"}}},
		{http.MethodDelete, "/hosts/any", nil},
		{http.MethodPost, "/requests", map[string]any{"host_id": "any"}},
		{http.MethodGet, "/requests", nil},
		{http.MethodGet, "/requests/any", nil},
		{http.MethodPatch, "/requests/any", map[string]any{"labels": map[string]string{"env": "x"}}},
		{http.MethodDelete, "/requests/any", nil},
		{http.MethodPost, "/registers", map[string]any{"host_id": "any"}},
		{http.MethodGet, "/registers", nil},
		{http.MethodGet, "/registers/any", nil},
		{http.MethodPatch, "/registers/any", map[string]any{"labels": map[string]string{"env": "x"}}},
		{http.MethodDelete, "/registers/any", nil},
		{http.MethodPost, "/grants", map[string]any{"request_id": "any", "payload": map[string]string{"x": "y"}}},
		{http.MethodGet, "/grants", nil},
		{http.MethodGet, "/grants/any", nil},
		{http.MethodDelete, "/grants/any", nil},
	}

	for _, scenario := range scenarios {
		res := sendTestRequest(t, app, scenario.method, scenario.path, headers, scenario.body)
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode, "%s %s should error when store closed", scenario.method, scenario.path)
	}
}

func TestRegisterHandlerListInvalidLabelFilter(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	headers := map[string]string{"REMOTE_USER": "register-filter"}
	res := sendTestRequest(t, app, http.MethodGet, "/registers?label=badfilter", headers, nil)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "invalid register label filter should fail")
}

func TestIndexHandler(t *testing.T) {
	t.Parallel()

	cfg := config.Config{DataDir: t.TempDir()}
	srv, err := New(context.Background(), cfg)
	require.NoError(t, err, "New() should succeed")
	defer func() {
		if err := srv.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	}()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(requestLoggingMiddleware())
	app.Use(srv.namespaceMiddleware())
	app.Get("/index.html", srv.handleIndex)

	headers := map[string]string{"REMOTE_USER": "cli-user"}
	res := sendTestRequest(t, app, http.MethodGet, "/index.html", headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "index handler should render page")
}

func TestRootRedirectsToIndex(t *testing.T) {
	t.Parallel()

	cfg := config.Config{DataDir: t.TempDir()}
	srv, err := New(context.Background(), cfg)
	require.NoError(t, err, "New() should succeed")
	defer func() {
		if err := srv.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	}()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/", srv.handleRoot)
	app.Get("/index.html", srv.handleIndex)

	headers := map[string]string{"REMOTE_USER": "cli-user"}
	res := sendTestRequest(t, app, http.MethodGet, "/", headers, nil)
	assert.Equal(t, http.StatusFound, res.StatusCode, "root should redirect to index")
	assert.Equal(t, "/index.html", res.Header.Get(fiber.HeaderLocation))
}

func TestWaterCSSServedFromStaticRoute(t *testing.T) {
	t.Parallel()

	cfg := config.Config{DataDir: t.TempDir()}
	srv, err := New(context.Background(), cfg)
	require.NoError(t, err, "New() should succeed")
	defer func() {
		if err := srv.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	}()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/static/water.min.css", srv.handleWaterCSS)

	res := sendTestRequest(t, app, http.MethodGet, "/static/water.min.css", nil, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "water.css should be served")
	assert.True(t, strings.HasPrefix(res.Header.Get("Content-Type"), "text/css"), "water.css content type should be css")
}

func TestCreateRequestMissingHostReturnsBadRequest(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	headers := map[string]string{"REMOTE_USER": "missing-host-request"}
	payload := map[string]any{
		"host_id": "absent-host",
		"payload": map[string]any{"name": "invalid"},
	}
	res := sendTestRequest(t, app, http.MethodPost, "/requests", headers, payload)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "missing host should fail with 400")
}

func TestCreateRegisterMissingHostReturnsBadRequest(t *testing.T) {
	t.Parallel()

	app, cleanup := newTestApp(t)
	defer cleanup()

	headers := map[string]string{"REMOTE_USER": "missing-host-register"}
	payload := map[string]any{"id": "reg-bad", "host_id": "absent-host"}
	res := sendTestRequest(t, app, http.MethodPost, "/registers", headers, payload)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "missing host should fail with 400")
}

func TestNamespaceValidationMiddleware(t *testing.T) {
	t.Parallel()

	cfg := config.Config{DataDir: t.TempDir()}
	srv, err := New(context.Background(), cfg)
	assert.NoError(t, err, "initialize server")
	defer func() {
		if err := srv.nsStore.Close(); err != nil {
			t.Errorf("close namespace store: %v", err)
		}
	}()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(srv.namespaceMiddleware())
	app.Get("/probe", func(c *fiber.Ctx) error {
		return c.Status(http.StatusOK).JSON(map[string]string{"status": "ok"})
	})

	headers := map[string]string{"REMOTE_USER": "bad space"}
	res := sendTestRequest(t, app, http.MethodGet, "/probe", headers, nil)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "invalid namespace should be rejected")
}
