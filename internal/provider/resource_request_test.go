package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	clienttest "github.com/tasansga/terraform-provider-grantory/api/client/testutil"
)

var (
	testRequestCreatedAt = time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC)
	testRequestUpdatedAt = time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC)
	testRequestID        = "req-123"
)

func TestResourceRequestLifecycle(t *testing.T) {
	t.Parallel()

	server := newRequestTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceRequest()
	requestData := map[string]any{
		"name": "test-db",
	}
	requestDataJSON, _ := json.Marshal(requestData)
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"host_id": "host-abc",
		"payload": string(requestDataJSON),
		"labels": map[string]any{
			"env": "testing",
		},
	})

	assert.False(t, resource.CreateContext(context.Background(), data, client).HasError(), "unexpected diagnostics from create")

	assert.Equal(t, "req-123", data.Id(), "resource id should match generated request ID")

	rawPayload, _ := data.Get("payload").(string)
	assert.NotEmpty(t, rawPayload, "payload should be a JSON string")
	var parsedPayload map[string]any
	assert.NoError(t, json.Unmarshal([]byte(rawPayload), &parsedPayload), "payload should decode")
	assert.Equal(t, "test-db", parsedPayload["name"], "payload name value")

	hasGrant, _ := data.Get("has_grant").(bool)
	assert.False(t, hasGrant, "has_grant should be false before grant")
	_, grantOK := data.GetOk("grant_id")
	assert.False(t, grantOK, "grant_id should be absent before grant")
	payloadValue, _ := data.Get("grant_payload").(string)
	assert.Empty(t, payloadValue, "grant_payload should be empty before grant")

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "read diagnostics")

	assert.NoError(t, data.Set("labels", map[string]any{"env": "prod"}), "prepare label update")
	assert.False(t, resource.UpdateContext(context.Background(), data, client).HasError(), "update diagnostics")

	updatedLabels, _ := data.Get("labels").(map[string]any)
	assert.Equal(t, "prod", updatedLabels["env"], "labels should refresh after update")

	assert.False(t, resource.DeleteContext(context.Background(), data, client).HasError(), "delete diagnostics")

	assert.Empty(t, data.Id(), "id should be cleared after delete")
}

func TestResourceRequestReadNotFound(t *testing.T) {
	t.Parallel()

	server := newRequestTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceRequest()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)
	data.SetId("missing-request")

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "read should not error when request missing")
	assert.Empty(t, data.Id(), "id should clear after not found")
}

func TestResourceRequestDeleteNotFound(t *testing.T) {
	t.Parallel()

	server := newRequestTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceRequest()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)
	data.SetId("missing-request")

	assert.False(t, resource.DeleteContext(context.Background(), data, client).HasError(), "delete should not fail for missing request")
	assert.Empty(t, data.Id(), "id should remain empty")
}

func newRequestTestServer() *httptest.Server {
	handler := &requestTestHandler{
		requests: make(map[string]apiRequest),
	}
	return httptest.NewServer(handler)
}

type requestTestHandler struct {
	mu       sync.Mutex
	requests map[string]apiRequest
}

func (h *requestTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/requests":
		h.handleCreate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/requests/"):
		h.handleGet(w, r)
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/requests/"):
		h.handleUpdate(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/requests/"):
		h.handleDelete(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *requestTestHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var payload apiRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if payload.HostID == "" {
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}
	if payload.ID == "" {
		payload.ID = testRequestID
	}

	payload.HasGrant = false
	payload.CreatedAt = testRequestCreatedAt
	payload.UpdatedAt = testRequestUpdatedAt

	h.mu.Lock()
	h.requests[payload.ID] = payload
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *requestTestHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/requests/")

	h.mu.Lock()
	req, ok := h.requests[id]
	h.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(req)
}

func (h *requestTestHandler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/requests/")

	h.mu.Lock()
	req, ok := h.requests[id]
	h.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	var payload struct {
		Payload *map[string]any    `json:"payload"`
		Labels  *map[string]string `json:"labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if payload.Payload == nil && payload.Labels == nil {
		http.Error(w, "data or labels required", http.StatusBadRequest)
		return
	}

	if payload.Payload != nil {
		req.Payload = *payload.Payload
	}
	if payload.Labels != nil {
		req.Labels = *payload.Labels
	}
	req.UpdatedAt = testRequestUpdatedAt

	h.mu.Lock()
	h.requests[id] = req
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(req)
}

func (h *requestTestHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/requests/")

	h.mu.Lock()
	_, ok := h.requests[id]
	if ok {
		delete(h.requests, id)
	}
	h.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
