package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

const (
	testGrantCreatedAt = "2024-02-02T10:00:00Z"
	testGrantUpdatedAt = "2024-02-02T10:00:00Z"
	testGrantID        = "grant-123"
)

func TestResourceGrantLifecycle(t *testing.T) {
	t.Parallel()

	server := newGrantTestServer()
	defer server.Close()

	client := &grantoryClient{
		baseURL:    mustParseURL(t, server.URL),
		httpClient: server.Client(),
	}

	resource := resourceGrant()
	grantData := map[string]any{
		"user": "alice",
	}
	grantDataJSON, _ := json.Marshal(grantData)
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"request_id": "req-123",
		"payload":    string(grantDataJSON),
	})

	assert.False(t, resource.CreateContext(context.Background(), data, client).HasError(), "unexpected diagnostics from create")

	assert.Equal(t, testGrantID, data.Id(), "resource id should match server-generated id")

	payloadValue, ok := data.Get("payload").(string)
	assert.True(t, ok, "grant payload should be a string")
	var decoded map[string]any
	assert.NoError(t, json.Unmarshal([]byte(payloadValue), &decoded), "grant payload should decode")
	assert.Equal(t, "alice", decoded["user"], "grant payload user value")

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "read diagnostics")

	assert.False(t, resource.DeleteContext(context.Background(), data, client).HasError(), "delete diagnostics")

	assert.Empty(t, data.Id(), "id should be cleared after delete")
}

func TestResourceGrantReadNotFound(t *testing.T) {
	t.Parallel()

	server := newGrantTestServer()
	defer server.Close()

	client := &grantoryClient{
		baseURL:    mustParseURL(t, server.URL),
		httpClient: server.Client(),
	}

	resource := resourceGrant()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)
	data.SetId("missing-grant")

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "read should handle missing grant")
	assert.Empty(t, data.Id(), "id should clear after not found")
}

func TestResourceGrantDeleteNotFound(t *testing.T) {
	t.Parallel()

	server := newGrantTestServer()
	defer server.Close()

	client := &grantoryClient{
		baseURL:    mustParseURL(t, server.URL),
		httpClient: server.Client(),
	}

	resource := resourceGrant()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)
	data.SetId("missing-grant")

	assert.False(t, resource.DeleteContext(context.Background(), data, client).HasError(), "delete should handle missing grant")
	assert.Empty(t, data.Id(), "id should remain empty")
}

func TestResourceGrantCreateWithoutPayload(t *testing.T) {
	t.Parallel()

	server := newGrantTestServer()
	defer server.Close()

	client := &grantoryClient{
		baseURL:    mustParseURL(t, server.URL),
		httpClient: server.Client(),
	}

	resource := resourceGrant()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"request_id": "req-123",
	})

	assert.False(t, resource.CreateContext(context.Background(), data, client).HasError(), "create without payload should succeed")
	assert.Equal(t, testGrantID, data.Id(), "id should still be populated")
	_, ok := data.GetOk("payload")
	assert.False(t, ok, "payload should not be set when not provided")
}

func newGrantTestServer() *httptest.Server {
	handler := &grantTestHandler{
		grants: make(map[string]apiGrant),
	}
	return httptest.NewServer(handler)
}

type grantTestHandler struct {
	mu     sync.Mutex
	grants map[string]apiGrant
}

func (h *grantTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/grants":
		h.handleCreate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/grants/"):
		h.handleGet(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/grants/"):
		h.handleDelete(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *grantTestHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var payload apiGrantCreatePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if payload.RequestID == "" {
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}

	grant := apiGrant{
		ID:        testGrantID,
		RequestID: payload.RequestID,
		Payload:   payload.Payload,
		CreatedAt: testGrantCreatedAt,
		UpdatedAt: testGrantUpdatedAt,
	}

	h.mu.Lock()
	h.grants[testGrantID] = grant
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(grant)
}

func (h *grantTestHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/grants/")

	h.mu.Lock()
	grant, ok := h.grants[id]
	h.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(grant)
}

func (h *grantTestHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/grants/")

	h.mu.Lock()
	_, ok := h.grants[id]
	if ok {
		delete(h.grants, id)
	}
	h.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
