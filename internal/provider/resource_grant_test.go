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
	testGrantCreatedAt = time.Date(2024, 2, 2, 10, 0, 0, 0, time.UTC)
	testGrantUpdatedAt = time.Date(2024, 2, 2, 10, 0, 0, 0, time.UTC)
	testGrantID        = "grant-123"
)

func TestResourceGrantLifecycle(t *testing.T) {
	t.Parallel()

	server := newGrantTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

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

	client := clienttest.New(t, server, "", "", "")

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

	client := clienttest.New(t, server, "", "", "")

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

	client := clienttest.New(t, server, "", "", "")

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
		requests: map[string]apiRequest{
			"req-123": {
				ID:      "req-123",
				HostID:  "host-123",
				Version: 1,
			},
		},
	}
	return httptest.NewServer(handler)
}

type grantTestHandler struct {
	mu       sync.Mutex
	grants   map[string]apiGrant
	requests map[string]apiRequest
}

func (h *grantTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/grants":
		h.handleCreate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/grants/"):
		h.handleGet(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/requests/"):
		h.handleGetRequest(w, r)
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
	if payload.RequestVersion <= 0 {
		http.Error(w, "missing request_version", http.StatusBadRequest)
		return
	}

	grant := apiGrant{
		ID:             testGrantID,
		RequestID:      payload.RequestID,
		RequestVersion: payload.RequestVersion,
		Payload:        payload.Payload,
		CreatedAt:      testGrantCreatedAt,
		UpdatedAt:      testGrantUpdatedAt,
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

func (h *grantTestHandler) handleGetRequest(w http.ResponseWriter, r *http.Request) {
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
