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
	clienttest "github.com/tasansga/terraform-provider-grantory/internal/api/client/testutil"
)

var testHostCreatedAt = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

type hostLabelsPayload struct {
	Labels map[string]string `json:"labels"`
}

func TestResourceHostLifecycle(t *testing.T) {
	t.Parallel()

	server := newHostTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceHost()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"unique_key": "unique:host",
		"labels": map[string]any{
			"env": "test",
		},
	})

	assert.False(t, resource.CreateContext(context.Background(), data, client).HasError(), "unexpected diagnostics from create")
	assert.Equal(t, data.Id(), data.Get("host_id"), "host_id should expose generated ID")
	assert.Equal(t, "unique:host", data.Get("unique_key"), "unique_key should be set")

	labels, ok := data.Get("labels").(map[string]any)
	assert.True(t, ok, "labels should be a map")
	assert.Equal(t, "test", labels["env"], "labels env value")

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "read diagnostics")

	assert.False(t, resource.DeleteContext(context.Background(), data, client).HasError(), "delete diagnostics")

	assert.Empty(t, data.Id(), "id should be cleared after delete")
}

func TestResourceHostUpdatesLabels(t *testing.T) {
	t.Parallel()

	server := newHostTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceHost()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"labels": map[string]any{
			"env": "initial",
		},
	})

	assert.False(t, resource.CreateContext(context.Background(), data, client).HasError(), "create should succeed")
	originalID := data.Id()

	assert.False(t, resource.UpdateContext(context.Background(), data, client).HasError(), "no-op update succeeds")

	updatedLabels := map[string]any{"env": "updated"}
	assert.NoError(t, data.Set("labels", updatedLabels))
	assert.False(t, resource.UpdateContext(context.Background(), data, client).HasError(), "update succeeds")
	assert.Equal(t, originalID, data.Id(), "host_id should not change")
	labelsValue, ok := data.Get("labels").(map[string]any)
	assert.True(t, ok, "labels should still be a map")
	assert.Equal(t, "updated", labelsValue["env"], "labels should reflect changes")
}

func TestResourceHostReadNotFound(t *testing.T) {
	t.Parallel()

	server := newHostTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceHost()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)
	data.SetId("missing-host")

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "read should succeed even when not found")
	assert.Empty(t, data.Id(), "ID should be cleared when host missing")
}

func TestResourceHostDeleteNotFound(t *testing.T) {
	t.Parallel()

	server := newHostTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceHost()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)
	data.SetId("missing-host")

	assert.False(t, resource.DeleteContext(context.Background(), data, client).HasError(), "delete should not error when host missing")
	assert.Empty(t, data.Id(), "ID should remain empty after delete")
}

func newHostTestServer() *httptest.Server {
	handler := &hostTestHandler{
		hosts: make(map[string]apiHost),
	}
	return httptest.NewServer(handler)
}

type hostTestHandler struct {
	mu    sync.Mutex
	hosts map[string]apiHost
}

func (h *hostTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/hosts":
		h.handleCreate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/hosts/"):
		h.handleGet(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/hosts/"):
		h.handleDelete(w, r)
	case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/labels"):
		h.handlePatch(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *hostTestHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var payload apiHost
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if payload.ID == "" {
		payload.ID = "host-created"
	}

	payload.CreatedAt = testHostCreatedAt

	h.mu.Lock()
	h.hosts[payload.ID] = payload
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *hostTestHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/hosts/")

	h.mu.Lock()
	host, ok := h.hosts[id]
	h.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(host)
}

func (h *hostTestHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/hosts/")

	h.mu.Lock()
	_, ok := h.hosts[id]
	if ok {
		delete(h.hosts, id)
	}
	h.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *hostTestHandler) handlePatch(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/hosts/"), "/labels")

	h.mu.Lock()
	defer h.mu.Unlock()
	host, ok := h.hosts[id]
	if !ok {
		http.NotFound(w, r)
		return
	}

	var payload hostLabelsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	host.Labels = payload.Labels
	h.hosts[id] = host

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(host)
}
