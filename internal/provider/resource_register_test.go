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
	testRegisterCreatedAt = time.Date(2024, 2, 3, 10, 0, 0, 0, time.UTC)
	testRegisterUpdatedAt = time.Date(2024, 2, 3, 10, 0, 0, 0, time.UTC)
	testRegisterID        = "reg-123"
)

func TestResourceRegisterLifecycle(t *testing.T) {
	t.Parallel()

	server := newRegisterTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceRegister()
	registerData := map[string]any{
		"item": "test",
	}
	registerDataJSON, _ := json.Marshal(registerData)
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"host_id":    "host-abc",
		"unique_key": "unique:reg",
		"payload":    string(registerDataJSON),
		"mutable":    true,
		"labels": map[string]any{
			"env": "testing",
		},
	})

	assert.False(t, resource.CreateContext(context.Background(), data, client).HasError(), "unexpected diagnostics from create")

	assert.Equal(t, testRegisterID, data.Id(), "resource id should match server-generated id")
	assert.Equal(t, "unique:reg", data.Get("unique_key"), "unique_key should be set")
	assert.Equal(t, true, data.Get("mutable"), "mutable should round-trip")

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "read diagnostics")

	assert.NoError(t, data.Set("payload", `{"item":"prod"}`), "prepare payload update")
	assert.NoError(t, data.Set("labels", map[string]any{"env": "prod"}), "prepare label update")
	assert.False(t, resource.UpdateContext(context.Background(), data, client).HasError(), "update diagnostics")

	updatedPayload, _ := data.Get("payload").(string)
	var updatedPayloadJSON map[string]any
	assert.NoError(t, json.Unmarshal([]byte(updatedPayload), &updatedPayloadJSON), "updated payload should decode")
	assert.Equal(t, "prod", updatedPayloadJSON["item"], "payload should refresh after update")
	updatedLabels, _ := data.Get("labels").(map[string]any)
	assert.Equal(t, "prod", updatedLabels["env"], "labels should refresh after update")

	assert.NoError(t, data.Set("payload", ""), "prepare payload clear")
	assert.False(t, resource.UpdateContext(context.Background(), data, client).HasError(), "payload clear diagnostics")
	clearedPayload, _ := data.Get("payload").(string)
	if clearedPayload != "" {
		var clearedPayloadJSON map[string]any
		assert.NoError(t, json.Unmarshal([]byte(clearedPayload), &clearedPayloadJSON), "cleared payload should decode")
		assert.Len(t, clearedPayloadJSON, 0, "cleared payload should be empty object")
	}

	assert.False(t, resource.DeleteContext(context.Background(), data, client).HasError(), "delete diagnostics")

	assert.Empty(t, data.Id(), "id should be cleared after delete")
}

func TestResourceRegisterReadNotFound(t *testing.T) {
	t.Parallel()

	server := newRegisterTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceRegister()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)
	data.SetId("missing-register")

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "read should not error on missing register")
	assert.Empty(t, data.Id(), "ID should clear after not found")
}

func TestResourceRegisterDeleteNotFound(t *testing.T) {
	t.Parallel()

	server := newRegisterTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceRegister()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)
	data.SetId("missing-register")

	assert.False(t, resource.DeleteContext(context.Background(), data, client).HasError(), "delete should succeed even when register missing")
	assert.Empty(t, data.Id(), "ID should remain empty")
}

func newRegisterTestServer() *httptest.Server {
	handler := &registerTestHandler{
		registers: make(map[string]apiRegister),
	}
	return httptest.NewServer(handler)
}

type registerTestHandler struct {
	mu        sync.Mutex
	registers map[string]apiRegister
}

func (h *registerTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/registers":
		h.handleCreate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/registers/"):
		h.handleGet(w, r)
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/registers/"):
		h.handleUpdate(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/registers/"):
		h.handleDelete(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *registerTestHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var payload apiRegister
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if payload.HostID == "" {
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}
	if payload.UniqueKey == "" {
		http.Error(w, "missing unique_key", http.StatusBadRequest)
		return
	}

	payload.ID = testRegisterID
	payload.CreatedAt = testRegisterCreatedAt
	payload.UpdatedAt = testRegisterUpdatedAt

	h.mu.Lock()
	h.registers[payload.ID] = payload
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *registerTestHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/registers/")

	h.mu.Lock()
	reg, ok := h.registers[id]
	h.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(reg)
}

func (h *registerTestHandler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/registers/")

	h.mu.Lock()
	reg, ok := h.registers[id]
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
	if payload.Labels == nil && payload.Payload == nil {
		http.Error(w, "labels or payload are required", http.StatusBadRequest)
		return
	}

	if payload.Payload != nil {
		reg.Payload = *payload.Payload
	}
	if payload.Labels != nil {
		reg.Labels = *payload.Labels
	}
	reg.UpdatedAt = testRegisterUpdatedAt

	h.mu.Lock()
	h.registers[id] = reg
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(reg)
}

func (h *registerTestHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/registers/")

	h.mu.Lock()
	_, ok := h.registers[id]
	if ok {
		delete(h.registers, id)
	}
	h.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
