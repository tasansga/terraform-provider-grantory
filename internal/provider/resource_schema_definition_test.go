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

var (
	testSchemaDefinitionCreatedAt = time.Date(2024, 2, 4, 10, 0, 0, 0, time.UTC)
	testSchemaDefinitionID        = "schema-def-123"
)

func TestResourceSchemaDefinitionLifecycle(t *testing.T) {
	t.Parallel()

	server := newSchemaDefinitionTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceSchemaDefinition()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"unique_key": "invoice.v1",
		"schema":     `{"type":"object","properties":{"name":{"type":"string"}}}`,
		"labels": map[string]any{
			"family":  "invoice",
			"version": "1",
		},
	})

	assert.False(t, resource.CreateContext(context.Background(), data, client).HasError(), "unexpected diagnostics from create")
	assert.Equal(t, testSchemaDefinitionID, data.Id(), "resource id should match server-generated id")
	assert.JSONEq(t, `{"type":"object","properties":{"name":{"type":"string"}}}`, data.Get("schema").(string), "schema should refresh from API response")
	assert.Equal(t, "invoice.v1", data.Get("unique_key"), "unique_key should refresh from API response")
	assert.Equal(t, map[string]any{"family": "invoice", "version": "1"}, data.Get("labels"), "labels should refresh from API response")

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "read diagnostics")

	assert.NoError(t, data.Set("labels", map[string]any{"family": "invoice", "version": "2"}), "prepare labels update")
	assert.False(t, resource.UpdateContext(context.Background(), data, client).HasError(), "update diagnostics")
	assert.Equal(t, map[string]any{"family": "invoice", "version": "2"}, data.Get("labels"), "labels should refresh after update")

	assert.False(t, resource.DeleteContext(context.Background(), data, client).HasError(), "delete diagnostics")
	assert.Empty(t, data.Id(), "id should be cleared after delete")
}

func TestResourceSchemaDefinitionReadNotFound(t *testing.T) {
	t.Parallel()

	server := newSchemaDefinitionTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceSchemaDefinition()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)
	data.SetId("missing-schema-def")

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "read should not error on missing schema definition")
	assert.Empty(t, data.Id(), "ID should clear after not found")
}

func TestResourceSchemaDefinitionDeleteNotFound(t *testing.T) {
	t.Parallel()

	server := newSchemaDefinitionTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceSchemaDefinition()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)
	data.SetId("missing-schema-def")

	assert.False(t, resource.DeleteContext(context.Background(), data, client).HasError(), "delete should succeed even when schema definition missing")
	assert.Empty(t, data.Id(), "ID should remain empty")
}

func TestResourceSchemaDefinitionCreateInvalidSchema(t *testing.T) {
	t.Parallel()

	server := newSchemaDefinitionTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceSchemaDefinition()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"schema": `{"type":"object"`,
	})

	diags := resource.CreateContext(context.Background(), data, client)
	assert.True(t, diags.HasError(), "create should fail for invalid JSON")
	assert.Equal(t, "invalid schema", diags[0].Summary)
	assert.Empty(t, data.Id(), "id should not be set on failure")
}

func TestResourceSchemaDefinitionCreateEmptySchema(t *testing.T) {
	t.Parallel()

	server := newSchemaDefinitionTestServer()
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := resourceSchemaDefinition()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"schema": "  ",
	})

	diags := resource.CreateContext(context.Background(), data, client)
	assert.True(t, diags.HasError(), "create should fail for empty schema")
	assert.Equal(t, "schema is required", diags[0].Summary)
	assert.Empty(t, data.Id(), "id should not be set on failure")
}

func TestResourceSchemaDefinitionRefreshClearsLabelsWhenNil(t *testing.T) {
	t.Parallel()

	resource := resourceSchemaDefinition()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"schema": `{"type":"object"}`,
		"labels": map[string]any{"family": "invoice"},
	})

	diags := resourceSchemaDefinitionRefresh(data, apiSchemaDefinition{
		ID:     "schema-def-123",
		Schema: json.RawMessage(`{"type":"object"}`),
		Labels: nil,
	})
	assert.False(t, diags.HasError(), "refresh should succeed")
	assert.Equal(t, map[string]any{}, data.Get("labels"), "labels should be cleared when API omits labels")
}

func newSchemaDefinitionTestServer() *httptest.Server {
	handler := &schemaDefinitionTestHandler{
		defs: make(map[string]apiSchemaDefinition),
	}
	return httptest.NewServer(handler)
}

type schemaDefinitionTestHandler struct {
	mu   sync.Mutex
	defs map[string]apiSchemaDefinition
}

func (h *schemaDefinitionTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/schema-definitions":
		h.handleCreate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/schema-definitions/"):
		h.handleGet(w, r)
	case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/labels"):
		h.handleUpdateLabels(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/schema-definitions/"):
		h.handleDelete(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *schemaDefinitionTestHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var payload apiSchemaDefinitionCreatePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(payload.Schema) == 0 {
		http.Error(w, "missing schema", http.StatusBadRequest)
		return
	}

	def := apiSchemaDefinition{
		ID:        testSchemaDefinitionID,
		UniqueKey: payload.UniqueKey,
		Schema:    payload.Schema,
		Labels:    payload.Labels,
		CreatedAt: testSchemaDefinitionCreatedAt,
	}

	h.mu.Lock()
	h.defs[def.ID] = def
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(def)
}

func (h *schemaDefinitionTestHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/schema-definitions/")

	h.mu.Lock()
	def, ok := h.defs[id]
	h.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(def)
}

func (h *schemaDefinitionTestHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/schema-definitions/")

	h.mu.Lock()
	_, ok := h.defs[id]
	if ok {
		delete(h.defs, id)
	}
	h.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *schemaDefinitionTestHandler) handleUpdateLabels(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/schema-definitions/"), "/labels")

	h.mu.Lock()
	def, ok := h.defs[id]
	h.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	var payload struct {
		Labels *map[string]string `json:"labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if payload.Labels == nil {
		http.Error(w, "labels are required", http.StatusBadRequest)
		return
	}

	def.Labels = *payload.Labels
	h.mu.Lock()
	h.defs[id] = def
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(def)
}
