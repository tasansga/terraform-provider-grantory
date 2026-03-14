package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	clienttest "github.com/tasansga/terraform-provider-grantory/internal/api/client/testutil"
)

func TestDataSchemaDefinitionsSource(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/schema-definitions" {
			http.NotFound(w, r)
			return
		}
		createdAt := time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC)
		resp := []apiSchemaDefinition{
			{
				ID:        "schema-1",
				UniqueKey: "invoice.v1",
				Schema:    json.RawMessage(`{"type":"object"}`),
				Labels:    map[string]string{"family": "invoice", "version": "1"},
				CreatedAt: createdAt,
			},
			{
				ID:        "schema-2",
				UniqueKey: "invoice.v2",
				Schema:    json.RawMessage(`{"type":"object","required":["name"]}`),
				Labels:    map[string]string{"family": "invoice", "version": "2"},
				CreatedAt: createdAt,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := dataSchemaDefinitions()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from schema definitions data read")
	defs, ok := data.Get("schema_definitions").([]any)
	assert.True(t, ok, "schema_definitions should be a list")
	assert.Len(t, defs, 2, "expected two schema definitions")
	first, ok := defs[0].(map[string]any)
	assert.True(t, ok, "schema definition entry should be structured")
	assert.Equal(t, "invoice.v1", first["unique_key"])
	assert.Equal(t, map[string]any{"family": "invoice", "version": "1"}, first["labels"])
}

func TestDataSchemaDefinitionsSourceFiltersByLabels(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/schema-definitions" {
			http.NotFound(w, r)
			return
		}
		createdAt := time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC)
		resp := []apiSchemaDefinition{
			{
				ID:        "schema-1",
				UniqueKey: "invoice.v1",
				Schema:    json.RawMessage(`{"type":"object"}`),
				Labels:    map[string]string{"family": "invoice", "version": "1"},
				CreatedAt: createdAt,
			},
			{
				ID:        "schema-2",
				UniqueKey: "user.v1",
				Schema:    json.RawMessage(`{"type":"object","required":["name"]}`),
				Labels:    map[string]string{"family": "user", "version": "1"},
				CreatedAt: createdAt,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")
	resource := dataSchemaDefinitions()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"labels": map[string]any{"family": "invoice"},
	})

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from schema definitions data read")
	defs, ok := data.Get("schema_definitions").([]any)
	assert.True(t, ok, "schema_definitions should be a list")
	assert.Len(t, defs, 1, "expected one schema definition after filtering")
}
