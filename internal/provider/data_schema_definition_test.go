package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

func TestDataSchemaDefinitionSource(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/schema-definitions/") {
			http.NotFound(w, r)
			return
		}
		defID := strings.TrimPrefix(r.URL.Path, "/schema-definitions/")
		if defID == "" {
			http.Error(w, "missing schema definition", http.StatusBadRequest)
			return
		}

		resp := apiSchemaDefinition{
			ID:            defID,
			RequestSchema: json.RawMessage(`{"type":"object"}`),
			GrantSchema:   json.RawMessage(`{"type":"object","required":["detail"]}`),
			CreatedAt:     "2024-02-02T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &grantoryClient{
		baseURL:    mustParseURL(t, server.URL),
		httpClient: server.Client(),
	}

	resource := dataSchemaDefinition()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"schema_definition_id": "schema-123",
	})

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from schema definition data read")
	assert.Equal(t, "schema-123", data.Id(), "schema definition id should be set")

	requestSchema, ok := data.Get("request_schema").(string)
	assert.True(t, ok, "request_schema should be a string")
	assert.JSONEq(t, `{"type":"object"}`, requestSchema, "request_schema should match payload")
	grantSchema, ok := data.Get("grant_schema").(string)
	assert.True(t, ok, "grant_schema should be a string")
	assert.JSONEq(t, `{"type":"object","required":["detail"]}`, grantSchema, "grant_schema should match payload")
}
