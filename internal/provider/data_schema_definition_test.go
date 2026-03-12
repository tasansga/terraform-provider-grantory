package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	clienttest "github.com/tasansga/terraform-provider-grantory/internal/api/client/testutil"
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

		createdAt := time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC)
		resp := apiSchemaDefinition{
			ID:        defID,
			Schema:    json.RawMessage(`{"type":"object"}`),
			CreatedAt: createdAt,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := dataSchemaDefinition()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"schema_definition_id": "schema-123",
	})

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from schema definition data read")
	assert.Equal(t, "schema-123", data.Id(), "schema definition id should be set")

	schemaValue, ok := data.Get("schema").(string)
	assert.True(t, ok, "schema should be a string")
	assert.JSONEq(t, `{"type":"object"}`, schemaValue, "schema should match payload")
}
