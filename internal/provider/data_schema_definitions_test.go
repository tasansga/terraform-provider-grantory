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
				Schema:    json.RawMessage(`{"type":"object"}`),
				CreatedAt: createdAt,
			},
			{
				ID:        "schema-2",
				Schema:    json.RawMessage(`{"type":"object","required":["name"]}`),
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
}
