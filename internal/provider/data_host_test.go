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

func TestDataHostSource(t *testing.T) {
	t.Parallel()

	handler := newHostDataSourceTestHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	client := &grantoryClient{
		baseURL:    mustParseURL(t, server.URL),
		httpClient: server.Client(),
	}

	resource := dataHost()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"host_id": "host-123",
	})

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from host data read")

	assert.Equal(t, "host-123", data.Get("host_id"), "host_id should be preserved")
	assert.Equal(t, "unique:host", data.Get("unique_key"), "unique_key should be preserved")
	labelsValue, ok := data.Get("labels").(map[string]any)
	assert.True(t, ok, "labels should be a map")
	assert.Equal(t, map[string]any{"env": "prod"}, labelsValue, "labels should match stored data")
}

func newHostDataSourceTestHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/hosts/") {
			http.NotFound(w, r)
			return
		}

		hostID := strings.TrimPrefix(r.URL.Path, "/hosts/")
		if hostID == "" {
			http.Error(w, "missing host", http.StatusBadRequest)
			return
		}

		response := apiHost{
			ID:        hostID,
			UniqueKey: "unique:host",
			Labels:    map[string]string{"env": "prod"},
			CreatedAt: "2024-02-02T00:00:00Z",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}
