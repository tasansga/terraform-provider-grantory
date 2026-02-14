package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

func TestDataRequestSource(t *testing.T) {
	t.Parallel()

	handler := newRequestDataSourceTestHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	client := &grantoryClient{
		baseURL:    mustParseURL(t, server.URL),
		httpClient: server.Client(),
	}

	resource := dataRequest()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"request_id": "req-123",
	})

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from request data read")

	assert.Equal(t, "host-123", data.Get("host_id"), "host_id should match payload")
	assert.True(t, data.Get("has_grant").(bool), "has_grant should be populated")
	payloadValue, ok := data.Get("payload").(string)
	assert.True(t, ok, "payload should be a string")
	assert.JSONEq(t, `{"name":"db"}`, payloadValue, "payload should match stored data")
	labelsValue, ok := data.Get("labels").(map[string]any)
	assert.True(t, ok, "labels should be a map")
	assert.Equal(t, map[string]any{"env": "prod"}, labelsValue, "labels should match stored data")
	assert.Equal(t, "grant-456", data.Get("grant_id"), "grant ID should be available")
	grantPayload, ok := data.Get("grant_payload").(string)
	assert.True(t, ok, "grant payload should be a string")
	assert.JSONEq(t, `{"user":"alice"}`, grantPayload, "grant payload should match stored grant")

}

func newRequestDataSourceTestHandler() *requestDataSourceTestHandler {
	return &requestDataSourceTestHandler{}
}

type requestDataSourceTestHandler struct {
	mu   sync.Mutex
	last url.Values
}

func (h *requestDataSourceTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.last = r.URL.Query()
	h.mu.Unlock()

	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/requests/") {
		http.NotFound(w, r)
		return
	}

	requestID := strings.TrimPrefix(r.URL.Path, "/requests/")
	if requestID == "" {
		http.Error(w, "missing request", http.StatusBadRequest)
		return
	}

	response := apiRequest{
		ID:       requestID,
		HostID:   "host-123",
		Payload:  map[string]any{"name": "db"},
		Labels:   map[string]string{"env": "prod"},
		HasGrant: true,
		GrantID:  "grant-456",
		Grant: &apiRequestGrant{
			GrantID: "grant-456",
			Payload: map[string]any{"user": "alice"},
		},
		CreatedAt: "2024-02-02T00:00:00Z",
		UpdatedAt: "2024-02-02T00:00:00Z",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
