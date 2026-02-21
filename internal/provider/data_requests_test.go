package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

func TestDataRequestsSource(t *testing.T) {
	t.Parallel()

	handler := newRequestsDataSourceTestHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	client := &grantoryClient{
		baseURL:    mustParseURL(t, server.URL),
		httpClient: server.Client(),
	}

	resource := dataRequests()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"has_grant": true,
		"labels": map[string]any{
			"env": "prod",
		},
		"host_labels": map[string]any{
			"role": "db",
		},
	})

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from requests data read")

	requests, ok := data.Get("requests").([]any)
	assert.True(t, ok, "requests should be a list")
	assert.Len(t, requests, 1, "expected single request entry")

	entry, ok := requests[0].(map[string]any)
	assert.True(t, ok, "request entry should be structured")
	assert.Equal(t, "host-123", entry["host_id"], "host_id should match filter")
	assert.True(t, entry["has_grant"].(bool), "has_grant should remain present")

	query := handler.lastQuery()
	labelValues := query["label"]
	assert.Equal(t, []string{"env=prod"}, labelValues, "expected label query")
	hostLabelValues := query["host_label"]
	assert.Equal(t, []string{"role=db"}, hostLabelValues, "expected host_label query")
	assert.Equal(t, "true", query.Get("has_grant"), "expected has_grant query")
}

func TestDataRequestsSourceNoFilters(t *testing.T) {
	t.Parallel()

	handler := newRequestsDataSourceTestHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	client := &grantoryClient{
		baseURL:    mustParseURL(t, server.URL),
		httpClient: server.Client(),
	}

	resource := dataRequests()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from requests data read")

	requests, ok := data.Get("requests").([]any)
	assert.True(t, ok, "requests should be a list")
	assert.Len(t, requests, 1, "expected single request entry")

	entry, ok := requests[0].(map[string]any)
	assert.True(t, ok, "request entry should be structured")
	assert.Equal(t, "req-outstanding", entry["request_id"], "request id should be exposed")

	query := handler.lastQuery()
	_, hasHost := query["has_grant"]
	assert.False(t, hasHost, "should not submit has_grant when absent")
}

func newRequestsDataSourceTestHandler() *requestsDataSourceTestHandler {
	return &requestsDataSourceTestHandler{}
}

type requestsDataSourceTestHandler struct {
	mu   sync.Mutex
	last url.Values
}

func (h *requestsDataSourceTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.last = r.URL.Query()
	h.mu.Unlock()

	response := []apiRequest{
		{
			ID:       "req-outstanding",
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
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (h *requestsDataSourceTestHandler) lastQuery() url.Values {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last
}
