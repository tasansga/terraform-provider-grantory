package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	clienttest "github.com/tasansga/terraform-provider-grantory/internal/api/client/testutil"
)

func TestDataHostsSource(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC)
	handler := newHostsDataSourceTestHandler([]apiHost{
		{
			ID:        "host-2",
			UniqueKey: "unique:host-2",
			Labels:    map[string]string{"env": "dev"},
			CreatedAt: createdAt,
		},
		{
			ID:        "host-1",
			UniqueKey: "unique:host-1",
			Labels:    map[string]string{"env": "prod"},
			CreatedAt: createdAt,
		},
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := dataHosts()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from hosts data read")

	hostIDs, ok := data.Get("hosts").([]any)
	assert.True(t, ok, "hosts should be a list")
	assert.Len(t, hostIDs, 2, "expected two host entries")

	expectedIDs := []string{"host-1", "host-2"}
	for i, id := range expectedIDs {
		assert.Equal(t, id, hostIDs[i], "host IDs should stay sorted")
	}

	expectedID, err := hashAsJSON(map[string]any{
		"labels": map[string]string(nil),
		"hosts":  expectedIDs,
	})
	assert.NoError(t, err, "hash hosts")
	assert.Equal(t, expectedID, data.Id(), "id should reflect host list hash")
}

func TestDataHostsSourceLabels(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC)
	handler := newHostsDataSourceTestHandler([]apiHost{
		{
			ID:        "host-1",
			UniqueKey: "unique:host-1",
			Labels:    map[string]string{"env": "prod"},
			CreatedAt: createdAt,
		},
		{
			ID:        "host-2",
			UniqueKey: "unique:host-2",
			Labels:    map[string]string{"env": "dev"},
			CreatedAt: createdAt,
		},
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := dataHosts()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"labels": map[string]any{
			"env": "prod",
		},
	})

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from hosts data read")

	hostIDs, ok := data.Get("hosts").([]any)
	assert.True(t, ok, "hosts should be a list")
	assert.Equal(t, []any{"host-1"}, hostIDs, "hosts should match labels filter")

	expectedID, err := hashAsJSON(map[string]any{
		"labels": map[string]string{"env": "prod"},
		"hosts":  []string{"host-1"},
	})
	assert.NoError(t, err, "hash hosts")
	assert.Equal(t, expectedID, data.Id(), "id should reflect host list hash")

	query := handler.lastQuery()
	_, hasLabel := query["label"]
	assert.False(t, hasLabel, "hosts endpoint should not submit label query")
}

func newHostsDataSourceTestHandler(response []apiHost) *hostsDataSourceTestHandler {
	return &hostsDataSourceTestHandler{
		response: response,
	}
}

type hostsDataSourceTestHandler struct {
	mu       sync.Mutex
	last     url.Values
	response []apiHost
}

func (h *hostsDataSourceTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.last = r.URL.Query()
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.response)
}

func (h *hostsDataSourceTestHandler) lastQuery() url.Values {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last
}
