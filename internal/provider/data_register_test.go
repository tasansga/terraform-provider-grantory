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

func TestDataRegisterSource(t *testing.T) {
	t.Parallel()

	handler := newRegisterDataSourceTestHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	client := &grantoryClient{
		baseURL:    mustParseURL(t, server.URL),
		httpClient: server.Client(),
	}

	resource := dataRegister()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"register_id": "reg-123",
	})

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from register data read")

	assert.Equal(t, "host-123", data.Get("host_id"), "host_id should match payload")
	assert.Equal(t, "reg-123", data.Get("register_id"), "register_id should be preserved")
	payloadValue, ok := data.Get("payload").(string)
	assert.True(t, ok, "payload should be a string")
	assert.JSONEq(t, `{"ip":"10.1.1.1"}`, payloadValue, "payload should match stored data")
	labelsValue, ok := data.Get("labels").(map[string]any)
	assert.True(t, ok, "labels should be a map")
	assert.Equal(t, map[string]any{"env": "prod"}, labelsValue, "labels should match stored data")

}

func newRegisterDataSourceTestHandler() *registerDataSourceTestHandler {
	return &registerDataSourceTestHandler{}
}

type registerDataSourceTestHandler struct {
	mu   sync.Mutex
	last url.Values
}

func (h *registerDataSourceTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.last = r.URL.Query()
	h.mu.Unlock()

	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/registers/") {
		http.NotFound(w, r)
		return
	}

	registerID := strings.TrimPrefix(r.URL.Path, "/registers/")
	if registerID == "" {
		http.Error(w, "missing register", http.StatusBadRequest)
		return
	}

	response := apiRegister{
		ID:        registerID,
		HostID:    "host-123",
		Payload:   map[string]any{"ip": "10.1.1.1"},
		Labels:    map[string]string{"env": "prod"},
		CreatedAt: "2024-02-02T00:00:00Z",
		UpdatedAt: "2024-02-02T00:00:00Z",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
