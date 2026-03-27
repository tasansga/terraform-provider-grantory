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
	clienttest "github.com/tasansga/terraform-provider-grantory/api/client/testutil"
)

func TestDataRegistersSource(t *testing.T) {
	t.Parallel()

	handler := newRegistersDataSourceTestHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := dataRegisters()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"labels": map[string]any{
			"env": "prod",
		},
		"host_labels": map[string]any{
			"role": "db",
		},
	})

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from registers data read")

	registers, ok := data.Get("registers").([]any)
	assert.True(t, ok, "registers should be a list")
	assert.Len(t, registers, 1, "expected single register entry")

	entry, ok := registers[0].(map[string]any)
	assert.True(t, ok, "register entry should be structured")
	assert.Equal(t, "host-123", entry["host_id"], "host_id should match filter")
	assert.Equal(t, "reg-123", entry["register_id"], "register id should be exposed")
	assert.Equal(t, "unique:reg", entry["unique_key"], "unique_key should be exposed")

	query := handler.lastQuery()
	labelValues := query["label"]
	assert.Equal(t, []string{"env=prod"}, labelValues, "expected label query")
	hostLabelValues := query["host_label"]
	assert.Equal(t, []string{"role=db"}, hostLabelValues, "expected host_label query")
}

func newRegistersDataSourceTestHandler() *registersDataSourceTestHandler {
	return &registersDataSourceTestHandler{}
}

type registersDataSourceTestHandler struct {
	mu   sync.Mutex
	last url.Values
}

func (h *registersDataSourceTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.last = r.URL.Query()
	h.mu.Unlock()

	createdAt := time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC)
	response := []apiRegister{
		{
			ID:        "reg-123",
			HostID:    "host-123",
			UniqueKey: "unique:reg",
			Payload:   map[string]any{"ip": "10.1.1.1"},
			Labels:    map[string]string{"env": "prod"},
			CreatedAt: createdAt,
			UpdatedAt: createdAt,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (h *registersDataSourceTestHandler) lastQuery() url.Values {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last
}
