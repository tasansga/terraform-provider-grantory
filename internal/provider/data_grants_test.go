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
	clienttest "github.com/tasansga/terraform-provider-grantory/api/client/testutil"
)

func TestDataGrantsSource(t *testing.T) {
	t.Parallel()

	handler := newGrantsDataSourceTestHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := dataGrants()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from grants data source")

	grants, ok := data.Get("grants").([]any)
	assert.True(t, ok, "grants should be a list")
	assert.Len(t, grants, 2, "expected two grant entries")

	first, ok := grants[0].(map[string]any)
	assert.True(t, ok, "grant entry should be structured")
	assert.Equal(t, "grant-pending", first["grant_id"])
	assert.Equal(t, "grant-pending", first["request_id"])

	expectedEntries := []grantListEntry{
		{GrantID: "grant-pending", RequestID: "grant-pending"},
		{GrantID: "grant-delivered", RequestID: "grant-delivered"},
	}
	expectedID, err := hashAsJSON(expectedEntries)
	assert.NoError(t, err, "hash grant list")
	assert.Equal(t, expectedID, data.Id(), "id should be hash of grants list")
}

type grantsDataSourceTestHandler struct{}

func newGrantsDataSourceTestHandler() *grantsDataSourceTestHandler {
	return &grantsDataSourceTestHandler{}
}

func (h *grantsDataSourceTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/grants" {
		createdAt := time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC)
		response := []apiGrant{
			{ID: "grant-pending", RequestID: "grant-pending", CreatedAt: createdAt, UpdatedAt: createdAt},
			{ID: "grant-delivered", RequestID: "grant-delivered", CreatedAt: createdAt, UpdatedAt: createdAt},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
		return
	}
	http.NotFound(w, r)
}
