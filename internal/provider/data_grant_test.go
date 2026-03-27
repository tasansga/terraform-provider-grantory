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
	clienttest "github.com/tasansga/terraform-provider-grantory/api/client/testutil"
)

func TestDataGrantSource(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(newGrantDataSourceTestHandler())
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := dataGrant()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"grant_id": "grant-123",
	})

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from grant data read")
	assert.Equal(t, "grant-123", data.Id(), "id should be set from API grant id")
	assert.Equal(t, "req-123", data.Get("request_id"), "request_id should match payload")
	payloadValue, ok := data.Get("payload").(string)
	assert.True(t, ok, "payload should be a string")
	assert.JSONEq(t, `{"user":"alice"}`, payloadValue, "payload should match stored data")
}

func TestDataGrantSourceWithoutPayload(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(newGrantDataSourceTestHandler())
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := dataGrant()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"grant_id": "grant-no-payload",
	})

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "unexpected diagnostics from grant data read")
	assert.Equal(t, "grant-no-payload", data.Id(), "id should be set from API grant id")
	assert.Equal(t, "req-no-payload", data.Get("request_id"), "request_id should match payload")
	assert.Empty(t, data.Get("payload"), "payload should be empty when API payload is nil")
}

func TestDataGrantSourceNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(newGrantDataSourceTestHandler())
	defer server.Close()

	client := clienttest.New(t, server, "", "", "")

	resource := dataGrant()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]any{
		"grant_id": "missing-grant",
	})
	data.SetId("existing-state")

	assert.False(t, resource.ReadContext(context.Background(), data, client).HasError(), "read should not error for missing grant")
	assert.Empty(t, data.Id(), "id should be cleared when grant is not found")
}

func newGrantDataSourceTestHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/grants/") {
			http.NotFound(w, r)
			return
		}

		grantID := strings.TrimPrefix(r.URL.Path, "/grants/")
		if grantID == "missing-grant" {
			http.NotFound(w, r)
			return
		}

		createdAt := time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC)
		resp := apiGrant{
			ID:        grantID,
			CreatedAt: createdAt,
			UpdatedAt: createdAt,
		}
		switch grantID {
		case "grant-no-payload":
			resp.RequestID = "req-no-payload"
		default:
			resp.RequestID = "req-123"
			resp.Payload = map[string]any{"user": "alice"}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
