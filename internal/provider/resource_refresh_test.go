package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

func TestResourceRequestRefreshIncludesGrant(t *testing.T) {
	t.Parallel()

	resource := resourceRequest()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)

	payload := map[string]any{"detail": "info"}
	req := apiRequest{
		ID:       "req-1",
		HostID:   "host-1",
		HasGrant: true,
		GrantID:  "grant-1",
		Grant: &apiRequestGrant{
			GrantID: "grant-1",
			Payload: payload,
		},
	}

	diags := resourceRequestRefresh(context.Background(), data, req)
	assert.Empty(t, diags)
	assert.Equal(t, "grant-1", data.Get("grant_id"))
	assert.Equal(t, true, data.Get("has_grant"))
	assert.JSONEq(t, `{"detail":"info"}`, data.Get("grant_payload").(string))
}

func TestResourceGrantRefreshClearsPayload(t *testing.T) {
	t.Parallel()

	resource := resourceGrant()
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)

	grant := apiGrant{RequestID: "req-1"}
	diags := resourceGrantRefresh(context.Background(), data, grant)
	assert.Empty(t, diags)
	assert.Equal(t, "", data.Get("payload"))
}
