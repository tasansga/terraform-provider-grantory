package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

func TestConfigureProviderValidServer(t *testing.T) {
	t.Parallel()

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		serverAttr: "https://example.com",
	})

	client, diags := configureProvider(context.Background(), data)
	assert.False(t, diags.HasError(), "expected no diagnostics")

	c, ok := client.(*grantoryClient)
	assert.True(t, ok, "expected grantoryClient")
	assert.Equal(t, "https://example.com", c.BaseAddress(), "base address should match server URI")
}

func TestConfigureProviderInvalidServer(t *testing.T) {
	t.Parallel()

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		serverAttr: "ftp://example.com",
	})

	client, diags := configureProvider(context.Background(), data)
	assert.Nil(t, client, "expected nil client for invalid server")
	assert.True(t, diags.HasError(), "expected diagnostics for invalid server")

	found := false
	for _, diag := range diags {
		if diag.Summary == "unsupported grantory server scheme" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected unsupported scheme diagnostic")
}

func TestParseServerURLMissingHost(t *testing.T) {
	t.Parallel()

	_, diags := parseServerURL("http:///")
	assert.True(t, diags.HasError(), "missing host should produce diagnostic")
}

func TestConfigureProviderConflictingAuth(t *testing.T) {
	t.Parallel()

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		serverAttr:   "https://example.com",
		tokenAttr:    "token",
		userAttr:     "user",
		passwordAttr: "pass",
	})

	client, diags := configureProvider(context.Background(), data)
	assert.Nil(t, client, "expected nil client when auth conflicts")
	assert.True(t, diags.HasError(), "expected diag for conflicting auth")
}

func TestConfigureProviderIncompleteBasicAuth(t *testing.T) {
	t.Parallel()

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		serverAttr: "https://example.com",
		userAttr:   "user",
	})

	client, diags := configureProvider(context.Background(), data)
	assert.Nil(t, client, "expected nil client when password missing")
	assert.True(t, diags.HasError(), "expected diag for incomplete auth")
}

func TestGrantoryClientBaseAddressEmpty(t *testing.T) {
	t.Parallel()

	var c *grantoryClient
	assert.Equal(t, "", c.BaseAddress(), "nil client should return empty base address")
}
