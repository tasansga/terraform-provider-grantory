package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	clienttest "github.com/tasansga/terraform-provider-grantory/internal/api/client/testutil"
)

func TestGrantoryClientSetsAuthorizationHeader(t *testing.T) {
	t.Parallel()

	const token = "secret-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]any{})
	}))
	defer server.Close()

	client := clienttest.New(t, server, token, "", "")
	_, err := client.ListHosts(context.Background())
	assert.NoError(t, err)
}

func TestGrantoryClientSetsBasicAuth(t *testing.T) {
	t.Parallel()

	const user = "alice"
	const password = "s3cr3t"
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expected, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]any{})
	}))
	defer server.Close()

	client := clienttest.New(t, server, "", user, password)
	_, err := client.ListHosts(context.Background())
	assert.NoError(t, err)
}
