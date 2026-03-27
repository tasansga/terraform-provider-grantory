package testutil

import (
	"net/http/httptest"
	"testing"

	"github.com/tasansga/terraform-provider-grantory/api/client"
)

func New(t *testing.T, server *httptest.Server, token, user, password string) *client.Client {
	t.Helper()
	newClient, err := client.New(client.Options{
		BaseURL:    server.URL,
		Token:      token,
		User:       user,
		Password:   password,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("new test client: %v", err)
	}
	return newClient
}
