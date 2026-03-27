package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAuthValidation(t *testing.T) {
	t.Parallel()

	_, err := New(Options{
		BaseURL:  "http://localhost:8080",
		Token:    "token",
		User:     "alice",
		Password: "secret",
	})
	if err == nil {
		t.Fatalf("expected auth conflict error")
	}

	_, err = New(Options{
		BaseURL: "http://localhost:8080",
		User:    "alice",
	})
	if err == nil {
		t.Fatalf("expected incomplete basic auth error")
	}
}

func TestClientSetsBearerAndNamespaceHeaders(t *testing.T) {
	t.Parallel()

	const token = "secret-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		if got := r.Header.Get("REMOTE_USER"); got != "team-a" {
			t.Fatalf("unexpected REMOTE_USER header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]Host{})
	}))
	defer server.Close()

	c, err := New(Options{
		BaseURL:    server.URL,
		Token:      " " + token + " ",
		Namespace:  " team-a ",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if _, err := c.ListHosts(context.Background()); err != nil {
		t.Fatalf("list hosts: %v", err)
	}
}

func TestClientSetsBasicAuthHeader(t *testing.T) {
	t.Parallel()

	const user = "alice"
	const password = "s3cr3t"
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != expected {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]Host{})
	}))
	defer server.Close()

	c, err := New(Options{
		BaseURL:    server.URL,
		User:       user,
		Password:   password,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if _, err := c.ListHosts(context.Background()); err != nil {
		t.Fatalf("list hosts: %v", err)
	}
}

func TestClientPreservesBasicAuthPasswordWhitespace(t *testing.T) {
	t.Parallel()

	const user = "alice"
	const password = "  s3cr3t  "
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != expected {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]Host{})
	}))
	defer server.Close()

	c, err := New(Options{
		BaseURL:    server.URL,
		User:       user,
		Password:   password,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if _, err := c.ListHosts(context.Background()); err != nil {
		t.Fatalf("list hosts: %v", err)
	}
}

func TestListRequestsEncodesFilters(t *testing.T) {
	t.Parallel()

	hasGrant := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if got := query.Get("has_grant"); got != "true" {
			t.Fatalf("unexpected has_grant value: %q", got)
		}
		if got := query["label"]; len(got) != 1 || got[0] != "env=prod" {
			t.Fatalf("unexpected label values: %#v", got)
		}
		if got := query["host_label"]; len(got) != 1 || got[0] != "tier=backend" {
			t.Fatalf("unexpected host_label values: %#v", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]Request{})
	}))
	defer server.Close()

	c, err := New(Options{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = c.ListRequests(context.Background(), RequestListOptions{
		Labels:     map[string]string{"env": "prod"},
		HostLabels: map[string]string{"tier": "backend"},
		HasGrant:   &hasGrant,
	})
	if err != nil {
		t.Fatalf("list requests: %v", err)
	}
}

func TestAPIErrorMessageFromJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"invalid payload"}`))
	}))
	defer server.Close()

	c, err := New(Options{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = c.ListHosts(context.Background())
	if err == nil {
		t.Fatalf("expected API error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.Message != "invalid payload" {
		t.Fatalf("unexpected API error message: %q", apiErr.Message)
	}
}
