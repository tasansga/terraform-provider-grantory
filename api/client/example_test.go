package client_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/tasansga/terraform-provider-grantory/api/client"
)

func ExampleNew() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/hosts" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]any{})
	}))
	defer server.Close()

	c, err := client.New(client.Options{
		BaseURL:    server.URL,
		Namespace:  "team-a",
		HTTPClient: server.Client(),
	})
	if err != nil {
		log.Fatal(err)
	}

	_, err = c.ListHosts(context.Background())
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleNew_withBearerToken() {
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]any{})
	}))
	defer server.Close()

	c, err := client.New(client.Options{
		BaseURL:    server.URL,
		Token:      "demo-token",
		HTTPClient: server.Client(),
	})
	if err != nil {
		log.Fatal(err)
	}

	_, err = c.ListHosts(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(authHeader == "Bearer demo-token")
	// Output: true
}

func ExampleClient_CreateRequest() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/requests":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "req-1",
				"host_id":    "host-1",
				"unique_key": "app.request",
				"payload": map[string]any{
					"service": "api",
				},
				"labels":    map[string]string{"env": "dev"},
				"has_grant": false,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/requests":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":         "req-1",
					"host_id":    "host-1",
					"unique_key": "app.request",
					"payload": map[string]any{
						"service": "api",
					},
					"labels":    map[string]string{"env": "dev"},
					"has_grant": false,
				},
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	c, err := client.New(client.Options{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	})
	if err != nil {
		log.Fatal(err)
	}

	_, err = c.CreateRequest(context.Background(), client.RequestCreatePayload{
		HostID:    "host-1",
		UniqueKey: "app.request",
		Payload:   map[string]any{"service": "api"},
		Labels:    map[string]string{"env": "dev"},
	})
	if err != nil {
		log.Fatal(err)
	}

	requests, err := c.ListRequests(context.Background(), client.RequestListOptions{
		Labels: map[string]string{"env": "dev"},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(requests))
	// Output: 1
}
