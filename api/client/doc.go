// Package client provides a Go client for the Grantory HTTP API.
//
// Import path:
//
//	github.com/tasansga/terraform-provider-grantory/api/client
//
// Authentication is optional for Grantory itself. The client supports optional
// Bearer token and Basic authentication for deployments behind a proxy/gateway
// that enforces auth.
//
// Namespace selection is sent via the REMOTE_USER header when
// Options.Namespace is set.
package client
