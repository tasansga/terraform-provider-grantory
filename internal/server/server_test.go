package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

func TestIsTLSEnabled(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  config.Config
		want bool
	}{
		{
			name: "no cert or key",
			cfg:  config.Config{},
			want: false,
		},
		{
			name: "only cert",
			cfg: config.Config{
				TLSCert: "/tmp/server.crt",
			},
			want: false,
		},
		{
			name: "only key",
			cfg: config.Config{
				TLSKey: "/tmp/server.key",
			},
			want: false,
		},
		{
			name: "cert and key",
			cfg: config.Config{
				TLSCert: "/tmp/server.crt",
				TLSKey:  "/tmp/server.key",
			},
			want: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, IsTLSEnabled(tc.cfg), "IsTLSEnabled result")
		})
	}
}

func ptrBool(value bool) *bool {
	return &value
}

func TestApplyRequestFilters(t *testing.T) {
	t.Parallel()

	requests := []storage.Request{
		{
			ID:       "req-postgres",
			Labels:   map[string]string{"env": "prod", "tier": "db"},
			HasGrant: false,
		},
		{
			ID:       "req-postgres-approved",
			Labels:   map[string]string{"env": "prod"},
			HasGrant: true,
		},
		{
			ID:       "req-mysql",
			Labels:   map[string]string{"env": "staging"},
			HasGrant: false,
		},
	}

	tests := []struct {
		name    string
		filters requestListFilters
		wantIDs []string
	}{
		{
			name: "filter by state and label",
			filters: requestListFilters{
				HasGrant: ptrBool(false),
				Labels: map[string]string{
					"env": "prod",
				},
			},
			wantIDs: []string{"req-postgres"},
		},
		{
			name: "state only",
			filters: requestListFilters{
				HasGrant: ptrBool(false),
			},
			wantIDs: []string{"req-postgres", "req-mysql"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			results := applyRequestFilters(requests, tc.filters)
			assert.Len(t, results, len(tc.wantIDs), "filtered request count")
			for i, req := range results {
				assert.Equal(t, tc.wantIDs[i], req.ID, "filtered request ID mismatch")
			}
		})
	}
}

func TestValidateTLSFilesMissingCert(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "server.key")
	assert.NoError(t, os.WriteFile(keyPath, []byte("key"), 0o600))

	err := validateTLSFiles(config.Config{
		TLSCert: "/does/not/exist.crt",
		TLSKey:  keyPath,
	})
	assert.Error(t, err, "missing cert should return error")
}

func TestValidateTLSFilesSuccess(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	assert.NoError(t, os.WriteFile(certPath, []byte("crt"), 0o600))
	assert.NoError(t, os.WriteFile(keyPath, []byte("key"), 0o600))

	err := validateTLSFiles(config.Config{
		TLSCert: certPath,
		TLSKey:  keyPath,
	})
	assert.NoError(t, err, "valid TLS files should not error")
}

func TestNamespaceMiddlewareStoresStore(t *testing.T) {
	t.Parallel()

	cfg := config.Config{DataDir: t.TempDir()}
	srv, err := New(context.Background(), cfg)
	assert.NoError(t, err, "New() should succeed")
	defer func() {
		if err := srv.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	}()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(srv.namespaceMiddleware())
	app.Get("/probe", func(c *fiber.Ctx) error {
		if storeFromLocals(c.Locals(storeCtxKey)) == nil {
			return fiber.NewError(http.StatusInternalServerError, "store missing")
		}
		return c.Status(http.StatusOK).JSON(map[string]string{"status": "ok"})
	})

	headers := map[string]string{"REMOTE_USER": "cli-user"}
	res := sendTestRequest(t, app, http.MethodGet, "/probe", headers, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "middleware should make store available")
}

func TestHandleReadinessTLSFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "server.key")
	assert.NoError(t, os.WriteFile(keyPath, []byte("key"), 0o600))

	cfg := config.Config{
		DataDir:  t.TempDir(),
		TLSCert:  filepath.Join(dir, "missing.crt"),
		TLSKey:   keyPath,
		BindAddr: "127.0.0.1:0",
	}
	srv, err := New(context.Background(), cfg)
	assert.NoError(t, err, "New() should succeed")
	defer func() {
		if err := srv.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	}()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/readyz", srv.handleReadiness)

	res := sendTestRequest(t, app, http.MethodGet, "/readyz", nil, nil)
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode, "missing TLS cert should fail readiness")
}

func TestHandleReadinessTLSSuccess(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	assert.NoError(t, os.WriteFile(certPath, []byte("cert"), 0o600))
	assert.NoError(t, os.WriteFile(keyPath, []byte("key"), 0o600))

	cfg := config.Config{
		DataDir:  t.TempDir(),
		TLSCert:  certPath,
		TLSKey:   keyPath,
		BindAddr: "127.0.0.1:0",
	}
	srv, err := New(context.Background(), cfg)
	assert.NoError(t, err, "New() should succeed")
	defer func() {
		if err := srv.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	}()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/readyz", srv.handleReadiness)

	res := sendTestRequest(t, app, http.MethodGet, "/readyz", nil, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode, "readiness should succeed with valid TLS files")
}

func TestHandleMetricsCountError(t *testing.T) {
	t.Parallel()

	cfg := config.Config{DataDir: t.TempDir()}
	srv, err := New(context.Background(), cfg)
	assert.NoError(t, err, "New() should succeed")
	defer func() {
		if err := srv.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	}()

	store, err := srv.nsStore.StoreFor(context.Background(), DefaultNamespace)
	assert.NoError(t, err, "StoreFor() should succeed")
	assert.NoError(t, store.Close(), "closing store to simulate failure")

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(requestLoggingMiddleware())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(storeCtxKey, localStore{store: store})
		c.Locals(namespaceCtxKey, DefaultNamespace)
		return c.Next()
	})
	app.Get("/metrics", srv.handleMetrics)

	res := sendTestRequest(t, app, http.MethodGet, "/metrics", nil, nil)
	assert.Equal(t, http.StatusInternalServerError, res.StatusCode, "metrics should fail when store closed")
}
