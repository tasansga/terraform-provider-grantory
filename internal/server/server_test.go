package server

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/api/service"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
	"github.com/tasansga/terraform-provider-grantory/internal/store"
	"github.com/valyala/fasthttp"
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
			cfg:  config.Config{TLSBind: "0.0.0.0:8443"},
			want: false,
		},
		{
			name: "only cert",
			cfg: config.Config{
				TLSCert: "/tmp/server.crt",
				TLSBind: "0.0.0.0:8443",
			},
			want: false,
		},
		{
			name: "only key",
			cfg: config.Config{
				TLSKey:  "/tmp/server.key",
				TLSBind: "0.0.0.0:8443",
			},
			want: false,
		},
		{
			name: "cert and key with valid TLSBind",
			cfg: config.Config{
				TLSCert: "/tmp/server.crt",
				TLSKey:  "/tmp/server.key",
				TLSBind: "0.0.0.0:8443",
			},
			want: true,
		},
		{
			name: "cert and key with TLSBind off",
			cfg: config.Config{
				TLSCert: "/tmp/server.crt",
				TLSKey:  "/tmp/server.key",
				TLSBind: "off",
			},
			want: false,
		},
		{
			name: "cert and key with empty TLSBind",
			cfg: config.Config{
				TLSCert: "/tmp/server.crt",
				TLSKey:  "/tmp/server.key",
				TLSBind: "",
			},
			want: false,
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

func TestIsUnixSocketEnabled(t *testing.T) {
	t.Parallel()

	assert.False(t, isUnixSocketEnabled(""), "empty path should disable unix socket")
	assert.False(t, isUnixSocketEnabled("off"), "off should disable unix socket")
	assert.False(t, isUnixSocketEnabled("  OFF  "), "off (case-insensitive) should disable unix socket")
	assert.True(t, isUnixSocketEnabled("/tmp/grantory.sock"), "path should enable unix socket")
}

func ptrBool(value bool) *bool {
	return &value
}

func filterRequestsForTest(requests []storage.Request, filters storage.RequestListFilters) []storage.Request {
	var filtered []storage.Request
	for _, req := range requests {
		if filters.HasGrant != nil && req.HasGrant != *filters.HasGrant {
			continue
		}
		if len(filters.Labels) > 0 {
			match := true
			for key, expected := range filters.Labels {
				if req.Labels[key] != expected {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}
		filtered = append(filtered, req)
	}
	return filtered
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
		filters storage.RequestListFilters
		wantIDs []string
	}{
		{
			name: "filter by state and label",
			filters: storage.RequestListFilters{
				HasGrant: ptrBool(false),
				Labels: map[string]string{
					"env": "prod",
				},
			},
			wantIDs: []string{"req-postgres"},
		},
		{
			name: "state only",
			filters: storage.RequestListFilters{
				HasGrant: ptrBool(false),
			},
			wantIDs: []string{"req-postgres", "req-mysql"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			results := filterRequestsForTest(requests, tc.filters)
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

func TestOpenUnixSocketListenerCreatesSocketWithMode(t *testing.T) {
	t.Parallel()

	socketPath := shortUnixSocketPath(t)
	listener, cleanup, err := openUnixSocketListener(socketPath, 0o660)
	assert.NoError(t, err, "open unix socket listener should succeed")
	if err != nil {
		return
	}
	defer cleanup()

	assert.NotNil(t, listener, "listener should be created")
	stat, statErr := os.Stat(socketPath)
	assert.NoError(t, statErr, "socket file should exist")
	if statErr != nil {
		return
	}
	assert.NotZero(t, stat.Mode()&os.ModeSocket, "path should be a socket")
	assert.Equal(t, os.FileMode(0o660), stat.Mode().Perm(), "socket mode should match configured mode")
}

func TestOpenUnixSocketListenerRejectsNonSocketPath(t *testing.T) {
	t.Parallel()

	socketPath := shortUnixSocketPath(t)
	assert.NoError(t, os.WriteFile(socketPath, []byte("not a socket"), 0o644))
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	_, _, err := openUnixSocketListener(socketPath, 0o660)
	assert.Error(t, err, "non-socket path should fail")
	assert.Contains(t, err.Error(), "refusing to overwrite non-socket path")
}

func TestOpenUnixSocketListenerRejectsActiveSocket(t *testing.T) {
	t.Parallel()

	socketPath := shortUnixSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	assert.NoError(t, err, "setup unix socket should succeed")
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()

	_, _, openErr := openUnixSocketListener(socketPath, 0o660)
	assert.Error(t, openErr, "active socket should fail")
	assert.Contains(t, openErr.Error(), "unix socket already in use")
}

func shortUnixSocketPath(t *testing.T) string {
	t.Helper()

	file, err := os.CreateTemp("", "g-sock-*")
	assert.NoError(t, err, "create temp socket path")
	path := file.Name()
	_ = file.Close()
	_ = os.Remove(path)
	socketPath := fmt.Sprintf("%s.sock", path)
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	return socketPath
}

func TestNamespaceMiddlewareStoresStore(t *testing.T) {
	t.Parallel()

	cfg := config.Config{Database: t.TempDir()}
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

func TestNamespaceMiddlewareRejectsInvalidNamespace(t *testing.T) {
	t.Parallel()

	cfg := config.Config{Database: t.TempDir()}
	srv, err := New(context.Background(), cfg)
	require.NoError(t, err, "New() should succeed")
	defer func() {
		_ = srv.Close()
	}()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(srv.namespaceMiddleware())
	app.Get("/probe", func(c *fiber.Ctx) error {
		return c.Status(http.StatusOK).JSON(map[string]string{"status": "ok"})
	})

	for _, invalidNS := range []string{"ab", "raft", "invalid@namespace", "bad spaces"} {
		t.Run(invalidNS, func(t *testing.T) {
			headers := map[string]string{"REMOTE_USER": invalidNS}
			res := sendTestRequest(t, app, http.MethodGet, "/probe", headers, nil)
			defer func() { _ = res.Body.Close() }()
			assert.Equal(t, http.StatusBadRequest, res.StatusCode, "middleware should return 400 for invalid namespace")
			body, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), "invalid namespace")
		})
	}
}

func TestHandleReadinessTLSFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "server.key")
	assert.NoError(t, os.WriteFile(keyPath, []byte("key"), 0o600))

	cfg := config.Config{
		Database: t.TempDir(),
		TLSCert:  filepath.Join(dir, "missing.crt"),
		TLSKey:   keyPath,
		TLSBind:  "127.0.0.1:8443",
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
		Database: t.TempDir(),
		TLSCert:  certPath,
		TLSKey:   keyPath,
		TLSBind:  "127.0.0.1:8443",
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

	cfg := config.Config{Database: t.TempDir()}
	srv, err := New(context.Background(), cfg)
	assert.NoError(t, err, "New() should succeed")
	defer func() {
		if err := srv.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	}()

	st, err := srv.nsStore.StoreFor(context.Background(), store.DefaultNamespace)
	assert.NoError(t, err, "StoreFor() should succeed")
	assert.NoError(t, st.Close(), "closing store to simulate failure")

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(requestLoggingMiddleware())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(storeCtxKey, st)
		c.Locals(namespaceCtxKey, store.DefaultNamespace)
		return c.Next()
	})
	app.Get("/metrics", srv.handleMetrics)

	res := sendTestRequest(t, app, http.MethodGet, "/metrics", nil, nil)
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode, "metrics should return 503 when store database is closed")
	assert.Equal(t, "1", res.Header.Get("Retry-After"))
}

func TestServerNew_RaftNodeInitialization(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := config.Config{
		Database:            dir,
		BindAddr:            "127.0.0.1:18082",
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 1,
	}

	srv, err := New(context.Background(), cfg)
	assert.NoError(t, err)
	defer func() { _ = srv.Close() }()

	assert.NotNil(t, srv.RaftNode())
	assert.Equal(t, "18082", srv.RaftNode().HTTPPort())
	assert.False(t, srv.RaftNode().IsTLS())
}

func TestServer_DynamicHTTPPortResolutionOnBindZero(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir := t.TempDir()
	cfg := config.Config{
		Database:            dir,
		BindAddr:            "127.0.0.1:0",
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-dyn",
		RaftBootstrapExpect: 1,
	}

	srv, err := New(ctx, cfg)
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	require.NotNil(t, srv.RaftNode())
	assert.Equal(t, "", srv.RaftNode().HTTPPort(), "HTTPPort before Serve should be empty string")

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()

	var dynamicPort string
	require.Eventually(t, func() bool {
		dynamicPort = srv.RaftNode().HTTPPort()
		return dynamicPort != "" && dynamicPort != "0"
	}, 5*time.Second, 50*time.Millisecond, "expected dynamic port resolution for RaftNode HTTP port")

	portNum, err := strconv.Atoi(dynamicPort)
	require.NoError(t, err)
	assert.Greater(t, portNum, 0)

	healthURL := fmt.Sprintf("http://127.0.0.1:%s/healthz", dynamicPort)
	client := &http.Client{Timeout: 2 * time.Second}
	require.Eventually(t, func() bool {
		resp, err := client.Get(healthURL)
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond, "expected healthz to succeed on dynamic port")

	cancel()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			assert.NoError(t, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shutdown in time")
	}
}

func TestServer_Serve_ShutdownGoroutineExitsOnStartupFailure(t *testing.T) {
	t.Run("conflicting port", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()

		cfg := config.Config{
			Database: t.TempDir(),
			BindAddr: ln.Addr().String(),
		}

		srv, err := New(context.Background(), cfg)
		require.NoError(t, err)
		defer func() { _ = srv.Close() }()

		serveErr := srv.Serve(context.Background())
		require.Error(t, serveErr)

		assert.Eventually(t, func() bool {
			buf := make([]byte, 64*1024)
			n := runtime.Stack(buf, true)
			stack := string(buf[:n])
			return !strings.Contains(stack, "Serve.func1")
		}, 2*time.Second, 20*time.Millisecond, "shutdown watcher goroutine should exit promptly on startup failure")
	})

	t.Run("invalid bind address", func(t *testing.T) {
		cfg := config.Config{
			Database: t.TempDir(),
			BindAddr: "invalid-bind-address-99999",
		}

		srv, err := New(context.Background(), cfg)
		require.NoError(t, err)
		defer func() { _ = srv.Close() }()

		serveErr := srv.Serve(context.Background())
		require.Error(t, serveErr)

		assert.Eventually(t, func() bool {
			buf := make([]byte, 64*1024)
			n := runtime.Stack(buf, true)
			stack := string(buf[:n])
			return !strings.Contains(stack, "Serve.func1")
		}, 2*time.Second, 20*time.Millisecond, "shutdown watcher goroutine should exit promptly on startup failure")
	})
}

func TestServer_Serve_ListenerCleanupOnStartupFailure(t *testing.T) {
	t.Run("unix listener closed when TCP listener fails", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()

		sockPath := shortUnixSocketPath(t)
		cfg := config.Config{
			Database:       t.TempDir(),
			BindAddr:       ln.Addr().String(), // Conflict: TCP port already in use
			UnixSocket:     sockPath,
			UnixSocketMode: 0o660,
		}

		srv, err := New(context.Background(), cfg)
		require.NoError(t, err)
		defer func() { _ = srv.Close() }()

		serveErr := srv.Serve(context.Background())
		require.Error(t, serveErr, "Serve should fail when TCP port is already bound")

		// Verify unix socket was cleaned up and closed
		_, dialErr := net.DialTimeout("unix", sockPath, 100*time.Millisecond)
		assert.Error(t, dialErr, "Dialing unix socket should fail after Serve cleanup")

		newLn, openErr := net.Listen("unix", sockPath)
		if assert.NoError(t, openErr, "Unix socket path should be available for new listener") {
			_ = newLn.Close()
			_ = os.Remove(sockPath)
		}
	})

	t.Run("unix and tls listeners closed when subsequent http listener fails", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCertAndKey(t, dir)
		sockPath := filepath.Join(dir, "cleanup_tls.sock")

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()

		cfg := config.Config{
			Database:       dir,
			BindAddr:       ln.Addr().String(), // Conflict: HTTP bind fails
			TLSBind:        "127.0.0.1:0",      // TLS bind succeeds
			TLSCert:        certPath,
			TLSKey:         keyPath,
			UnixSocket:     sockPath,
			UnixSocketMode: 0o660,
		}

		srv, err := New(context.Background(), cfg)
		require.NoError(t, err)
		defer func() { _ = srv.Close() }()

		serveErr := srv.Serve(context.Background())
		require.Error(t, serveErr, "Serve should fail when HTTP listener fails")

		// Verify unix socket was cleaned up and closed
		_, dialErr := net.DialTimeout("unix", sockPath, 100*time.Millisecond)
		assert.Error(t, dialErr)

		newLn, openErr := net.Listen("unix", sockPath)
		if assert.NoError(t, openErr) {
			_ = newLn.Close()
			_ = os.Remove(sockPath)
		}
	})
}

func TestServer_ListenTCP(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	ln, err := srv.listenTCP("127.0.0.1:0", false)
	require.NoError(t, err)
	require.NotNil(t, ln)
	defer func() { _ = ln.Close() }()

	_, err = srv.listenTCP("invalid-address-format", false)
	require.Error(t, err)
}

func TestServer_DualListenerHTTPPortPreservesTLS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, keyPath := generateTestCertAndKey(t, dir)

	cfg := config.Config{
		Database:            dir,
		BindAddr:            "127.0.0.1:0",
		TLSBind:             "127.0.0.1:0",
		TLSCert:             certPath,
		TLSKey:              keyPath,
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-dual",
		RaftBootstrapExpect: 1,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := New(ctx, cfg)
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	require.NotNil(t, srv.RaftNode())
	require.True(t, srv.RaftNode().IsTLS())

	// 1. Direct listenTCP verification
	tlsLn, err := srv.listenTCP("127.0.0.1:0", true)
	require.NoError(t, err)
	defer func() { _ = tlsLn.Close() }()
	tlsPort := strconv.Itoa(tlsLn.Addr().(*net.TCPAddr).Port)
	assert.Equal(t, tlsPort, srv.RaftNode().HTTPPort())

	plainLn, err := srv.listenTCP("127.0.0.1:0", false)
	require.NoError(t, err)
	defer func() { _ = plainLn.Close() }()
	plainPort := strconv.Itoa(plainLn.Addr().(*net.TCPAddr).Port)
	assert.NotEqual(t, tlsPort, plainPort)
	assert.Equal(t, tlsPort, srv.RaftNode().HTTPPort(), "HTTPPort should retain TLS port and not be overwritten by plaintext listener")
}

func TestServer_Serve_DualListenerSetsTLSHTTPPort(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, keyPath := generateTestCertAndKey(t, dir)

	cfg := config.Config{
		Database:            dir,
		BindAddr:            "127.0.0.1:0",
		TLSBind:             "127.0.0.2:0",
		TLSCert:             certPath,
		TLSKey:              keyPath,
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-dual-serve",
		RaftBootstrapExpect: 1,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := New(ctx, cfg)
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()

	var dynamicPort string
	require.Eventually(t, func() bool {
		dynamicPort = srv.RaftNode().HTTPPort()
		return dynamicPort != "" && dynamicPort != "0"
	}, 5*time.Second, 50*time.Millisecond, "expected dynamic TLS port resolution for RaftNode HTTP port")

	// Verify that the port assigned to RaftNode is indeed a TLS listener
	tlsConf := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.2:%s", dynamicPort), tlsConf)
	require.NoError(t, err, "HTTPPort should accept TLS handshake")
	_ = conn.Close()

	cancel()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			assert.NoError(t, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shutdown in time")
	}
}

func TestServer_BuildApp_RequireSignatures(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	pubHex := hex.EncodeToString(pub)

	cfg := config.Config{
		Database:          t.TempDir(),
		RequireSignatures: true,
	}

	srv, err := New(context.Background(), cfg)
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	app := srv.buildApp()

	// 1. Rejects unsigned write requests when host does not exist with 401 Unauthorized ("signature required")
	badReqPayload := map[string]any{
		"host_id": "non-existent-host",
		"payload": map[string]any{"action": "create"},
	}
	resBad := sendTestRequest(t, app, http.MethodPost, "/requests", nil, badReqPayload)
	assert.Equal(t, http.StatusUnauthorized, resBad.StatusCode)
	bodyBad, err := io.ReadAll(resBad.Body)
	require.NoError(t, err)
	assert.Contains(t, string(bodyBad), "signature required")

	// 2. Registering a host without a public key succeeds, but unsigned requests for it are rejected with 401 ("signature required")
	noKeyHostPayload := map[string]any{
		"unique_key": "host-no-key",
	}
	resNoKeyHost := sendTestRequest(t, app, http.MethodPost, "/hosts", nil, noKeyHostPayload)
	require.Equal(t, http.StatusCreated, resNoKeyHost.StatusCode)
	noKeyHost := decodeJSON[storage.Host](t, resNoKeyHost)

	reqNoKey := map[string]any{
		"host_id": noKeyHost.ID,
		"payload": map[string]any{"action": "create"},
	}
	resNoKeyReq := sendTestRequest(t, app, http.MethodPost, "/requests", nil, reqNoKey)
	assert.Equal(t, http.StatusUnauthorized, resNoKeyReq.StatusCode)
	bodyNoKey, err := io.ReadAll(resNoKeyReq.Body)
	require.NoError(t, err)
	assert.Contains(t, string(bodyNoKey), "signature required")

	// 3. Registering a host with a public key succeeds
	signedHostPayload := map[string]any{
		"unique_key": "host-with-key",
		"public_key": pubHex,
	}
	resSignedHost := sendTestRequest(t, app, http.MethodPost, "/hosts", nil, signedHostPayload)
	require.Equal(t, http.StatusCreated, resSignedHost.StatusCode)
	signedHost := decodeJSON[storage.Host](t, resSignedHost)

	// Unsigned write request for this host is rejected with 401 Unauthorized
	validReqPayload := map[string]any{
		"host_id": signedHost.ID,
		"payload": map[string]any{"action": "create"},
	}
	resUnsigned := sendTestRequest(t, app, http.MethodPost, "/requests", nil, validReqPayload)
	assert.Equal(t, http.StatusUnauthorized, resUnsigned.StatusCode)

	// Properly signed request for this host is accepted with 201 Created
	ts := fmt.Sprintf("%d", time.Now().Unix())
	nonce := "nonce-test-req"
	payloadBytes, err := json.Marshal(validReqPayload)
	require.NoError(t, err)
	sig := sign(priv, ts, nonce, http.MethodPost, "/requests", string(payloadBytes))

	headers := map[string]string{
		"X-Grantory-Timestamp": ts,
		"X-Grantory-Nonce":     nonce,
		"X-Grantory-Signature": sig,
	}
	resSigned := sendTestRequest(t, app, http.MethodPost, "/requests", headers, validReqPayload)
	assert.Equal(t, http.StatusCreated, resSigned.StatusCode)

	// Also verify DELETE on host without signature is rejected with 401
	resDel := sendTestRequest(t, app, http.MethodDelete, "/hosts/"+signedHost.ID, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resDel.StatusCode)
}

func TestErrorHandler_LeadershipErrors(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Database: t.TempDir(),
	}
	srv, err := New(context.Background(), cfg)
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	app := srv.buildApp()

	app.Get("/test-leadership-lost", func(c *fiber.Ctx) error {
		return storage.ErrLeadershipLost
	})
	app.Get("/test-not-leader", func(c *fiber.Ctx) error {
		return storage.ErrNotLeader
	})
	app.Get("/test-wrapped-leadership", func(c *fiber.Ctx) error {
		return fmt.Errorf("consensus failure: %w", storage.ErrLeadershipLost)
	})
	app.Get("/test-existing-retry-after", func(c *fiber.Ctx) error {
		c.Set("Retry-After", "5")
		return storage.ErrNotLeader
	})
	app.Get("/test-bad-gateway", func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusBadGateway, "upstream unreachable")
	})
	app.Get("/test-bad-gateway-existing-retry-after", func(c *fiber.Ctx) error {
		c.Set("Retry-After", "10")
		return fiber.NewError(fiber.StatusBadGateway, "upstream unreachable")
	})

	// Test ErrLeadershipLost
	res1 := sendTestRequest(t, app, http.MethodGet, "/test-leadership-lost", nil, nil)
	defer func() { _ = res1.Body.Close() }()
	assert.Equal(t, fiber.StatusServiceUnavailable, res1.StatusCode)
	assert.Equal(t, "1", res1.Header.Get("Retry-After"))
	body1, err := io.ReadAll(res1.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body1), storage.ErrLeadershipLost.Error())

	// Test ErrNotLeader
	res2 := sendTestRequest(t, app, http.MethodGet, "/test-not-leader", nil, nil)
	defer func() { _ = res2.Body.Close() }()
	assert.Equal(t, fiber.StatusServiceUnavailable, res2.StatusCode)
	assert.Equal(t, "1", res2.Header.Get("Retry-After"))
	body2, err := io.ReadAll(res2.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body2), storage.ErrNotLeader.Error())

	// Test wrapped ErrLeadershipLost
	res3 := sendTestRequest(t, app, http.MethodGet, "/test-wrapped-leadership", nil, nil)
	defer func() { _ = res3.Body.Close() }()
	assert.Equal(t, fiber.StatusServiceUnavailable, res3.StatusCode)
	assert.Equal(t, "1", res3.Header.Get("Retry-After"))
	body3, err := io.ReadAll(res3.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body3), storage.ErrLeadershipLost.Error())

	// Test preserving explicit Retry-After
	res4 := sendTestRequest(t, app, http.MethodGet, "/test-existing-retry-after", nil, nil)
	defer func() { _ = res4.Body.Close() }()
	assert.Equal(t, fiber.StatusServiceUnavailable, res4.StatusCode)
	assert.Equal(t, "5", res4.Header.Get("Retry-After"))

	// Test BadGateway
	res5 := sendTestRequest(t, app, http.MethodGet, "/test-bad-gateway", nil, nil)
	defer func() { _ = res5.Body.Close() }()
	assert.Equal(t, fiber.StatusBadGateway, res5.StatusCode)
	assert.Equal(t, "1", res5.Header.Get("Retry-After"))

	// Test preserving explicit Retry-After on BadGateway
	res6 := sendTestRequest(t, app, http.MethodGet, "/test-bad-gateway-existing-retry-after", nil, nil)
	defer func() { _ = res6.Body.Close() }()
	assert.Equal(t, fiber.StatusBadGateway, res6.StatusCode)
	assert.Equal(t, "10", res6.Header.Get("Retry-After"))
}

func TestErrorHandler_DatabaseClosedErrors(t *testing.T) {
	t.Parallel()

	t.Run("isDatabaseClosedError helper", func(t *testing.T) {
		assert.False(t, isDatabaseClosedError(nil))
		assert.True(t, isDatabaseClosedError(sql.ErrConnDone))
		assert.True(t, isDatabaseClosedError(fmt.Errorf("db failure: %w", sql.ErrConnDone)))
		assert.True(t, isDatabaseClosedError(errors.New("sql: database is closed")))
		assert.True(t, isDatabaseClosedError(errors.New("database is closed")))
		assert.True(t, isDatabaseClosedError(errors.New("bad connection")))
		assert.True(t, isDatabaseClosedError(errors.New("driver: bad connection")))
		assert.False(t, isDatabaseClosedError(errors.New("syntax error at line 1")))
	})

	t.Run("ErrorHandler maps database closed errors to 503 with Retry-After", func(t *testing.T) {
		cfg := config.Config{
			Database: t.TempDir(),
		}
		srv, err := New(context.Background(), cfg)
		require.NoError(t, err)
		defer func() { _ = srv.Close() }()

		app := srv.buildApp()

		app.Get("/test-sql-database-closed", func(c *fiber.Ctx) error {
			return errors.New("sql: database is closed")
		})
		app.Get("/test-err-conn-done", func(c *fiber.Ctx) error {
			return sql.ErrConnDone
		})
		app.Get("/test-wrapped-conn-done", func(c *fiber.Ctx) error {
			return fmt.Errorf("query execute failed: %w", sql.ErrConnDone)
		})
		app.Get("/test-bad-connection", func(c *fiber.Ctx) error {
			return errors.New("bad connection")
		})
		app.Get("/test-fiber-unavailable", func(c *fiber.Ctx) error {
			return fiber.NewError(fiber.StatusServiceUnavailable, "database temporarily unavailable")
		})

		endpoints := []string{
			"/test-sql-database-closed",
			"/test-err-conn-done",
			"/test-wrapped-conn-done",
			"/test-bad-connection",
			"/test-fiber-unavailable",
		}

		for _, endpoint := range endpoints {
			res := sendTestRequest(t, app, http.MethodGet, endpoint, nil, nil)
			defer func() { _ = res.Body.Close() }()
			assert.Equal(t, fiber.StatusServiceUnavailable, res.StatusCode, "expected 503 for %s", endpoint)
			assert.Equal(t, "1", res.Header.Get("Retry-After"), "expected Retry-After 1 for %s", endpoint)
		}
	})
}

func TestIsClusterUnavailableError(t *testing.T) {
	t.Parallel()

	t.Run("helper variants", func(t *testing.T) {
		cases := []struct {
			name     string
			err      error
			expected bool
		}{
			{"nil error", nil, false},
			{"unrelated error", errors.New("unrelated error"), false},
			{"context canceled", context.Canceled, false},
			{"storage.ErrLeadershipLost", storage.ErrLeadershipLost, true},
			{"wrapped storage.ErrLeadershipLost", fmt.Errorf("raft: %w", storage.ErrLeadershipLost), true},
			{"storage.ErrNotLeader", storage.ErrNotLeader, true},
			{"wrapped storage.ErrNotLeader", fmt.Errorf("raft: %w", storage.ErrNotLeader), true},
			{"service.ErrLeadershipLost", service.ErrLeadershipLost, true},
			{"wrapped service.ErrLeadershipLost", fmt.Errorf("svc: %w", service.ErrLeadershipLost), true},
			{"service.ErrNotLeader", service.ErrNotLeader, true},
			{"wrapped service.ErrNotLeader", fmt.Errorf("svc: %w", service.ErrNotLeader), true},
			{"sql.ErrConnDone", sql.ErrConnDone, true},
			{"wrapped sql.ErrConnDone", fmt.Errorf("db: %w", sql.ErrConnDone), true},
			{"sql: database is closed", errors.New("sql: database is closed"), true},
			{"database is closed", errors.New("database is closed"), true},
			{"bad connection", errors.New("bad connection"), true},
			{"driver: bad connection", errors.New("driver: bad connection"), true},
		}

		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				assert.Equal(t, tc.expected, isClusterUnavailableError(tc.err))
			})
		}
	})

	t.Run("ErrorHandler translates cluster unavailable errors to 503 with Retry-After", func(t *testing.T) {
		cfg := config.Config{
			Database: t.TempDir(),
		}
		srv, err := New(context.Background(), cfg)
		require.NoError(t, err)
		defer func() { _ = srv.Close() }()

		app := srv.buildApp()

		routes := []struct {
			path string
			err  error
		}{
			{"/err-storage-leadership-lost", storage.ErrLeadershipLost},
			{"/err-storage-not-leader", storage.ErrNotLeader},
			{"/err-service-leadership-lost", service.ErrLeadershipLost},
			{"/err-service-not-leader", service.ErrNotLeader},
			{"/err-sql-conn-done", sql.ErrConnDone},
			{"/err-db-closed", errors.New("database is closed")},
		}

		for _, r := range routes {
			r := r
			app.Get(r.path, func(c *fiber.Ctx) error {
				return r.err
			})
		}

		for _, r := range routes {
			r := r
			t.Run(r.path, func(t *testing.T) {
				res := sendTestRequest(t, app, http.MethodGet, r.path, nil, nil)
				defer func() { _ = res.Body.Close() }()

				assert.Equal(t, fiber.StatusServiceUnavailable, res.StatusCode)
				assert.Equal(t, "1", res.Header.Get("Retry-After"))
				body, err := io.ReadAll(res.Body)
				require.NoError(t, err)
				fe, ok := asFiberError(r.err)
				require.True(t, ok)
				assert.Contains(t, string(body), fe.Message)
			})
		}
	})
}

func TestRenderPageError(t *testing.T) {
	t.Parallel()

	t.Run("cluster unavailable leadership lost returns 503", func(t *testing.T) {
		err := renderPageError(storage.ErrLeadershipLost, "test-ns", "action", "fallback msg")
		require.Error(t, err)
		var fe *fiber.Error
		require.True(t, errors.As(err, &fe))
		assert.Equal(t, fiber.StatusServiceUnavailable, fe.Code)
		assert.Equal(t, "cluster leader changed during operation", fe.Message)
	})

	t.Run("cluster unavailable not leader returns 503", func(t *testing.T) {
		err := renderPageError(storage.ErrNotLeader, "test-ns", "action", "fallback msg")
		require.Error(t, err)
		var fe *fiber.Error
		require.True(t, errors.As(err, &fe))
		assert.Equal(t, fiber.StatusServiceUnavailable, fe.Code)
		assert.Equal(t, "not cluster leader", fe.Message)
	})

	t.Run("cluster unavailable database closed returns 503", func(t *testing.T) {
		err := renderPageError(sql.ErrConnDone, "test-ns", "action", "fallback msg")
		require.Error(t, err)
		var fe *fiber.Error
		require.True(t, errors.As(err, &fe))
		assert.Equal(t, fiber.StatusServiceUnavailable, fe.Code)
		assert.Equal(t, "database temporarily unavailable", fe.Message)
	})

	t.Run("generic error returns 500 with fallback msg and logs", func(t *testing.T) {
		err := renderPageError(errors.New("db disk failure"), "test-ns", "load register", "unable to load register", logrus.Fields{
			"register_id": "reg-123",
		})
		require.Error(t, err)
		var fe *fiber.Error
		require.True(t, errors.As(err, &fe))
		assert.Equal(t, http.StatusInternalServerError, fe.Code)
		assert.Equal(t, "unable to load register", fe.Message)
	})
}

type mockFailingMetricsStore struct {
	storage.Store
	err error
}

func (m *mockFailingMetricsStore) CountRequestsByGrantPresence(_ context.Context) (map[string]int64, error) {
	return nil, m.err
}

func (m *mockFailingMetricsStore) CountGrants(_ context.Context) (map[string]int64, error) {
	return nil, m.err
}

func (m *mockFailingMetricsStore) CountRegisters(_ context.Context) (map[string]int64, error) {
	return nil, m.err
}

func (m *mockFailingMetricsStore) GetRegister(_ context.Context, _ string) (storage.Register, error) {
	return storage.Register{}, m.err
}

func (m *mockFailingMetricsStore) GetRequest(_ context.Context, _ string) (storage.Request, error) {
	return storage.Request{}, m.err
}

func (m *mockFailingMetricsStore) GetGrantForRequest(_ context.Context, _ string) (storage.Grant, bool, error) {
	return storage.Grant{}, false, m.err
}

func (m *mockFailingMetricsStore) GetGrant(_ context.Context, _ string) (storage.Grant, error) {
	return storage.Grant{}, m.err
}

func (m *mockFailingMetricsStore) GetSchemaDefinition(_ context.Context, _ string) (storage.SchemaDefinition, error) {
	return storage.SchemaDefinition{}, m.err
}

func (m *mockFailingMetricsStore) Close() error {
	return nil
}

type mockSecondaryFailingStore struct {
	storage.Store
	err error
}

func (m *mockSecondaryFailingStore) GetRequest(_ context.Context, id string) (storage.Request, error) {
	if id == "req-fail" {
		return storage.Request{}, m.err
	}
	return storage.Request{ID: id}, nil
}

func (m *mockSecondaryFailingStore) GetGrantForRequest(_ context.Context, _ string) (storage.Grant, bool, error) {
	return storage.Grant{}, false, m.err
}

func (m *mockSecondaryFailingStore) GetGrant(_ context.Context, id string) (storage.Grant, error) {
	return storage.Grant{ID: id, RequestID: "req-fail"}, nil
}

func (m *mockSecondaryFailingStore) Close() error {
	return nil
}

func TestServer_ClusterUnavailable_IndexAndMetrics(t *testing.T) {
	t.Parallel()

	t.Run("real server with closed database returns 503 and Retry-After 1", func(t *testing.T) {
		dir := t.TempDir()
		cfg := config.Config{Database: dir}
		srv, err := New(context.Background(), cfg)
		require.NoError(t, err)
		defer func() { _ = srv.Close() }()

		app := srv.buildApp()

		// Warm up default database store
		res := sendTestRequest(t, app, http.MethodGet, "/metrics", nil, nil)
		require.Equal(t, http.StatusOK, res.StatusCode)
		_ = res.Body.Close()

		res = sendTestRequest(t, app, http.MethodGet, "/index.html", nil, nil)
		require.Equal(t, http.StatusOK, res.StatusCode)
		_ = res.Body.Close()

		// Close underlying database
		rawStore, err := srv.nsStore.StoreFor(context.Background(), store.DefaultNamespace)
		require.NoError(t, err)
		require.NoError(t, rawStore.Close())

		for _, endpoint := range []string{
			"/metrics",
			"/index.html",
			"/register.html?id=reg-1",
			"/request.html?id=req-1",
			"/grant.html?id=grant-1",
			"/schema.html?id=schema-1",
		} {
			res := sendTestRequest(t, app, http.MethodGet, endpoint, nil, nil)
			defer func() { _ = res.Body.Close() }()
			assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode, "endpoint %s", endpoint)
			assert.Equal(t, "1", res.Header.Get("Retry-After"), "endpoint %s", endpoint)
		}
	})

	t.Run("mock store returning cluster unavailable error returns 503 and Retry-After 1", func(t *testing.T) {
		cases := []struct {
			name string
			err  error
		}{
			{"LeadershipLost", storage.ErrLeadershipLost},
			{"NotLeader", storage.ErrNotLeader},
			{"DatabaseClosed", errors.New("sql: database is closed")},
		}

		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				cfg := config.Config{Database: t.TempDir()}
				srv, err := New(context.Background(), cfg)
				require.NoError(t, err)
				defer func() { _ = srv.Close() }()

				mock := &mockFailingMetricsStore{err: tc.err}
				app := fiber.New(fiber.Config{
					DisableStartupMessage: true,
					ErrorHandler: func(c *fiber.Ctx, err error) error {
						code := fiber.StatusInternalServerError
						if isClusterUnavailableError(err) {
							code = fiber.StatusServiceUnavailable
						} else {
							var fe *fiber.Error
							if errors.As(err, &fe) {
								code = fe.Code
							}
						}
						if (code == fiber.StatusServiceUnavailable || code == fiber.StatusBadGateway) && len(c.Response().Header.Peek("Retry-After")) == 0 {
							c.Set("Retry-After", "1")
						}
						c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
						return c.Status(code).SendString(err.Error())
					},
				})
				app.Use(requestLoggingMiddleware())
				app.Use(func(c *fiber.Ctx) error {
					c.Locals(storeCtxKey, mock)
					c.Locals(namespaceCtxKey, "default")
					return c.Next()
				})
				app.Get("/index.html", srv.handleIndex)
				app.Get("/metrics", srv.handleMetrics)
				app.Get("/register.html", srv.handleRegisterPage)
				app.Get("/request.html", srv.handleRequestPage)
				app.Get("/grant.html", srv.handleGrantPage)
				app.Get("/schema.html", srv.handleSchemaPage)

				endpoints := []string{
					"/index.html",
					"/metrics",
					"/register.html?id=reg-1",
					"/request.html?id=req-1",
					"/grant.html?id=grant-1",
					"/schema.html?id=schema-1",
				}
				for _, endpoint := range endpoints {
					res := sendTestRequest(t, app, http.MethodGet, endpoint, nil, nil)
					defer func() { _ = res.Body.Close() }()
					assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode, "endpoint %s", endpoint)
					assert.Equal(t, "1", res.Header.Get("Retry-After"), "endpoint %s", endpoint)
				}
			})
		}
	})

	t.Run("secondary queries returning cluster unavailable error return 503 and Retry-After 1", func(t *testing.T) {
		cases := []struct {
			name string
			err  error
		}{
			{"LeadershipLost", storage.ErrLeadershipLost},
			{"NotLeader", storage.ErrNotLeader},
			{"DatabaseClosed", errors.New("sql: database is closed")},
		}

		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				cfg := config.Config{Database: t.TempDir()}
				srv, err := New(context.Background(), cfg)
				require.NoError(t, err)
				defer func() { _ = srv.Close() }()

				mock := &mockSecondaryFailingStore{err: tc.err}
				app := fiber.New(fiber.Config{
					DisableStartupMessage: true,
					ErrorHandler: func(c *fiber.Ctx, err error) error {
						code := fiber.StatusInternalServerError
						if isClusterUnavailableError(err) {
							code = fiber.StatusServiceUnavailable
						} else {
							var fe *fiber.Error
							if errors.As(err, &fe) {
								code = fe.Code
							}
						}
						if (code == fiber.StatusServiceUnavailable || code == fiber.StatusBadGateway) && len(c.Response().Header.Peek("Retry-After")) == 0 {
							c.Set("Retry-After", "1")
						}
						c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
						return c.Status(code).SendString(err.Error())
					},
				})
				app.Use(requestLoggingMiddleware())
				app.Use(func(c *fiber.Ctx) error {
					c.Locals(storeCtxKey, mock)
					c.Locals(namespaceCtxKey, "default")
					return c.Next()
				})
				app.Get("/request.html", srv.handleRequestPage)
				app.Get("/grant.html", srv.handleGrantPage)

				for _, endpoint := range []string{"/request.html?id=req-1", "/grant.html?id=grant-1"} {
					res := sendTestRequest(t, app, http.MethodGet, endpoint, nil, nil)
					defer func() { _ = res.Body.Close() }()
					assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode, "endpoint %s", endpoint)
					assert.Equal(t, "1", res.Header.Get("Retry-After"), "endpoint %s", endpoint)
				}
			})
		}
	})
}

type mockCloseTrackingStore struct {
	storage.Store
	closeCalled bool
}

func (m *mockCloseTrackingStore) Close() error {
	m.closeCalled = true
	return nil
}

func TestUnclosableStore(t *testing.T) {
	mockUnderlying := &mockCloseTrackingStore{}
	u := unclosableStore{Store: mockUnderlying}

	// Verify unclosableStore satisfies storage.Store interface
	var s storage.Store = u
	require.NotNil(t, s)

	// Verify Close() is a no-op that returns nil and does not invoke Close() on underlying store
	err := u.Close()
	assert.NoError(t, err)
	assert.False(t, mockUnderlying.closeCalled, "Close() must not be called on the wrapped store")

	// Verify Unwrap() returns the underlying store
	assert.Same(t, mockUnderlying, u.Unwrap())
}

func TestNamespaceMiddleware_StandaloneUnclosableStore(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := config.Config{Database: dir}
	srv, err := New(context.Background(), cfg)
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(srv.namespaceMiddleware())

	var capturedStore storage.Store
	var wasUnclosable bool
	var unwrappedStore storage.Store

	app.Get("/test-unclosable", func(c *fiber.Ctx) error {
		raw := c.Locals(storeCtxKey)
		if u, ok := raw.(unclosableStore); ok {
			wasUnclosable = true
			unwrappedStore = u.Unwrap()
		}
		capturedStore = storeFromLocals(raw)
		return c.SendStatus(http.StatusOK)
	})

	res := sendTestRequest(t, app, http.MethodGet, "/test-unclosable", nil, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.True(t, wasUnclosable, "standalone mode should wrap store in unclosableStore")
	assert.NotNil(t, unwrappedStore, "Unwrap() should return underlying store")
	assert.NotNil(t, capturedStore)

	// Calling Close() on captured store should be a no-op that returns nil
	assert.NoError(t, capturedStore.Close())
}

func TestServer_CloseCleanly(t *testing.T) {
	t.Parallel()

	// Test nil server close
	var nilSrv *Server
	assert.NoError(t, nilSrv.Close())

	// Test server with proxyClient and nsStore
	dir := t.TempDir()
	cfg := config.Config{Database: dir}
	srv, err := New(context.Background(), cfg)
	require.NoError(t, err)

	// Attach a proxyClient
	srv.proxyClient = &fasthttp.Client{}

	// Perform a request to initialize store
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(srv.namespaceMiddleware())
	app.Get("/probe", func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusOK)
	})
	res := sendTestRequest(t, app, http.MethodGet, "/probe", nil, nil)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	// Close must close proxyClient, namespace store, and return no error
	require.NoError(t, srv.Close())

	// Verifying namespace store is now closed
	_, err = srv.nsStore.StoreFor(context.Background(), "default")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "namespace store is closed")
}

func TestServer_MultiListenerTeardown(t *testing.T) {
	t.Parallel()

	t.Run("closing one listener triggers clean shutdown of sibling listener", func(t *testing.T) {
		app := fiber.New(fiber.Config{DisableStartupMessage: true})
		app.Get("/ping", func(c *fiber.Ctx) error {
			return c.SendString("pong")
		})

		tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		sockDir := t.TempDir()
		sockPath := filepath.Join(sockDir, "multi_listener_test.sock")
		unixLn, unixCleanup, err := openUnixSocketListener(sockPath, 0o660)
		require.NoError(t, err)
		defer unixCleanup()

		serverErrCh := make(chan error, 1)
		go func() {
			serverErrCh <- listenAndServe(app, tcpLn, unixLn)
		}()

		// Verify TCP listener is responsive
		tcpAddr := tcpLn.Addr().String()
		client := &http.Client{Timeout: 2 * time.Second}
		require.Eventually(t, func() bool {
			resp, err := client.Get(fmt.Sprintf("http://%s/ping", tcpAddr))
			if err != nil {
				return false
			}
			defer func() { _ = resp.Body.Close() }()
			return resp.StatusCode == http.StatusOK
		}, 3*time.Second, 50*time.Millisecond, "TCP listener should respond")

		// Close TCP listener directly. This should cause the TCP listener goroutine to exit,
		// triggering app.Shutdown(), which shuts down unixLn and causes listenAndServe to return promptly without hanging.
		require.NoError(t, tcpLn.Close())

		select {
		case <-serverErrCh:
			// Server shut down cleanly
		case <-time.After(3 * time.Second):
			t.Fatal("server hung: closing one listener did not trigger shutdown of sibling listener")
		}
	})

	t.Run("clean listener exit triggers app.Shutdown for siblings", func(t *testing.T) {
		app := fiber.New(fiber.Config{DisableStartupMessage: true})
		app.Get("/ping", func(c *fiber.Ctx) error {
			return c.SendString("pong")
		})

		ln1, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		ln2, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		serverErrCh := make(chan error, 1)
		go func() {
			serverErrCh <- listenAndServe(app, ln1, ln2)
		}()

		// Close ln2 to simulate termination of one listener
		_ = ln2.Close()

		select {
		case <-serverErrCh:
			// Both listeners exited promptly
		case <-time.After(3 * time.Second):
			t.Fatal("server hung waiting for sibling listener to exit")
		}
	})
}

func TestServer_Serve_ListenerUnification(t *testing.T) {
	t.Parallel()

	t.Run("listenAndServe validation", func(t *testing.T) {
		app := fiber.New(fiber.Config{DisableStartupMessage: true})
		err := listenAndServe(app)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "need at least one listener")
	})

	t.Run("listenAndServe single listener", func(t *testing.T) {
		app := fiber.New(fiber.Config{DisableStartupMessage: true})
		app.Get("/healthz", func(c *fiber.Ctx) error {
			return c.SendString("ok")
		})
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		serverErrCh := make(chan error, 1)
		go func() {
			serverErrCh <- listenAndServe(app, ln)
		}()

		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(fmt.Sprintf("http://%s/healthz", ln.Addr().String()))
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		_ = app.Shutdown()
		select {
		case <-serverErrCh:
		case <-time.After(3 * time.Second):
			t.Fatal("server did not shut down cleanly")
		}
	})

	t.Run("non-TLS with TCP and Unix socket", func(t *testing.T) {
		dir := t.TempDir()
		sockPath := filepath.Join(dir, "unified_nontls.sock")

		cfg := config.Config{
			Database:       dir,
			BindAddr:       "127.0.0.1:0",
			UnixSocket:     sockPath,
			UnixSocketMode: 0o660,
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		srv, err := New(ctx, cfg)
		require.NoError(t, err)
		defer func() { _ = srv.Close() }()

		errCh := make(chan error, 1)
		go func() {
			errCh <- srv.Serve(ctx)
		}()

		unixClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", sockPath)
				},
			},
			Timeout: 2 * time.Second,
		}
		require.Eventually(t, func() bool {
			resp, err := unixClient.Get("http://unix/healthz")
			if err != nil {
				return false
			}
			defer func() { _ = resp.Body.Close() }()
			return resp.StatusCode == http.StatusOK
		}, 5*time.Second, 50*time.Millisecond, "Unix socket listener should respond")

		cancel()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				assert.NoError(t, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("server did not shut down in time")
		}
	})

	t.Run("TLS with TLS TCP and Unix socket", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCertAndKey(t, dir)
		sockPath := filepath.Join(dir, "unified_tls.sock")

		cfg := config.Config{
			Database:       dir,
			BindAddr:       "off",
			TLSBind:        "127.0.0.1:0",
			TLSCert:        certPath,
			TLSKey:         keyPath,
			UnixSocket:     sockPath,
			UnixSocketMode: 0o660,
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		srv, err := New(ctx, cfg)
		require.NoError(t, err)
		defer func() { _ = srv.Close() }()

		errCh := make(chan error, 1)
		go func() {
			errCh <- srv.Serve(ctx)
		}()

		unixClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", sockPath)
				},
			},
			Timeout: 2 * time.Second,
		}
		require.Eventually(t, func() bool {
			resp, err := unixClient.Get("http://unix/healthz")
			if err != nil {
				return false
			}
			defer func() { _ = resp.Body.Close() }()
			return resp.StatusCode == http.StatusOK
		}, 5*time.Second, 50*time.Millisecond, "Unix socket listener in TLS mode should respond")

		cancel()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				assert.NoError(t, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("server did not shut down in time")
		}
	})
}

func TestErrorHandler_DomainErrors(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Database: t.TempDir(),
	}
	srv, err := New(context.Background(), cfg)
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	app := srv.buildApp()

	app.Get("/err-replay", func(c *fiber.Ctx) error {
		return storage.ErrReplayDetected
	})
	app.Get("/err-timeout", func(c *fiber.Ctx) error {
		return context.DeadlineExceeded
	})
	app.Get("/err-not-leader", func(c *fiber.Ctx) error {
		return storage.ErrNotLeader
	})

	// 1. ErrReplayDetected -> 401 Unauthorized
	resReplay := sendTestRequest(t, app, http.MethodGet, "/err-replay", nil, nil)
	defer func() { _ = resReplay.Body.Close() }()
	assert.Equal(t, fiber.StatusUnauthorized, resReplay.StatusCode)
	bodyReplay, err := io.ReadAll(resReplay.Body)
	require.NoError(t, err)
	assert.Contains(t, string(bodyReplay), "replay detected")

	// 2. context.DeadlineExceeded -> 408 Request Timeout
	resTimeout := sendTestRequest(t, app, http.MethodGet, "/err-timeout", nil, nil)
	defer func() { _ = resTimeout.Body.Close() }()
	assert.Equal(t, fiber.StatusRequestTimeout, resTimeout.StatusCode)
	bodyTimeout, err := io.ReadAll(resTimeout.Body)
	require.NoError(t, err)
	assert.Contains(t, string(bodyTimeout), "operation timed out")

	// 3. storage.ErrNotLeader -> 503 Service Unavailable with Retry-After: 1
	resNotLeader := sendTestRequest(t, app, http.MethodGet, "/err-not-leader", nil, nil)
	defer func() { _ = resNotLeader.Body.Close() }()
	assert.Equal(t, fiber.StatusServiceUnavailable, resNotLeader.StatusCode)
	assert.Equal(t, "1", resNotLeader.Header.Get("Retry-After"))
	bodyNotLeader, err := io.ReadAll(resNotLeader.Body)
	require.NoError(t, err)
	assert.Contains(t, string(bodyNotLeader), "not cluster leader")
}
