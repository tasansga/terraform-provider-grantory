package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"

	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

const (
	storeCtxKey     = "grantory:store"
	namespaceCtxKey = "grantory:namespace"
)

type localStore struct {
	store storage.Store
}

type Server struct {
	cfg     config.Config
	nsStore *NamespaceStore
}

func New(ctx context.Context, cfg config.Config) (*Server, error) {
	nsStore, err := NewNamespaceStore(ctx, cfg.Database)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, nsStore: nsStore}, nil
}

func (s *Server) Serve(ctx context.Context) error {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})

	app.Get("/static/water.min.css", s.handleWaterCSS)
	app.Get("/", s.handleRoot)

	app.Get("/healthz", s.handleHealth)
	app.Get("/readyz", s.handleReadiness)
	app.Get("/meta", s.handleMeta)
	app.Use(requestLoggingMiddleware())

	api := app.Group("/", s.namespaceMiddleware())

	registerHostRoutes(api)
	registerRequestRoutes(api)
	registerRegisterRoutes(api)
	registerSchemaDefinitionRoutes(api)
	registerGrantRoutes(api)
	api.Get("/metrics", s.handleMetrics)
	api.Get("/index.html", s.handleIndex)
	api.Get("/register.html", s.handleRegisterPage)
	api.Get("/request.html", s.handleRequestPage)
	api.Get("/grant.html", s.handleGrantPage)
	api.Get("/schema.html", s.handleSchemaPage)

	go func() {
		<-ctx.Done()
		_ = app.Shutdown()
	}()

	httpDisabled := isBindDisabled(s.cfg.BindAddr)
	httpsDisabled := isBindDisabled(s.cfg.TLSBind)
	unixSocketEnabled := isUnixSocketEnabled(s.cfg.UnixSocket)

	var unixListener net.Listener
	var unixCleanup func()
	if unixSocketEnabled {
		listener, cleanup, err := openUnixSocketListener(s.cfg.UnixSocket, s.cfg.UnixSocketMode)
		if err != nil {
			return err
		}
		unixListener = listener
		unixCleanup = cleanup
		defer unixCleanup()
	}

	if IsTLSEnabled(s.cfg) {
		if s.cfg.TLSBind == "" || httpsDisabled {
			return fmt.Errorf("https bind address must be configured when TLS is enabled")
		}
		if !httpDisabled && s.cfg.TLSBind == s.cfg.BindAddr {
			return fmt.Errorf("https bind address must differ from http bind address")
		}

		errCount := 1
		if !httpDisabled {
			errCount = 2
		}
		if unixSocketEnabled {
			errCount++
		}
		errCh := make(chan error, errCount)
		if !httpDisabled {
			go func() {
				errCh <- app.Listen(s.cfg.BindAddr)
			}()
		}
		go func() {
			errCh <- app.ListenTLS(s.cfg.TLSBind, s.cfg.TLSCert, s.cfg.TLSKey)
		}()
		if unixSocketEnabled {
			go func() {
				errCh <- app.Listener(unixListener)
			}()
		}

		err := <-errCh
		if err != nil {
			_ = app.Shutdown()
		}
		return err
	}

	if httpDisabled && !unixSocketEnabled {
		return fmt.Errorf("need at least one listener - enable http bind address or unix socket when TLS is disabled")
	}
	if httpDisabled {
		return app.Listener(unixListener)
	}
	if !unixSocketEnabled {
		return app.Listen(s.cfg.BindAddr)
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- app.Listen(s.cfg.BindAddr)
	}()
	go func() {
		errCh <- app.Listener(unixListener)
	}()
	err := <-errCh
	if err != nil {
		_ = app.Shutdown()
	}
	return err
}

func isBindDisabled(addr string) bool {
	return strings.EqualFold(strings.TrimSpace(addr), "off")
}

func isUnixSocketEnabled(path string) bool {
	trimmed := strings.TrimSpace(path)
	return trimmed != "" && !strings.EqualFold(trimmed, "off")
}

func openUnixSocketListener(path string, mode os.FileMode) (net.Listener, func(), error) {
	socketPath := strings.TrimSpace(path)
	if socketPath == "" {
		return nil, nil, fmt.Errorf("unix socket path must not be empty")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, nil, fmt.Errorf("create unix socket directory: %w", err)
	}

	if st, err := os.Lstat(socketPath); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, nil, fmt.Errorf("refusing to overwrite non-socket path: %s", socketPath)
		}
		conn, dialErr := net.DialTimeout("unix", socketPath, 250*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("unix socket already in use: %s", socketPath)
		}
		if !errors.Is(dialErr, os.ErrNotExist) && !strings.Contains(strings.ToLower(dialErr.Error()), "connection refused") {
			return nil, nil, fmt.Errorf("check existing unix socket: %w", dialErr)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, nil, fmt.Errorf("remove stale unix socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("stat unix socket path: %w", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("listen on unix socket: %w", err)
	}
	if err := os.Chmod(socketPath, mode); err != nil {
		_ = listener.Close()
		return nil, nil, fmt.Errorf("chmod unix socket: %w", err)
	}

	cleanup := func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}
	return listener, cleanup, nil
}

func requestLoggingMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		err := c.Next()
		status := c.Response().StatusCode()
		if err != nil {
			var fe *fiber.Error
			if errors.As(err, &fe) {
				status = fe.Code
			} else if status < http.StatusBadRequest {
				status = http.StatusInternalServerError
			}
		}
		if status >= http.StatusBadRequest {
			details := map[string]any{"status": status}
			if err != nil {
				details["error"] = err.Error()
			}
			logRequestEntry(c, "Server.request", details)
		}
		return err
	}
}

func (s *Server) namespaceMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		namespace := c.Get("REMOTE_USER")
		if namespace == "" {
			namespace = DefaultNamespace
		}
		store, err := s.nsStore.StoreFor(c.Context(), namespace)
		if err != nil {
			if err := ValidateNamespaceName(namespace); err != nil {
				return fiber.NewError(fiber.StatusBadRequest, err.Error())
			}
			logrus.WithError(err).WithField("namespace", namespace).Error("prepare namespace store")
			return fiber.NewError(fiber.StatusInternalServerError, "unable to access namespace data")
		}

		c.Locals(storeCtxKey, localStore{store: store})
		c.Locals(namespaceCtxKey, namespace)
		return c.Next()
	}
}

func IsTLSEnabled(cfg config.Config) bool {
	return cfg.TLSCert != "" && cfg.TLSKey != ""
}

func (s *Server) handleHealth(c *fiber.Ctx) error {
	logRequestEntry(c, "Server.handleHealth", nil)
	return c.Status(http.StatusOK).JSON(map[string]string{"status": "ok"})
}

func (s *Server) handleRoot(c *fiber.Ctx) error {
	logRequestEntry(c, "Server.handleRoot", nil)
	return c.Redirect("/index.html", fiber.StatusFound)
}

func (s *Server) handleReadiness(c *fiber.Ctx) error {
	logRequestEntry(c, "Server.handleReadiness", nil)
	if IsTLSEnabled(s.cfg) {
		if err := validateTLSFiles(s.cfg); err != nil {
			logrus.WithError(err).Error("validate tls configuration")
			return fiber.NewError(http.StatusServiceUnavailable, "tls configuration invalid")
		}
	}

	if _, err := s.nsStore.StoreFor(c.Context(), DefaultNamespace); err != nil {
		logrus.WithError(err).Error("prepare default namespace")
		return fiber.NewError(http.StatusServiceUnavailable, "database not ready")
	}

	backend := "sqlite"
	dbInfo := s.cfg.Database
	if storage.IsPostgresDSN(s.cfg.Database) {
		backend = "postgres"
		dbInfo = "redacted"
	}

	return c.Status(http.StatusOK).JSON(map[string]string{
		"status":   "ok",
		"backend":  backend,
		"database": dbInfo,
	})
}

func validateTLSFiles(cfg config.Config) error {
	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		return fmt.Errorf("tls cert and key must be configured")
	}
	if _, err := os.Stat(cfg.TLSCert); err != nil {
		return fmt.Errorf("tls cert missing: %w", err)
	}
	if _, err := os.Stat(cfg.TLSKey); err != nil {
		return fmt.Errorf("tls key missing: %w", err)
	}
	return nil
}

func (s *Server) handleMetrics(c *fiber.Ctx) error {
	logRequestEntry(c, "Server.handleMetrics", nil)
	store, namespace, err := resolveNamespaceStore(c)
	if err != nil {
		return err
	}
	reqCounts, err := store.CountRequestsByGrantPresence(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("count requests")
		return fiber.NewError(http.StatusInternalServerError, "unable to collect request metrics")
	}
	grantCounts, err := store.CountGrants(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("count grants")
		return fiber.NewError(http.StatusInternalServerError, "unable to collect grant metrics")
	}
	registerCounts, err := store.CountRegisters(c.Context())
	if err != nil {
		logrus.WithError(err).WithField("namespace", namespace).Error("count registers")
		return fiber.NewError(http.StatusInternalServerError, "unable to collect register metrics")
	}

	return c.JSON(map[string]any{
		"requests":  reqCounts,
		"grants":    grantCounts,
		"registers": registerCounts,
	})
}

// Close releases all namespace databases.
func (s *Server) Close() error {
	return s.nsStore.Close()
}
