package server

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"github.com/tasansga/terraform-provider-grantory/api/service"
	"github.com/tasansga/terraform-provider-grantory/internal/cluster/raft"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
	"github.com/tasansga/terraform-provider-grantory/internal/store"
)

const (
	storeCtxKey             = "grantory:store"
	namespaceCtxKey         = "grantory:namespace"
	requireSignaturesCtxKey = "grantory:require-signatures"
)

type Server struct {
	cfg         config.Config
	nsStore     *store.NamespaceStore
	raftNode    *raft.RaftNode
	proxyClient *fasthttp.Client
}

func New(ctx context.Context, cfg config.Config) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	nsStore, err := store.NewNamespaceStore(ctx, cfg.Database)
	if err != nil {
		return nil, err
	}

	var proxyClient *fasthttp.Client
	if cfg.IsRaftEnabled() {
		client, err := buildProxyClient(cfg)
		if err != nil {
			_ = nsStore.Close()
			return nil, fmt.Errorf("build proxy client: %w", err)
		}
		proxyClient = client
	}

	s := &Server{
		cfg:         cfg,
		nsStore:     nsStore,
		proxyClient: proxyClient,
	}
	if cfg.IsRaftEnabled() {
		raftNode, err := raft.NewRaftNode(ctx, cfg, nsStore, nsStore.DataDir())
		if err != nil {
			_ = nsStore.Close()
			return nil, fmt.Errorf("initialize raft node: %w", err)
		}
		s.raftNode = raftNode
	}

	return s, nil
}

func (s *Server) buildApp() *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			msg := err.Error()
			if fe, ok := asFiberError(err); ok {
				code = fe.Code
				msg = fe.Message
			}
			if (code == fiber.StatusServiceUnavailable || code == fiber.StatusBadGateway) && len(c.Response().Header.Peek("Retry-After")) == 0 {
				c.Set("Retry-After", "1")
			}
			c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
			return c.Status(code).SendString(msg)
		},
	})

	app.Get("/static/water.min.css", s.handleWaterCSS)
	app.Get("/", s.handleRoot)

	app.Get("/healthz", s.handleHealth)
	app.Get("/readyz", s.handleReadiness)
	app.Get("/meta", s.handleMeta)
	app.Use(requestLoggingMiddleware())

	var clusterMgr ClusterManager
	if s.raftNode != nil {
		clusterMgr = s.raftNode
	}
	registerClusterAdminAuth(app, s.cfg.RaftClusterSecret)
	app.Use(clusterRoutingMiddleware(clusterMgr, s.proxyClient))
	registerClusterRoutes(app, clusterMgr)

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

	return app
}

func (s *Server) Serve(ctx context.Context) error {
	app := s.buildApp()

	serveCtx, cancel := context.WithCancel(ctx)
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-serveCtx.Done()
		_ = app.Shutdown()
		if s.raftNode != nil {
			_ = s.raftNode.Close()
		}
	}()
	defer func() {
		cancel()
		<-shutdownDone
	}()

	var openedListeners []net.Listener
	var started bool
	defer func() {
		if !started {
			for _, l := range openedListeners {
				_ = l.Close()
			}
		}
	}()

	httpDisabled := isBindDisabled(s.cfg.BindAddr)
	unixSocketEnabled := isUnixSocketEnabled(s.cfg.UnixSocket)

	var unixListener net.Listener
	var unixCleanup func()
	if unixSocketEnabled {
		listener, cleanup, err := openUnixSocketListener(s.cfg.UnixSocket, s.cfg.UnixSocketMode)
		if err != nil {
			return err
		}
		unixListener = listener
		openedListeners = append(openedListeners, unixListener)
		unixCleanup = cleanup
		defer unixCleanup()
	}

	if IsTLSEnabled(s.cfg) {
		if !httpDisabled && s.cfg.TLSBind == s.cfg.BindAddr {
			return fmt.Errorf("https bind address must differ from http bind address")
		}

		tlsTcpLn, err := s.listenTCP(s.cfg.TLSBind, true)
		if err != nil {
			return err
		}
		openedListeners = append(openedListeners, tlsTcpLn)

		cer, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
		if err != nil {
			return err
		}
		tlsLn := tls.NewListener(tlsTcpLn, &tls.Config{Certificates: []tls.Certificate{cer}})

		var httpLn net.Listener
		if !httpDisabled {
			httpTcpLn, err := s.listenTCP(s.cfg.BindAddr, false)
			if err != nil {
				return err
			}
			openedListeners = append(openedListeners, httpTcpLn)
			httpLn = httpTcpLn
		}

		var listeners []net.Listener
		listeners = append(listeners, tlsLn)
		if httpLn != nil {
			listeners = append(listeners, httpLn)
		}
		if unixListener != nil {
			listeners = append(listeners, unixListener)
		}
		started = true
		return listenAndServe(app, listeners...)
	}

	if httpDisabled && !unixSocketEnabled {
		return fmt.Errorf("need at least one listener - enable http bind address or unix socket when TLS is disabled")
	}

	var listeners []net.Listener
	if !httpDisabled {
		httpTcpLn, err := s.listenTCP(s.cfg.BindAddr, false)
		if err != nil {
			return err
		}
		openedListeners = append(openedListeners, httpTcpLn)
		listeners = append(listeners, httpTcpLn)
	}
	if unixSocketEnabled {
		listeners = append(listeners, unixListener)
	}
	started = true
	return listenAndServe(app, listeners...)
}

func isClusterUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, storage.ErrLeadershipLost) ||
		errors.Is(err, storage.ErrNotLeader) ||
		errors.Is(err, service.ErrLeadershipLost) ||
		errors.Is(err, service.ErrNotLeader) ||
		isDatabaseClosedError(err)
}

func isDatabaseClosedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrConnDone) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "sql: database is closed") ||
		strings.Contains(msg, "database is closed") ||
		strings.Contains(msg, "bad connection")
}

// listenAndServe serves app concurrently on all provided listeners.
// When any listener exits (whether cleanly or with an error), it unconditionally
// shuts down app so that sibling listeners exit promptly without hanging.
func listenAndServe(app *fiber.App, listeners ...net.Listener) error {
	if len(listeners) == 0 {
		return fmt.Errorf("need at least one listener")
	}
	if len(listeners) == 1 {
		return app.Listener(listeners[0])
	}
	errCh := make(chan error, len(listeners))
	for _, ln := range listeners {
		ln := ln
		go func() {
			errCh <- app.Listener(ln)
		}()
	}
	err := <-errCh
	_ = app.Shutdown()
	return err
}

func (s *Server) listenTCP(addr string, isTLSListener bool) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if s.raftNode != nil && (isTLSListener || !s.raftNode.IsTLS()) {
		if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
			s.raftNode.SetHTTPPort(strconv.Itoa(tcpAddr.Port))
		}
	}
	return ln, nil
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
			if isClusterUnavailableError(err) {
				status = fiber.StatusServiceUnavailable
			} else {
				var fe *fiber.Error
				if errors.As(err, &fe) {
					status = fe.Code
				} else if status < http.StatusBadRequest {
					status = http.StatusInternalServerError
				}
			}
		}
		// Safety fallback: ensure Retry-After: 1 is injected even on non-error direct
		// 503/502 responses (e.g., from proxy middleware or direct handler responses)
		// that bypass Fiber's central ErrorHandler.
		if status == fiber.StatusServiceUnavailable || status == fiber.StatusBadGateway {
			if len(c.Response().Header.Peek("Retry-After")) == 0 {
				c.Set("Retry-After", "1")
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

type unclosableStore struct {
	storage.Store
}

func (u unclosableStore) Close() error {
	return nil
}

func (u unclosableStore) Unwrap() storage.Store {
	return u.Store
}

func (u unclosableStore) SupportsSignatureBundling() bool {
	return checkSignatureBundling(u.Store)
}

func (s *Server) namespaceMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		namespace := c.Get("REMOTE_USER")
		if namespace == "" {
			namespace = store.DefaultNamespace
		}
		storeInstance, err := s.nsStore.StoreFor(c.UserContext(), namespace)
		if err != nil {
			if errors.Is(err, store.ErrInvalidNamespace) {
				return fiber.NewError(fiber.StatusBadRequest, err.Error())
			}
			logrus.WithError(err).WithField("namespace", namespace).Error("prepare namespace store")
			return fiber.NewError(fiber.StatusInternalServerError, "unable to access namespace data")
		}

		if s.raftNode != nil {
			c.Locals(storeCtxKey, newRaftStore(storeInstance, s.raftNode, namespace))
		} else {
			c.Locals(storeCtxKey, unclosableStore{Store: storeInstance})
		}
		c.Locals(namespaceCtxKey, namespace)
		c.Locals(requireSignaturesCtxKey, s.cfg.RequireSignatures)
		// Clear storeCtxKey on return to prevent fasthttp's (*userData).Reset() from invoking
		// io.Closer.Close() on the long-lived singleton namespace store when recycling fiber.Ctx.
		defer c.Locals(storeCtxKey, nil)
		return c.Next()
	}
}

func IsTLSEnabled(cfg config.Config) bool {
	return cfg.IsTLSEnabled()
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

	if s.raftNode != nil {
		if s.raftNode.LeaderAddr() == "" && !s.raftNode.IsLeader() {
			c.Set("Retry-After", "1")
			return fiber.NewError(http.StatusServiceUnavailable, "raft cluster has no leader")
		}
	}

	if _, err := s.nsStore.StoreFor(c.UserContext(), store.DefaultNamespace); err != nil {
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
	reqCounts, err := store.CountRequestsByGrantPresence(c.UserContext())
	if err != nil {
		if isClusterUnavailableError(err) {
			fe, _ := asFiberError(err)
			return fe
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("count requests")
		return fiber.NewError(http.StatusInternalServerError, "unable to collect request metrics")
	}
	grantCounts, err := store.CountGrants(c.UserContext())
	if err != nil {
		if isClusterUnavailableError(err) {
			fe, _ := asFiberError(err)
			return fe
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("count grants")
		return fiber.NewError(http.StatusInternalServerError, "unable to collect grant metrics")
	}
	registerCounts, err := store.CountRegisters(c.UserContext())
	if err != nil {
		if isClusterUnavailableError(err) {
			fe, _ := asFiberError(err)
			return fe
		}
		logrus.WithError(err).WithField("namespace", namespace).Error("count registers")
		return fiber.NewError(http.StatusInternalServerError, "unable to collect register metrics")
	}

	return c.JSON(map[string]any{
		"requests":  reqCounts,
		"grants":    grantCounts,
		"registers": registerCounts,
	})
}

// Close releases all namespace databases and cluster resources.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var firstErr error
	if s.raftNode != nil {
		if err := s.raftNode.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.proxyClient != nil {
		s.proxyClient.CloseIdleConnections()
	}
	if s.nsStore != nil {
		if err := s.nsStore.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// RaftNode returns the underlying RaftNode if clustering is enabled.
func (s *Server) RaftNode() *raft.RaftNode {
	if s == nil {
		return nil
	}
	return s.raftNode
}

// buildProxyClient constructs a fasthttp.Client configured with cluster TLS settings.
// fasthttp is used specifically for reverse-proxying user HTTP API requests from follower nodes
// to the leader to achieve high-throughput request proxying with minimal memory allocation.
// In contrast, internal control plane RPCs (such as cluster join, status probing, and leader step-down)
// use standard net/http.Client via clusterraft.BuildClusterHTTPClient.
func buildProxyClient(cfg config.Config) (*fasthttp.Client, error) {
	tlsConfig, err := config.BuildClusterTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &fasthttp.Client{
		TLSConfig:       tlsConfig,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    10 * time.Second,
		MaxConnDuration: 60 * time.Second,
	}, nil
}
