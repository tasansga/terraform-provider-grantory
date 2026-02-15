package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

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
	store *storage.Store
}

type Server struct {
	cfg     config.Config
	nsStore *NamespaceStore
}

func New(ctx context.Context, cfg config.Config) (*Server, error) {
	nsStore, err := NewNamespaceStore(ctx, cfg.DataDir)
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
	app.Use(requestLoggingMiddleware())

	api := app.Group("/", s.namespaceMiddleware())

	registerHostRoutes(api)
	registerRequestRoutes(api)
	registerRegisterRoutes(api)
	registerGrantRoutes(api)
	api.Get("/metrics", s.handleMetrics)
	api.Get("/index.html", s.handleIndex)

	go func() {
		<-ctx.Done()
		_ = app.Shutdown()
	}()

	httpDisabled := isBindDisabled(s.cfg.BindAddr)
	httpsDisabled := isBindDisabled(s.cfg.TLSBind)

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
		errCh := make(chan error, errCount)
		if !httpDisabled {
			go func() {
				errCh <- app.Listen(s.cfg.BindAddr)
			}()
		}
		go func() {
			errCh <- app.ListenTLS(s.cfg.TLSBind, s.cfg.TLSCert, s.cfg.TLSKey)
		}()

		err := <-errCh
		if err != nil {
			_ = app.Shutdown()
		}
		return err
	}

	if httpDisabled {
		return fmt.Errorf("need at least one listener - http bind address must be enabled when TLS is disabled")
	}
	return app.Listen(s.cfg.BindAddr)
}

func isBindDisabled(addr string) bool {
	return strings.EqualFold(strings.TrimSpace(addr), "off")
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

	return c.Status(http.StatusOK).JSON(map[string]string{"status": "ok"})
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
