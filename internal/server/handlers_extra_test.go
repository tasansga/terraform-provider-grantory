package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

func TestStoreFromLocalsVariants(t *testing.T) {
	t.Parallel()

	st, err := storage.New(context.Background(), ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		return
	}
	defer func() {
		assert.NoError(t, st.Close(), "close store")
	}()

	assert.Equal(t, st, storeFromLocals(st))
	assert.Nil(t, storeFromLocals(nil))
	assert.Nil(t, storeFromLocals("unexpected"))
	assert.Nil(t, storeFromLocals(12345))
	assert.Nil(t, storeFromLocals(true))
	assert.Nil(t, storeFromLocals(struct{ A string }{A: "foo"}))
	var nilStore storage.Store
	assert.Nil(t, storeFromLocals(nilStore))
}


func TestAsFiberError_TimeoutAndCancellation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"DeadlineExceeded", context.DeadlineExceeded},
		{"Canceled", context.Canceled},
		{"WrappedDeadlineExceeded", fmt.Errorf("timeout: %w", context.DeadlineExceeded)},
		{"WrappedCanceled", fmt.Errorf("canceled: %w", context.Canceled)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fe, ok := asFiberError(tc.err)
			assert.True(t, ok)
			if assert.NotNil(t, fe) {
				assert.Equal(t, fiber.StatusRequestTimeout, fe.Code)
				assert.Equal(t, "operation timed out or cancelled", fe.Message)
			}
		})
	}
}

func TestAsFiberError_StorageLeadershipErrors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		err         error
		expectedMsg string
	}{
		{"ErrNotLeader", storage.ErrNotLeader, "not cluster leader"},
		{"ErrLeadershipLost", storage.ErrLeadershipLost, "cluster leader changed during operation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fe, ok := asFiberError(tc.err)
			assert.True(t, ok)
			if assert.NotNil(t, fe) {
				assert.Equal(t, fiber.StatusServiceUnavailable, fe.Code)
				assert.Equal(t, tc.expectedMsg, fe.Message)
			}
		})
	}
}

func TestAsFiberError_DatabaseClosedErrors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"ErrConnDone", sql.ErrConnDone},
		{"WrappedErrConnDone", fmt.Errorf("connection closed: %w", sql.ErrConnDone)},
		{"SQLDatabaseIsClosed", errors.New("sql: database is closed")},
		{"DatabaseIsClosed", errors.New("database is closed")},
		{"BadConnection", errors.New("driver: bad connection")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fe, ok := asFiberError(tc.err)
			assert.True(t, ok)
			if assert.NotNil(t, fe) {
				assert.Equal(t, fiber.StatusServiceUnavailable, fe.Code)
				assert.Equal(t, "database temporarily unavailable", fe.Message)
			}
		})
	}
}

type mockFailingStore struct {
	storage.Store
	err error
}

func (m *mockFailingStore) Close() error {
	return nil
}

func (m *mockFailingStore) CreateHost(ctx context.Context, host storage.Host) (storage.Host, error) {
	return storage.Host{}, m.err
}

func (m *mockFailingStore) GetHost(ctx context.Context, id string) (storage.Host, error) {
	return storage.Host{}, m.err
}

func (m *mockFailingStore) ListHosts(ctx context.Context) ([]storage.Host, error) {
	return nil, m.err
}

func (m *mockFailingStore) CreateRequest(ctx context.Context, req storage.Request) (storage.Request, error) {
	return storage.Request{}, m.err
}

func (m *mockFailingStore) GetRequest(ctx context.Context, id string) (storage.Request, error) {
	return storage.Request{}, m.err
}

func (m *mockFailingStore) ListRequests(ctx context.Context, filters *storage.RequestListFilters) ([]storage.Request, error) {
	return nil, m.err
}

func (m *mockFailingStore) CreateRegister(ctx context.Context, reg storage.Register) (storage.Register, error) {
	return storage.Register{}, m.err
}

func (m *mockFailingStore) GetRegister(ctx context.Context, id string) (storage.Register, error) {
	return storage.Register{}, m.err
}

func (m *mockFailingStore) ListRegisters(ctx context.Context, filters *storage.RegisterListFilters) ([]storage.Register, error) {
	return nil, m.err
}

func (m *mockFailingStore) ListRegisterEvents(ctx context.Context, registerID string) ([]storage.RegisterEvent, error) {
	return nil, m.err
}

func (m *mockFailingStore) CreateSchemaDefinition(ctx context.Context, def storage.SchemaDefinition) (storage.SchemaDefinition, error) {
	return storage.SchemaDefinition{}, m.err
}

func (m *mockFailingStore) GetSchemaDefinition(ctx context.Context, id string) (storage.SchemaDefinition, error) {
	return storage.SchemaDefinition{}, m.err
}

func (m *mockFailingStore) ListSchemaDefinitions(ctx context.Context) ([]storage.SchemaDefinition, error) {
	return nil, m.err
}

func (m *mockFailingStore) CreateGrant(ctx context.Context, grant storage.Grant) (storage.Grant, error) {
	return storage.Grant{}, m.err
}

func (m *mockFailingStore) GetGrant(ctx context.Context, id string) (storage.Grant, error) {
	return storage.Grant{}, m.err
}

func (m *mockFailingStore) ListGrants(ctx context.Context) ([]storage.Grant, error) {
	return nil, m.err
}

func (m *mockFailingStore) DeleteHost(ctx context.Context, id string) error {
	return m.err
}

func (m *mockFailingStore) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) error {
	return m.err
}

func (m *mockFailingStore) UpdateRequest(ctx context.Context, id string, payload *map[string]any, labels *map[string]string) error {
	return m.err
}

func (m *mockFailingStore) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) error {
	return m.err
}

func (m *mockFailingStore) DeleteRequest(ctx context.Context, id string) error {
	return m.err
}

func (m *mockFailingStore) UpdateRegister(ctx context.Context, id string, payload *map[string]any, labels *map[string]string) error {
	return m.err
}

func (m *mockFailingStore) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) error {
	return m.err
}

func (m *mockFailingStore) DeleteRegister(ctx context.Context, id string) error {
	return m.err
}

func (m *mockFailingStore) UpdateGrant(ctx context.Context, id string, payload map[string]any, requestVersion int) error {
	return m.err
}

func (m *mockFailingStore) DeleteGrant(ctx context.Context, id string) error {
	return m.err
}

func (m *mockFailingStore) UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) error {
	return m.err
}

func (m *mockFailingStore) DeleteSchemaDefinition(ctx context.Context, id string) error {
	return m.err
}

func TestHandler_StorageLeadershipErrorsReturn503WithRetryAfter(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		err         error
		expectedMsg string
	}{
		{storage.ErrNotLeader, "not cluster leader"},
		{storage.ErrLeadershipLost, "cluster leader changed during operation"},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			app := fiber.New(fiber.Config{
				ErrorHandler: func(c *fiber.Ctx, err error) error {
					code := fiber.StatusInternalServerError
					var fe *fiber.Error
					if errors.As(err, &fe) {
						code = fe.Code
					}
					if code == fiber.StatusServiceUnavailable && len(c.Response().Header.Peek("Retry-After")) == 0 {
						c.Set("Retry-After", "1")
					}
					return c.Status(code).SendString(err.Error())
				},
			})

			mockSt := &mockFailingStore{err: tc.err}
			api := app.Group("/", func(c *fiber.Ctx) error {
				c.Locals(storeCtxKey, mockSt)
				c.Locals(namespaceCtxKey, "default")
				return c.Next()
			})
			registerHostRoutes(api)

			req := httptest.NewRequest(http.MethodPost, "/hosts", strings.NewReader(`{"unique_key":"h1"}`))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
			assert.Equal(t, "1", resp.Header.Get("Retry-After"))
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), tc.expectedMsg)
		})
	}
}

func TestVerifySignature_StorageLeadershipErrorReturns503(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		err         error
		expectedMsg string
	}{
		{storage.ErrLeadershipLost, "cluster leader changed during operation"},
		{storage.ErrNotLeader, "not cluster leader"},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			app := fiber.New(fiber.Config{
				ErrorHandler: func(c *fiber.Ctx, err error) error {
					code := fiber.StatusInternalServerError
					var fe *fiber.Error
					if errors.As(err, &fe) {
						code = fe.Code
					}
					if code == fiber.StatusServiceUnavailable && len(c.Response().Header.Peek("Retry-After")) == 0 {
						c.Set("Retry-After", "1")
					}
					return c.Status(code).SendString(err.Error())
				},
			})

			mockSt := &mockFailingStore{err: tc.err}
			api := app.Group("/", func(c *fiber.Ctx) error {
				c.Locals(storeCtxKey, mockSt)
				c.Locals(namespaceCtxKey, "default")
				return c.Next()
			})
			registerHostRoutes(api)

			req := httptest.NewRequest(http.MethodDelete, "/hosts/host-123", nil)
			resp, err := app.Test(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
			assert.Equal(t, "1", resp.Header.Get("Retry-After"))
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), tc.expectedMsg)
		})
	}
}

func TestVerifySignature_UnexpectedStorageErrorReturns500(t *testing.T) {
	t.Parallel()

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			var fe *fiber.Error
			if errors.As(err, &fe) {
				code = fe.Code
			}
			return c.Status(code).SendString(err.Error())
		},
	})

	mockSt := &mockFailingStore{err: errors.New("unexpected disk I/O failure")}
	api := app.Group("/", func(c *fiber.Ctx) error {
		c.Locals(storeCtxKey, mockSt)
		c.Locals(namespaceCtxKey, "default")
		return c.Next()
	})
	registerHostRoutes(api)

	req := httptest.NewRequest(http.MethodDelete, "/hosts/host-123", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "unable to fetch host for signature verification")
}

func TestVerifySignature_RequireSignaturesStorageLeadershipErrorReturns503(t *testing.T) {
	t.Parallel()

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			var fe *fiber.Error
			if errors.As(err, &fe) {
				code = fe.Code
			}
			if code == fiber.StatusServiceUnavailable && len(c.Response().Header.Peek("Retry-After")) == 0 {
				c.Set("Retry-After", "1")
			}
			return c.Status(code).SendString(err.Error())
		},
	})

	mockSt := &mockFailingStore{err: storage.ErrLeadershipLost}
	api := app.Group("/", func(c *fiber.Ctx) error {
		c.Locals(storeCtxKey, mockSt)
		c.Locals(namespaceCtxKey, "default")
		c.Locals(requireSignaturesCtxKey, true)
		return c.Next()
	})
	registerHostRoutes(api)

	req := httptest.NewRequest(http.MethodDelete, "/hosts/host-123", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "1", resp.Header.Get("Retry-After"))
}

func TestReadEndpointsAndPreReadChecks_StorageLeadershipErrorsReturn503WithRetryAfter(t *testing.T) {
	t.Parallel()

	leadershipErrors := []struct {
		name        string
		err         error
		expectedMsg string
	}{
		{"ErrNotLeader", storage.ErrNotLeader, "not cluster leader"},
		{"ErrLeadershipLost", storage.ErrLeadershipLost, "cluster leader changed during operation"},
	}

	endpoints := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
	}{
		// Read endpoints
		{name: "ListHosts", method: http.MethodGet, path: "/hosts"},
		{name: "GetHost", method: http.MethodGet, path: "/hosts/h1"},
		{name: "ListRequests", method: http.MethodGet, path: "/requests"},
		{name: "GetRequest", method: http.MethodGet, path: "/requests/r1"},
		{name: "ListRegisters", method: http.MethodGet, path: "/registers"},
		{name: "GetRegister", method: http.MethodGet, path: "/registers/reg1"},
		{name: "ListRegisterEvents", method: http.MethodGet, path: "/registers/reg1/events"},
		{name: "ListSchemaDefinitions", method: http.MethodGet, path: "/schema-definitions"},
		{name: "GetSchemaDefinition", method: http.MethodGet, path: "/schema-definitions/sd1"},
		{name: "ListGrants", method: http.MethodGet, path: "/grants"},
		{name: "GetGrant", method: http.MethodGet, path: "/grants/g1"},
		// Pre-read checks (entity lookups before signature check / mutation)
		{name: "UpdateRequest_PreRead", method: http.MethodPatch, path: "/requests/r1", body: `{"labels":{"env":"prod"}}`, contentType: "application/json"},
		{name: "DeleteRequest_PreRead", method: http.MethodDelete, path: "/requests/r1"},
		{name: "UpdateRegister_PreRead", method: http.MethodPatch, path: "/registers/reg1", body: `{"labels":{"env":"prod"}}`, contentType: "application/json"},
		{name: "DeleteRegister_PreRead", method: http.MethodDelete, path: "/registers/reg1"},
	}

	for _, lErr := range leadershipErrors {
		lErr := lErr
		t.Run(lErr.name, func(t *testing.T) {
			t.Parallel()

			app := fiber.New(fiber.Config{
				ErrorHandler: func(c *fiber.Ctx, err error) error {
					code := fiber.StatusInternalServerError
					var fe *fiber.Error
					if errors.As(err, &fe) {
						code = fe.Code
					}
					if code == fiber.StatusServiceUnavailable && len(c.Response().Header.Peek("Retry-After")) == 0 {
						c.Set("Retry-After", "1")
					}
					return c.Status(code).SendString(err.Error())
				},
			})

			mockSt := &mockFailingStore{err: lErr.err}
			api := app.Group("/", func(c *fiber.Ctx) error {
				c.Locals(storeCtxKey, mockSt)
				c.Locals(namespaceCtxKey, "default")
				return c.Next()
			})
			registerHostRoutes(api)
			registerRequestRoutes(api)
			registerRegisterRoutes(api)
			registerSchemaDefinitionRoutes(api)
			registerGrantRoutes(api)

			for _, ep := range endpoints {
				ep := ep
				t.Run(ep.name, func(t *testing.T) {
					var bodyReader io.Reader
					if ep.body != "" {
						bodyReader = strings.NewReader(ep.body)
					}
					req := httptest.NewRequest(ep.method, ep.path, bodyReader)
					if ep.contentType != "" {
						req.Header.Set("Content-Type", ep.contentType)
					}
					resp, err := app.Test(req)
					require.NoError(t, err)
					defer func() { _ = resp.Body.Close() }()

					assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "expected 503 for %s %s", ep.method, ep.path)
					assert.Equal(t, "1", resp.Header.Get("Retry-After"), "expected Retry-After: 1 for %s %s", ep.method, ep.path)
					bodyBytes, err := io.ReadAll(resp.Body)
					require.NoError(t, err)
					assert.Contains(t, string(bodyBytes), lErr.expectedMsg, "body should contain error message for %s %s", ep.method, ep.path)
				})
			}
		})
	}
}

func TestWriteEndpoints_TimeoutAndCancellationReturn408(t *testing.T) {
	t.Parallel()

	timeoutErrors := []struct {
		name string
		err  error
	}{
		{"DeadlineExceeded", context.DeadlineExceeded},
		{"Canceled", context.Canceled},
	}

	endpoints := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
	}{
		{name: "CreateHost", method: http.MethodPost, path: "/hosts", body: `{"unique_key":"h1"}`, contentType: "application/json"},
		{name: "DeleteHost", method: http.MethodDelete, path: "/hosts/h1"},
		{name: "UpdateHostLabels", method: http.MethodPatch, path: "/hosts/h1/labels", body: `{"labels":{"env":"prod"}}`, contentType: "application/json"},
		{name: "CreateRequest", method: http.MethodPost, path: "/requests", body: `{"host_id":"h1"}`, contentType: "application/json"},
		{name: "UpdateRequest", method: http.MethodPatch, path: "/requests/r1", body: `{"labels":{"env":"prod"}}`, contentType: "application/json"},
		{name: "DeleteRequest", method: http.MethodDelete, path: "/requests/r1"},
		{name: "CreateRegister", method: http.MethodPost, path: "/registers", body: `{"host_id":"h1","unique_key":"reg1"}`, contentType: "application/json"},
		{name: "UpdateRegister", method: http.MethodPatch, path: "/registers/reg1", body: `{"labels":{"env":"prod"}}`, contentType: "application/json"},
		{name: "DeleteRegister", method: http.MethodDelete, path: "/registers/reg1"},
		{name: "CreateGrant", method: http.MethodPost, path: "/grants", body: `{"request_id":"req1","request_version":1,"payload":{"role":"admin"}}`, contentType: "application/json"},
		{name: "UpdateGrant", method: http.MethodPatch, path: "/grants/g1", body: `{"request_version":1,"payload":{"role":"admin"}}`, contentType: "application/json"},
		{name: "DeleteGrant", method: http.MethodDelete, path: "/grants/g1"},
		{name: "CreateSchemaDefinition", method: http.MethodPost, path: "/schema-definitions", body: `{"unique_key":"sd1","schema":{"type":"object"}}`, contentType: "application/json"},
		{name: "UpdateSchemaDefinitionLabels", method: http.MethodPatch, path: "/schema-definitions/sd1/labels", body: `{"labels":{"env":"prod"}}`, contentType: "application/json"},
		{name: "DeleteSchemaDefinition", method: http.MethodDelete, path: "/schema-definitions/sd1"},
	}

	for _, tErr := range timeoutErrors {
		tErr := tErr
		t.Run(tErr.name, func(t *testing.T) {
			t.Parallel()

			app := fiber.New(fiber.Config{
				ErrorHandler: func(c *fiber.Ctx, err error) error {
					code := fiber.StatusInternalServerError
					var fe *fiber.Error
					if errors.As(err, &fe) {
						code = fe.Code
					}
					return c.Status(code).SendString(err.Error())
				},
			})

			mockSt := &mockFailingStore{err: tErr.err}
			api := app.Group("/", func(c *fiber.Ctx) error {
				c.Locals(storeCtxKey, mockSt)
				c.Locals(namespaceCtxKey, "default")
				return c.Next()
			})
			registerHostRoutes(api)
			registerRequestRoutes(api)
			registerRegisterRoutes(api)
			registerSchemaDefinitionRoutes(api)
			registerGrantRoutes(api)

			for _, ep := range endpoints {
				ep := ep
				t.Run(ep.name, func(t *testing.T) {
					var bodyReader io.Reader
					if ep.body != "" {
						bodyReader = strings.NewReader(ep.body)
					}
					req := httptest.NewRequest(ep.method, ep.path, bodyReader)
					if ep.contentType != "" {
						req.Header.Set("Content-Type", ep.contentType)
					}
					resp, err := app.Test(req)
					require.NoError(t, err)
					defer func() { _ = resp.Body.Close() }()

					assert.Equal(t, http.StatusRequestTimeout, resp.StatusCode, "expected 408 for %s %s", ep.method, ep.path)
					bodyBytes, err := io.ReadAll(resp.Body)
					require.NoError(t, err)
					assert.Contains(t, string(bodyBytes), "operation timed out or cancelled", "body should contain error message for %s %s", ep.method, ep.path)
				})
			}
		})
	}
}

type mockPreReadSuccessWriteFailingStore struct {
	storage.Store
	writeErr error
}

func (m *mockPreReadSuccessWriteFailingStore) Close() error { return nil }

func (m *mockPreReadSuccessWriteFailingStore) GetRequest(ctx context.Context, id string) (storage.Request, error) {
	return storage.Request{ID: id, HostID: "h1", Version: 1, Mutable: true}, nil
}

func (m *mockPreReadSuccessWriteFailingStore) GetRegister(ctx context.Context, id string) (storage.Register, error) {
	return storage.Register{ID: id, HostID: "h1", Mutable: true}, nil
}

func (m *mockPreReadSuccessWriteFailingStore) GetGrant(ctx context.Context, id string) (storage.Grant, error) {
	return storage.Grant{ID: id, RequestID: "req1", RequestVersion: 1}, nil
}

func (m *mockPreReadSuccessWriteFailingStore) GetGrantForRequest(ctx context.Context, requestID string) (storage.Grant, bool, error) {
	return storage.Grant{}, false, nil
}

func (m *mockPreReadSuccessWriteFailingStore) GetHost(ctx context.Context, id string) (storage.Host, error) {
	return storage.Host{ID: id}, nil
}

func (m *mockPreReadSuccessWriteFailingStore) GetSchemaDefinition(ctx context.Context, id string) (storage.SchemaDefinition, error) {
	return storage.SchemaDefinition{ID: id}, nil
}

func (m *mockPreReadSuccessWriteFailingStore) CreateHost(ctx context.Context, host storage.Host) (storage.Host, error) {
	return storage.Host{}, m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) DeleteHost(ctx context.Context, id string) error {
	return m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) error {
	return m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) CreateRequest(ctx context.Context, req storage.Request) (storage.Request, error) {
	return storage.Request{}, m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) UpdateRequest(ctx context.Context, id string, payload *map[string]any, labels *map[string]string) error {
	return m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) error {
	return m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) DeleteRequest(ctx context.Context, id string) error {
	return m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) CreateRegister(ctx context.Context, reg storage.Register) (storage.Register, error) {
	return storage.Register{}, m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) UpdateRegister(ctx context.Context, id string, payload *map[string]any, labels *map[string]string) error {
	return m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) error {
	return m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) DeleteRegister(ctx context.Context, id string) error {
	return m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) CreateGrant(ctx context.Context, grant storage.Grant) (storage.Grant, error) {
	return storage.Grant{}, m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) UpdateGrant(ctx context.Context, id string, payload map[string]any, requestVersion int) error {
	return m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) DeleteGrant(ctx context.Context, id string) error {
	return m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) CreateSchemaDefinition(ctx context.Context, def storage.SchemaDefinition) (storage.SchemaDefinition, error) {
	return storage.SchemaDefinition{}, m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) error {
	return m.writeErr
}

func (m *mockPreReadSuccessWriteFailingStore) DeleteSchemaDefinition(ctx context.Context, id string) error {
	return m.writeErr
}

func TestWriteMutation_TimeoutAndCancellationReturn408(t *testing.T) {
	t.Parallel()

	timeoutErrors := []struct {
		name string
		err  error
	}{
		{"DeadlineExceeded", context.DeadlineExceeded},
		{"Canceled", context.Canceled},
	}

	endpoints := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
	}{
		{name: "UpdateRequest_Mutation", method: http.MethodPatch, path: "/requests/r1", body: `{"labels":{"env":"prod"}}`, contentType: "application/json"},
		{name: "DeleteRequest_Mutation", method: http.MethodDelete, path: "/requests/r1"},
		{name: "UpdateRegister_Mutation", method: http.MethodPatch, path: "/registers/reg1", body: `{"labels":{"env":"prod"}}`, contentType: "application/json"},
		{name: "DeleteRegister_Mutation", method: http.MethodDelete, path: "/registers/reg1"},
		{name: "UpdateGrant_Mutation", method: http.MethodPatch, path: "/grants/g1", body: `{"request_version":1,"payload":{"role":"admin"}}`, contentType: "application/json"},
		{name: "DeleteGrant_Mutation", method: http.MethodDelete, path: "/grants/g1"},
		{name: "DeleteHost_Mutation", method: http.MethodDelete, path: "/hosts/h1"},
		{name: "UpdateHostLabels_Mutation", method: http.MethodPatch, path: "/hosts/h1/labels", body: `{"labels":{"env":"prod"}}`, contentType: "application/json"},
		{name: "UpdateSchemaDefinitionLabels_Mutation", method: http.MethodPatch, path: "/schema-definitions/sd1/labels", body: `{"labels":{"env":"prod"}}`, contentType: "application/json"},
		{name: "DeleteSchemaDefinition_Mutation", method: http.MethodDelete, path: "/schema-definitions/sd1"},
	}

	for _, tErr := range timeoutErrors {
		tErr := tErr
		t.Run(tErr.name, func(t *testing.T) {
			t.Parallel()

			app := fiber.New(fiber.Config{
				ErrorHandler: func(c *fiber.Ctx, err error) error {
					code := fiber.StatusInternalServerError
					var fe *fiber.Error
					if errors.As(err, &fe) {
						code = fe.Code
					}
					return c.Status(code).SendString(err.Error())
				},
			})

			mockSt := &mockPreReadSuccessWriteFailingStore{writeErr: tErr.err}
			api := app.Group("/", func(c *fiber.Ctx) error {
				c.Locals(storeCtxKey, mockSt)
				c.Locals(namespaceCtxKey, "default")
				return c.Next()
			})
			registerHostRoutes(api)
			registerRequestRoutes(api)
			registerRegisterRoutes(api)
			registerSchemaDefinitionRoutes(api)
			registerGrantRoutes(api)

			for _, ep := range endpoints {
				ep := ep
				t.Run(ep.name, func(t *testing.T) {
					var bodyReader io.Reader
					if ep.body != "" {
						bodyReader = strings.NewReader(ep.body)
					}
					req := httptest.NewRequest(ep.method, ep.path, bodyReader)
					if ep.contentType != "" {
						req.Header.Set("Content-Type", ep.contentType)
					}
					resp, err := app.Test(req)
					require.NoError(t, err)
					defer func() { _ = resp.Body.Close() }()

					assert.Equal(t, http.StatusRequestTimeout, resp.StatusCode, "expected 408 for %s %s", ep.method, ep.path)
					bodyBytes, err := io.ReadAll(resp.Body)
					require.NoError(t, err)
					assert.Contains(t, string(bodyBytes), "operation timed out or cancelled", "body should contain error message for %s %s", ep.method, ep.path)
				})
			}
		})
	}
}
