package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestLoggingMiddlewareRecordsErrorStatus(t *testing.T) {
	t.Parallel()

	hook := test.NewGlobal()
	t.Cleanup(hook.Reset)

	app := fiber.New()
	app.Use(requestLoggingMiddleware())

	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	res, err := app.Test(req, 100)
	require.NoError(t, err, "unexpected app error")
	assert.Equal(t, http.StatusNotFound, res.StatusCode, "expected 404 status")

	var logged *logrus.Entry
	for i := len(hook.AllEntries()) - 1; i >= 0; i-- {
		candidate := hook.AllEntries()[i]
		if handler, ok := candidate.Data["handler"].(string); ok && handler == "Server.request" {
			if _, hasStatus := candidate.Data["status"]; hasStatus {
				logged = candidate
				break
			}
		}
	}

	require.NotNil(t, logged, "expected a log entry for Server.request")

	status, ok := logged.Data["status"].(int)
	assert.True(t, ok, "status should be int")
	assert.Equal(t, http.StatusNotFound, status, "expected logged status")
}
