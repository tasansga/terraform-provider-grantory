package server

import (
	"net/http"

	"github.com/gofiber/fiber/v2"

	"github.com/tasansga/terraform-provider-grantory/internal/api"
)

type MetaResponse struct {
	ServerVersion string            `json:"server_version"`
	APIVersion    string            `json:"api_version"`
	Features      []api.FeatureInfo `json:"features"`
}

func (s *Server) handleMeta(c *fiber.Ctx) error {
	logRequestEntry(c, "Server.handleMeta", nil)

	serverVersion := s.cfg.ServerVersion
	if serverVersion == "" {
		serverVersion = "unknown"
	}

	return c.Status(http.StatusOK).JSON(MetaResponse{
		ServerVersion: serverVersion,
		APIVersion:    api.APIVersion,
		Features:      api.Features(),
	})
}
