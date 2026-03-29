package server

import (
	"context"

	internalserver "github.com/tasansga/terraform-provider-grantory/internal/server"
)

// Server runs the Grantory HTTP API.
type Server struct {
	inner *internalserver.Server
}

// New constructs an embeddable Grantory HTTP server.
func New(ctx context.Context, cfg Config) (*Server, error) {
	internalCfg, err := cfg.toInternalConfig()
	if err != nil {
		return nil, err
	}

	inner, err := internalserver.New(ctx, internalCfg)
	if err != nil {
		return nil, err
	}

	return &Server{inner: inner}, nil
}

// Serve starts the server listeners and blocks until shutdown or failure.
func (s *Server) Serve(ctx context.Context) error {
	return s.inner.Serve(ctx)
}

// Close releases underlying namespace/database resources.
func (s *Server) Close() error {
	return s.inner.Close()
}
