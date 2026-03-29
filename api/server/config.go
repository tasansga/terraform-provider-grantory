package server

import (
	"fmt"

	"github.com/sirupsen/logrus"

	internalconfig "github.com/tasansga/terraform-provider-grantory/internal/config"
)

// Config configures the embedded HTTP server.
type Config struct {
	Database string
	BindAddr string
	TLSBind  string
	TLSCert  string
	TLSKey   string

	// LogLevel is a logrus level string, for example: "info", "debug", "warn".
	// When empty, the default server log level is used.
	LogLevel string

	ServerVersion string
}

// DefaultConfig returns defaults matching the Grantory server binary.
func DefaultConfig() Config {
	return Config{
		Database: internalconfig.DefaultDataDir,
		BindAddr: internalconfig.DefaultBindAddr,
		TLSBind:  internalconfig.DefaultTLSBind,
		LogLevel: internalconfig.DefaultLogLevel.String(),
	}
}

func (c Config) toInternalConfig() (internalconfig.Config, error) {
	cfg := c
	defaults := DefaultConfig()

	if cfg.Database == "" {
		cfg.Database = defaults.Database
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = defaults.BindAddr
	}
	if cfg.TLSBind == "" {
		cfg.TLSBind = defaults.TLSBind
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = defaults.LogLevel
	}

	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		return internalconfig.Config{}, fmt.Errorf("invalid log level %q: %w", cfg.LogLevel, err)
	}

	return internalconfig.Config{
		Database:      cfg.Database,
		BindAddr:      cfg.BindAddr,
		TLSBind:       cfg.TLSBind,
		TLSCert:       cfg.TLSCert,
		TLSKey:        cfg.TLSKey,
		LogLevel:      level,
		ServerVersion: cfg.ServerVersion,
	}, nil
}
