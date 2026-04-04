package server

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	internalconfig "github.com/tasansga/terraform-provider-grantory/internal/config"
)

// Config configures the embedded HTTP server.
type Config struct {
	Database       string
	BindAddr       string
	TLSBind        string
	TLSCert        string
	TLSKey         string
	UnixSocket     string
	UnixSocketMode uint32

	// LogLevel is a logrus level string, for example: "info", "debug", "warn".
	// When empty, the default server log level is used.
	LogLevel string

	ServerVersion string
}

// DefaultConfig returns defaults matching the Grantory server binary.
func DefaultConfig() Config {
	return Config{
		Database:       internalconfig.DefaultDataDir,
		BindAddr:       internalconfig.DefaultBindAddr,
		TLSBind:        internalconfig.DefaultTLSBind,
		UnixSocket:     internalconfig.DefaultUnixSocket,
		UnixSocketMode: uint32(internalconfig.DefaultUnixSocketMode),
		LogLevel:       internalconfig.DefaultLogLevel.String(),
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
	if cfg.UnixSocketMode == 0 {
		cfg.UnixSocketMode = defaults.UnixSocketMode
	}

	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		return internalconfig.Config{}, fmt.Errorf("invalid log level %q: %w", cfg.LogLevel, err)
	}

	return internalconfig.Config{
		Database:       cfg.Database,
		BindAddr:       cfg.BindAddr,
		TLSBind:        cfg.TLSBind,
		TLSCert:        cfg.TLSCert,
		TLSKey:         cfg.TLSKey,
		UnixSocket:     cfg.UnixSocket,
		UnixSocketMode: os.FileMode(cfg.UnixSocketMode),
		LogLevel:       level,
		ServerVersion:  cfg.ServerVersion,
	}, nil
}
