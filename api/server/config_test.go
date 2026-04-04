package server

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	internalconfig "github.com/tasansga/terraform-provider-grantory/internal/config"
)

func TestDefaultConfigIncludesUnixSocketDefaults(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	assert.Equal(t, internalconfig.DefaultUnixSocket, cfg.UnixSocket, "default unix socket")
	assert.Equal(t, uint32(internalconfig.DefaultUnixSocketMode), cfg.UnixSocketMode, "default unix socket mode")
}

func TestConfigToInternalConfigMapsUnixSocketFields(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Database:       "data",
		BindAddr:       "127.0.0.1:8080",
		TLSBind:        "off",
		UnixSocket:     "/tmp/grantory.sock",
		UnixSocketMode: 0o660,
		LogLevel:       "info",
	}

	internalCfg, err := cfg.toInternalConfig()
	assert.NoError(t, err, "toInternalConfig should succeed")
	assert.Equal(t, "/tmp/grantory.sock", internalCfg.UnixSocket, "unix socket mapping")
	assert.Equal(t, os.FileMode(0o660), internalCfg.UnixSocketMode, "unix socket mode mapping")
}
