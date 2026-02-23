package config

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestFromFlagSetDefaults(t *testing.T) {
	fs := newTestFlagSet(t)
	assert.NoError(t, fs.Parse([]string{}), "unable to parse empty args")

	cfg, err := FromFlagSet(fs)
	assert.NoError(t, err, "unexpected error from FromFlagSet")

	assert.Equal(t, DefaultDataDir, cfg.Database, "default database")
	assert.Equal(t, DefaultBindAddr, cfg.BindAddr, "default bind addr")
	assert.Equal(t, DefaultTLSBind, cfg.TLSBind, "default tls bind addr")
	assert.Equal(t, "", cfg.TLSCert, "default tls cert")
	assert.Equal(t, "", cfg.TLSKey, "default tls key")
	assert.Equal(t, DefaultLogLevel, cfg.LogLevel, "default log level")
}

func TestFromFlagSetEnvOverrides(t *testing.T) {
	t.Setenv(EnvDatabase, "postgres://env")
	t.Setenv(EnvBindAddr, "127.0.0.1:9000")
	t.Setenv(EnvTLSBind, "127.0.0.1:9443")
	t.Setenv(EnvTLSCert, "/tmp/cert.pem")
	t.Setenv(EnvTLSKey, "/tmp/key.pem")
	t.Setenv(EnvLogLevel, "debug")

	fs := newTestFlagSet(t)
	assert.NoError(t, fs.Parse([]string{}), "unable to parse empty args")

	cfg, err := FromFlagSet(fs)
	assert.NoError(t, err, "unexpected error from FromFlagSet")

	assert.Equal(t, "postgres://env", cfg.Database, "database from env")
	assert.Equal(t, "127.0.0.1:9000", cfg.BindAddr, "bind addr from env")
	assert.Equal(t, "127.0.0.1:9443", cfg.TLSBind, "tls bind addr from env")
	assert.Equal(t, "/tmp/cert.pem", cfg.TLSCert, "tls cert from env")
	assert.Equal(t, "/tmp/key.pem", cfg.TLSKey, "tls key from env")
	assert.Equal(t, logLevelOrDefault("debug"), cfg.LogLevel, "log level from env")
}

func TestFromFlagSetFlagOverridesEnv(t *testing.T) {
	t.Setenv(EnvDatabase, "postgres://env")
	t.Setenv(EnvBindAddr, "127.0.0.1:9000")
	t.Setenv(EnvLogLevel, "debug")

	fs := newTestFlagSet(t)
	args := []string{
		"--database=postgres://flag",
		"--http-bind=0.0.0.0:8081",
		"--https-bind=0.0.0.0:8443",
		"--tls-cert=/etc/server.crt",
		"--tls-key=/etc/server.key",
		"--log-level=warn",
	}
	assert.NoError(t, fs.Parse(args), "unable to parse args")

	cfg, err := FromFlagSet(fs)
	assert.NoError(t, err, "unexpected error from FromFlagSet")

	assert.Equal(t, "postgres://flag", cfg.Database, "database from flag")
	assert.Equal(t, "0.0.0.0:8081", cfg.BindAddr, "bind addr from flag")
	assert.Equal(t, "0.0.0.0:8443", cfg.TLSBind, "tls bind addr from flag")
	assert.Equal(t, "/etc/server.crt", cfg.TLSCert, "tls cert from flag")
	assert.Equal(t, "/etc/server.key", cfg.TLSKey, "tls key from flag")
	assert.Equal(t, logLevelOrDefault("warn"), cfg.LogLevel, "log level from flag")
}

func TestFromFlagSetInvalidLogLevel(t *testing.T) {
	fs := newTestFlagSet(t)
	assert.NoError(t, fs.Parse([]string{"--log-level=unknown"}), "unable to parse args")

	_, err := FromFlagSet(fs)
	assert.Error(t, err, "expected an error for invalid log level")
}

func newTestFlagSet(t *testing.T) *pflag.FlagSet {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterFlags(fs)
	return fs
}

func logLevelOrDefault(value string) logrus.Level {
	level, err := logrus.ParseLevel(value)
	if err != nil {
		return DefaultLogLevel
	}
	return level
}
