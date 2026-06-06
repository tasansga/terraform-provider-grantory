package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

const (
	EnvDatabase       = "DATABASE"
	EnvBindAddr       = "HTTP_BIND"
	EnvTLSBind        = "HTTPS_BIND"
	EnvTLSCert        = "TLS_CERT"
	EnvTLSKey         = "TLS_KEY"
	EnvUnixSocket     = "UNIX_SOCKET"
	EnvUnixSocketMode = "UNIX_SOCKET_MODE"
	EnvLogLevel       = "LOG_LEVEL"
	EnvRequireSignatures = "REQUIRE_SIGNATURES"
)

const (
	DefaultDataDir        = "data"
	DefaultBindAddr       = "0.0.0.0:8080"
	DefaultTLSBind        = "0.0.0.0:8443"
	DefaultUnixSocket     = ""
	DefaultUnixSocketMode = os.FileMode(0o660)
)

const DefaultLogLevel = logrus.InfoLevel

// Config holds the runtime configuration for the Grantory server.
type Config struct {
	Database       string
	BindAddr       string
	TLSBind        string
	TLSCert        string
	TLSKey         string
	UnixSocket     string
	UnixSocketMode os.FileMode
	LogLevel       logrus.Level
	RequireSignatures bool
	ServerVersion  string
}

// RegisterFlags adds command-line flags to the provided FlagSet.
func RegisterFlags(fs *pflag.FlagSet) {
	fs.String("database", "", "database connection string or sqlite data directory (env: "+EnvDatabase+")")
	fs.String("http-bind", "", "interface:port for the HTTP listener (env: "+EnvBindAddr+"); set to 'off' to disable")
	fs.String("https-bind", "", "interface:port for the HTTPS listener when TLS is enabled (env: "+EnvTLSBind+"); set to 'off' to disable")
	fs.String("tls-cert", "", "path to the TLS certificate file (env: "+EnvTLSCert+")")
	fs.String("tls-key", "", "path to the TLS private key file (env: "+EnvTLSKey+")")
	fs.String("unix-socket", "", "path to a unix domain socket listener (env: "+EnvUnixSocket+"); leave empty or set to 'off' to disable")
	fs.String("unix-socket-mode", "", "unix socket file mode in octal (env: "+EnvUnixSocketMode+", default: 0660)")
	fs.String("log-level", "", "log level for the server (env: "+EnvLogLevel+")")
	fs.Bool("require-signatures", false, "enforce Ed25519 signatures for all write operations (env: "+EnvRequireSignatures+")")
}

// FromFlagSet builds a Config from the flag set and environment variables.
func FromFlagSet(fs *pflag.FlagSet) (Config, error) {
	database := stringValue(fs, "database", EnvDatabase, DefaultDataDir)
	bind := stringValue(fs, "http-bind", EnvBindAddr, DefaultBindAddr)
	tlsBind := stringValue(fs, "https-bind", EnvTLSBind, DefaultTLSBind)
	tlsCert := stringValue(fs, "tls-cert", EnvTLSCert, "")
	tlsKey := stringValue(fs, "tls-key", EnvTLSKey, "")
	unixSocket := stringValue(fs, "unix-socket", EnvUnixSocket, DefaultUnixSocket)
	unixSocketModeRaw := stringValue(fs, "unix-socket-mode", EnvUnixSocketMode, "0660")
	unixSocketMode, err := parseFileMode(unixSocketModeRaw)
	if err != nil {
		return Config{}, fmt.Errorf("invalid unix socket mode %q: %w", unixSocketModeRaw, err)
	}

	levelStr := stringValue(fs, "log-level", EnvLogLevel, DefaultLogLevel.String())
	level, err := logrus.ParseLevel(levelStr)
	if err != nil {
		return Config{}, fmt.Errorf("invalid log level %q: %w", levelStr, err)
	}

	requireSignatures := boolValue(fs, "require-signatures", EnvRequireSignatures, false)

	return Config{
		Database:          database,
		BindAddr:          bind,
		TLSBind:           tlsBind,
		TLSCert:           tlsCert,
		TLSKey:            tlsKey,
		UnixSocket:        unixSocket,
		UnixSocketMode:    unixSocketMode,
		LogLevel:          level,
		RequireSignatures: requireSignatures,
	}, nil
}

func boolValue(fs *pflag.FlagSet, name, envKey string, defaultValue bool) bool {
	if fs != nil {
		if fs.Changed(name) {
			val, err := fs.GetBool(name)
			if err == nil {
				return val
			}
		}
	}

	if v := os.Getenv(envKey); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err == nil {
			return parsed
		}
	}

	return defaultValue
}

func parseFileMode(raw string) (os.FileMode, error) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(raw), 8, 32)
	if err != nil {
		return 0, err
	}
	return os.FileMode(parsed), nil
}

func stringValue(fs *pflag.FlagSet, name, envKey, defaultValue string) string {
	if fs != nil {
		if fs.Changed(name) {
			val, err := fs.GetString(name)
			if err == nil && val != "" {
				return val
			}
		}
	}

	if v := os.Getenv(envKey); v != "" {
		return v
	}

	return defaultValue
}
