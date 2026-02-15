package config

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

const (
	EnvDataDir  = "DATA_DIR"
	EnvBindAddr = "HTTP_BIND"
	EnvTLSBind  = "HTTPS_BIND"
	EnvTLSCert  = "TLS_CERT"
	EnvTLSKey   = "TLS_KEY"
	EnvLogLevel = "LOG_LEVEL"
)

const (
	DefaultDataDir  = "data"
	DefaultBindAddr = "0.0.0.0:8080"
	DefaultTLSBind  = "0.0.0.0:8443"
)

const DefaultLogLevel = logrus.InfoLevel

// Config holds the runtime configuration for the Grantory server.
type Config struct {
	DataDir  string
	BindAddr string
	TLSBind  string
	TLSCert  string
	TLSKey   string
	LogLevel logrus.Level
}

// RegisterFlags adds command-line flags to the provided FlagSet.
func RegisterFlags(fs *pflag.FlagSet) {
	fs.String("data-dir", "", "path to the directory that contains namespace databases (env: "+EnvDataDir+")")
	fs.String("http-bind", "", "interface:port for the HTTP listener (env: "+EnvBindAddr+"); set to 'off' to disable")
	fs.String("https-bind", "", "interface:port for the HTTPS listener when TLS is enabled (env: "+EnvTLSBind+"); set to 'off' to disable")
	fs.String("tls-cert", "", "path to the TLS certificate file (env: "+EnvTLSCert+")")
	fs.String("tls-key", "", "path to the TLS private key file (env: "+EnvTLSKey+")")
	fs.String("log-level", "", "log level for the server (env: "+EnvLogLevel+")")
}

// FromFlagSet builds a Config from the flag set and environment variables.
func FromFlagSet(fs *pflag.FlagSet) (Config, error) {
	dataDir := stringValue(fs, "data-dir", EnvDataDir, DefaultDataDir)
	bind := stringValue(fs, "http-bind", EnvBindAddr, DefaultBindAddr)
	tlsBind := stringValue(fs, "https-bind", EnvTLSBind, DefaultTLSBind)
	tlsCert := stringValue(fs, "tls-cert", EnvTLSCert, "")
	tlsKey := stringValue(fs, "tls-key", EnvTLSKey, "")

	levelStr := stringValue(fs, "log-level", EnvLogLevel, DefaultLogLevel.String())
	level, err := logrus.ParseLevel(levelStr)
	if err != nil {
		return Config{}, fmt.Errorf("invalid log level %q: %w", levelStr, err)
	}

	return Config{
		DataDir:  dataDir,
		BindAddr: bind,
		TLSBind:  tlsBind,
		TLSCert:  tlsCert,
		TLSKey:   tlsKey,
		LogLevel: level,
	}, nil
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
