package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

const (
	EnvDatabase          = "DATABASE"
	EnvBindAddr          = "HTTP_BIND"
	EnvTLSBind           = "HTTPS_BIND"
	EnvTLSCert           = "TLS_CERT"
	EnvTLSKey            = "TLS_KEY"
	EnvUnixSocket        = "UNIX_SOCKET"
	EnvUnixSocketMode    = "UNIX_SOCKET_MODE"
	EnvLogLevel          = "LOG_LEVEL"
	EnvRequireSignatures = "REQUIRE_SIGNATURES"

	EnvRaftBind                = "RAFT_BIND"
	EnvRaftAdvertise           = "RAFT_ADVERTISE"
	EnvRaftNodeID              = "RAFT_NODE_ID"
	EnvRaftBootstrapExpect     = "RAFT_BOOTSTRAP_EXPECT"
	EnvRaftPeers               = "RAFT_PEERS"
	EnvRaftCAFile              = "RAFT_CA_FILE"
	EnvRaftCertFile            = "RAFT_CERT_FILE"
	EnvRaftKeyFile             = "RAFT_KEY_FILE"
	EnvRaftSnapshotThreshold   = "RAFT_SNAPSHOT_THRESHOLD"
	EnvRaftTrailingLogs        = "RAFT_TRAILING_LOGS"
	EnvRaftPeerHTTPAddrs       = "RAFT_PEER_HTTP_ADDRS"
	EnvRaftClusterSecret       = "RAFT_CLUSTER_SECRET"
	EnvRaftTLSServerName       = "RAFT_TLS_SERVER_NAME"
	EnvRaftAutoJoin            = "RAFT_AUTO_JOIN"
	EnvRaftLockTimeout         = "RAFT_LOCK_TIMEOUT"
	EnvGrantoryRaftLockTimeout = "GRANTORY_RAFT_LOCK_TIMEOUT"
	EnvGrantoryLockTimeout     = "GRANTORY_LOCK_TIMEOUT"
)

const (
	DefaultDataDir               = "data"
	DefaultBindAddr              = "0.0.0.0:8080"
	DefaultTLSBind               = "0.0.0.0:8443"
	DefaultUnixSocket            = ""
	DefaultUnixSocketMode        = os.FileMode(0o660)
	DefaultRaftSnapshotThreshold = 10000
	DefaultRaftTrailingLogs      = 1000
	DefaultRaftLockTimeout       = 3 * time.Second
)

const DefaultLogLevel = logrus.InfoLevel

// Config holds the runtime configuration for the Grantory server.
type Config struct {
	Database              string
	BindAddr              string
	TLSBind               string
	TLSCert               string
	TLSKey                string
	UnixSocket            string
	UnixSocketMode        os.FileMode
	LogLevel              logrus.Level
	RequireSignatures     bool
	ServerVersion         string
	RaftBind              string
	RaftAdvertise         string
	RaftNodeID            string
	RaftBootstrapExpect   int
	RaftPeers             []string
	RaftCAFile            string
	RaftCertFile          string
	RaftKeyFile           string
	RaftSnapshotThreshold uint64
	RaftTrailingLogs      uint64
	RaftPeerHTTPAddrs     []string
	RaftClusterSecret     string
	RaftTLSServerName     string
	RaftAutoJoin          bool
}

func (c Config) IsRaftEnabled() bool {
	return strings.TrimSpace(c.RaftBind) != ""
}

// IsTLSEnabled returns true if TLS certificates and keys are configured and the HTTPS bind address is not disabled.
func (c Config) IsTLSEnabled() bool {
	trimmedBind := strings.TrimSpace(c.TLSBind)
	return c.TLSCert != "" && c.TLSKey != "" && trimmedBind != "" && !strings.EqualFold(trimmedBind, "off")
}

// Validate checks configuration for validity and incompatibilities.
func (c Config) Validate() error {
	if c.RaftBootstrapExpect < 0 {
		return errors.New("--raft-bootstrap-expect cannot be negative")
	}
	if c.IsRaftEnabled() && storage.IsPostgresDSN(c.Database) {
		return errors.New("raft consensus is not supported with PostgreSQL database backend")
	}
	if c.IsRaftEnabled() && c.RaftBootstrapExpect > 1 && len(c.RaftPeers) == 0 {
		return errors.New("--raft-peers must be specified when --raft-bootstrap-expect > 1")
	}
	if c.IsRaftEnabled() {
		hasExplicitID := false
		hasPlainAddr := false
		seenIDs := make(map[string]struct{})
		for _, peer := range c.RaftPeers {
			if strings.TrimSpace(peer) == "" {
				continue
			}
			if strings.Contains(peer, "=") {
				hasExplicitID = true
				parts := strings.SplitN(peer, "=", 2)
				id := strings.TrimSpace(parts[0])
				if id == "" {
					return fmt.Errorf("invalid peer entry %q: node ID cannot be empty", peer)
				}
				if _, exists := seenIDs[id]; exists {
					return fmt.Errorf("duplicate peer node ID %q in --raft-peers", id)
				}
				seenIDs[id] = struct{}{}
			} else {
				hasPlainAddr = true
			}
		}
		if hasExplicitID && hasPlainAddr {
			return errors.New("mixed peer formats in --raft-peers: if any peer uses 'node_id=address', all peers must use 'node_id=address'")
		}
	}
	if c.IsRaftEnabled() && c.RaftBootstrapExpect > 1 && c.RaftNodeID != "" {
		hasSelf := false
		for _, peer := range c.RaftPeers {
			if strings.TrimSpace(peer) == "" {
				continue
			}
			if !strings.Contains(peer, "=") {
				return errors.New("when --raft-node-id is set for multi-node bootstrap (--raft-bootstrap-expect > 1), all --raft-peers entries must use the 'node_id=address' format")
			}
			id := strings.SplitN(peer, "=", 2)[0]
			if strings.TrimSpace(id) == c.RaftNodeID {
				hasSelf = true
			}
		}
		if !hasSelf {
			return fmt.Errorf("--raft-node-id %q must be included in --raft-peers", c.RaftNodeID)
		}
	}
	effectiveAdv := c.RaftAdvertise
	if effectiveAdv == "" && !strings.HasSuffix(c.RaftBind, ":0") {
		effectiveAdv = c.RaftBind
	}
	if c.IsRaftEnabled() && effectiveAdv != "" {
		host := effectiveAdv
		if h, _, err := net.SplitHostPort(effectiveAdv); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			return fmt.Errorf("--raft-advertise cannot be an unspecified IP address (%s); specify a reachable IP or hostname", effectiveAdv)
		}
	}
	// When bootstrapping a multi-node cluster (RaftBootstrapExpect > 1), an explicit
	// --raft-advertise address is intentionally required rather than falling back to
	// RaftBind. This prevents accidental advertising of local, ephemeral, or unroutable
	// bind interfaces (e.g. 127.0.0.1 or 0.0.0.0) across multi-node topologies, avoiding
	// interface leaks and split-brain scenarios in NAT or containerized environments.
	if c.IsRaftEnabled() && c.RaftBootstrapExpect > 1 {
		if c.RaftAdvertise == "" {
			return errors.New("--raft-advertise must be explicitly specified when --raft-bootstrap-expect > 1")
		}
	}
	hasCA := c.RaftCAFile != ""
	hasCert := c.RaftCertFile != ""
	hasKey := c.RaftKeyFile != ""
	if (hasCA || hasCert || hasKey) && (!hasCA || !hasCert || !hasKey) {
		return errors.New("raft TLS requires all of --raft-ca-file, --raft-cert-file, and --raft-key-file to be set")
	}
	return nil
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

	fs.String("raft-bind", "", "listening address for Raft peer communication (env: "+EnvRaftBind+"); enables Raft when set")
	fs.String("raft-advertise", "", "address to advertise to Raft peers (env: "+EnvRaftAdvertise+"); defaults to raft-bind")
	fs.String("raft-node-id", "", "unique node identifier in the Raft cluster (env: "+EnvRaftNodeID+"); when set with --raft-bootstrap-expect > 1, all --raft-peers must use 'node_id=address' format. For headless DNS discovery, omit this flag to derive consistent IDs from addresses")
	fs.Int("raft-bootstrap-expect", 0, "number of expected nodes for automatic cluster bootstrapping (env: "+EnvRaftBootstrapExpect+")")
	fs.StringSlice("raft-peers", nil, "comma-separated addresses, node_id=address pairs, or DNS name of initial Raft cluster peers (env: "+EnvRaftPeers+"); if --raft-node-id is set with --raft-bootstrap-expect > 1, all entries must use 'node_id=address'; supports optional '@http-address' suffix (e.g. node-1=10.0.0.1:8300@http://10.0.0.1:8080)")
	fs.String("raft-ca-file", "", "CA certificate for Raft mTLS verification (env: "+EnvRaftCAFile+")")
	fs.String("raft-cert-file", "", "TLS certificate for Raft peer communication (env: "+EnvRaftCertFile+")")
	fs.String("raft-key-file", "", "TLS private key for Raft peer communication (env: "+EnvRaftKeyFile+")")
	fs.Uint64("raft-snapshot-threshold", DefaultRaftSnapshotThreshold, "number of log entries between Raft snapshots (env: "+EnvRaftSnapshotThreshold+")")
	fs.Uint64("raft-trailing-logs", DefaultRaftTrailingLogs, "number of logs retained after snapshot (env: "+EnvRaftTrailingLogs+")")
	fs.StringSlice("raft-peer-http-addrs", nil, "comma-separated mappings of raft-address-or-id=http-address (env: "+EnvRaftPeerHTTPAddrs+")")
	fs.String("raft-cluster-secret", "", "shared secret for authenticating cluster join and remove operations (env: "+EnvRaftClusterSecret+")")
	fs.String("raft-tls-server-name", "", "expected TLS server name (DNS SAN) for peer verification (env: "+EnvRaftTLSServerName+"); required when peer certificates use DNS SANs but peers dial via IP addresses")
	fs.Bool("raft-auto-join", true, "automatically join existing cluster if peers are reachable (env: "+EnvRaftAutoJoin+")")
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

	raftBind := stringValue(fs, "raft-bind", EnvRaftBind, "")
	raftAdvertise := stringValue(fs, "raft-advertise", EnvRaftAdvertise, "")
	raftNodeID := stringValue(fs, "raft-node-id", EnvRaftNodeID, "")
	raftBootstrapExpect, err := intValue(fs, "raft-bootstrap-expect", EnvRaftBootstrapExpect, 0)
	if err != nil {
		return Config{}, fmt.Errorf("invalid raft bootstrap expect: %w", err)
	}
	if raftAdvertise == "" && raftBootstrapExpect <= 1 {
		if !strings.HasSuffix(raftBind, ":0") {
			raftAdvertise = raftBind
		}
	}
	raftPeers := stringSliceValue(fs, "raft-peers", EnvRaftPeers)
	raftCAFile := stringValue(fs, "raft-ca-file", EnvRaftCAFile, "")
	raftCertFile := stringValue(fs, "raft-cert-file", EnvRaftCertFile, "")
	raftKeyFile := stringValue(fs, "raft-key-file", EnvRaftKeyFile, "")

	raftSnapshotThreshold, err := uint64Value(fs, "raft-snapshot-threshold", EnvRaftSnapshotThreshold, DefaultRaftSnapshotThreshold)
	if err != nil {
		return Config{}, fmt.Errorf("invalid raft snapshot threshold: %w", err)
	}

	raftTrailingLogs, err := uint64Value(fs, "raft-trailing-logs", EnvRaftTrailingLogs, DefaultRaftTrailingLogs)
	if err != nil {
		return Config{}, fmt.Errorf("invalid raft trailing logs: %w", err)
	}
	raftPeerHTTPAddrs := stringSliceValue(fs, "raft-peer-http-addrs", EnvRaftPeerHTTPAddrs)
	raftClusterSecret := stringValue(fs, "raft-cluster-secret", EnvRaftClusterSecret, "")
	raftTLSServerName := stringValue(fs, "raft-tls-server-name", EnvRaftTLSServerName, "")
	raftAutoJoin := boolValue(fs, "raft-auto-join", EnvRaftAutoJoin, true)

	return Config{
		Database:              database,
		BindAddr:              bind,
		TLSBind:               tlsBind,
		TLSCert:               tlsCert,
		TLSKey:                tlsKey,
		UnixSocket:            unixSocket,
		UnixSocketMode:        unixSocketMode,
		LogLevel:              level,
		RequireSignatures:     requireSignatures,
		RaftBind:              raftBind,
		RaftAdvertise:         raftAdvertise,
		RaftNodeID:            raftNodeID,
		RaftBootstrapExpect:   raftBootstrapExpect,
		RaftPeers:             raftPeers,
		RaftCAFile:            raftCAFile,
		RaftCertFile:          raftCertFile,
		RaftKeyFile:           raftKeyFile,
		RaftSnapshotThreshold: raftSnapshotThreshold,
		RaftTrailingLogs:      raftTrailingLogs,
		RaftPeerHTTPAddrs:     raftPeerHTTPAddrs,
		RaftClusterSecret:     raftClusterSecret,
		RaftTLSServerName:     raftTLSServerName,
		RaftAutoJoin:          raftAutoJoin,
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

func intValue(fs *pflag.FlagSet, name, envKey string, defaultValue int) (int, error) {
	if fs != nil && fs.Changed(name) {
		return fs.GetInt(name)
	}

	if v := os.Getenv(envKey); v != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, fmt.Errorf("invalid %s %q: %w", envKey, v, err)
		}
		return parsed, nil
	}

	return defaultValue, nil
}

func uint64Value(fs *pflag.FlagSet, name, envKey string, defaultValue uint64) (uint64, error) {
	if fs != nil && fs.Changed(name) {
		return fs.GetUint64(name)
	}

	if v := os.Getenv(envKey); v != "" {
		parsed, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid %s %q: %w", envKey, v, err)
		}
		return parsed, nil
	}

	return defaultValue, nil
}

func stringSliceValue(fs *pflag.FlagSet, name, envKey string) []string {
	if fs != nil && fs.Changed(name) {
		val, err := fs.GetStringSlice(name)
		if err == nil {
			return val
		}
	}

	if v := os.Getenv(envKey); v != "" {
		parts := strings.Split(v, ",")
		var list []string
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				list = append(list, trimmed)
			}
		}
		return list
	}

	return nil
}

// ExtractPort returns the port component of an address, or empty string if disabled/unspecified.
func ExtractPort(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" || strings.EqualFold(addr, "off") {
		return ""
	}
	_, port, err := net.SplitHostPort(addr)
	if err == nil && port != "" {
		return port
	}
	if _, err := strconv.Atoi(addr); err == nil {
		return addr
	}
	return ""
}
