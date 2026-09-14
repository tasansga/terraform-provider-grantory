package config

import (
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Equal(t, DefaultUnixSocket, cfg.UnixSocket, "default unix socket")
	assert.Equal(t, DefaultUnixSocketMode, cfg.UnixSocketMode, "default unix socket mode")
	assert.Equal(t, DefaultLogLevel, cfg.LogLevel, "default log level")
	assert.Equal(t, "", cfg.RaftBind, "default raft bind")
	assert.Equal(t, "", cfg.RaftAdvertise, "default raft advertise")
	assert.Equal(t, "", cfg.RaftNodeID, "default raft node id")
	assert.Equal(t, 0, cfg.RaftBootstrapExpect, "default raft bootstrap expect")
	assert.Nil(t, cfg.RaftPeers, "default raft peers")
	assert.Equal(t, "", cfg.RaftCAFile, "default raft ca file")
	assert.Equal(t, "", cfg.RaftCertFile, "default raft cert file")
	assert.Equal(t, "", cfg.RaftKeyFile, "default raft key file")
	assert.Equal(t, uint64(10000), cfg.RaftSnapshotThreshold, "default raft snapshot threshold")
	assert.Equal(t, uint64(1000), cfg.RaftTrailingLogs, "default raft trailing logs")
	assert.Equal(t, "", cfg.RaftClusterSecret, "default raft cluster secret")
	assert.Equal(t, "", cfg.RaftTLSServerName, "default raft tls server name")
	assert.False(t, cfg.IsRaftEnabled(), "default raft enabled")
}

func TestFromFlagSetEnvOverrides(t *testing.T) {
	t.Setenv(EnvDatabase, "postgres://env")
	t.Setenv(EnvBindAddr, "127.0.0.1:9000")
	t.Setenv(EnvTLSBind, "127.0.0.1:9443")
	t.Setenv(EnvTLSCert, "/tmp/cert.pem")
	t.Setenv(EnvTLSKey, "/tmp/key.pem")
	t.Setenv(EnvUnixSocket, "/run/grantory/server.sock")
	t.Setenv(EnvUnixSocketMode, "0666")
	t.Setenv(EnvLogLevel, "debug")
	t.Setenv(EnvRaftBind, "127.0.0.1:8081")
	t.Setenv(EnvRaftAdvertise, "10.0.0.2:8081")
	t.Setenv(EnvRaftNodeID, "node-env")
	t.Setenv(EnvRaftBootstrapExpect, "3")
	t.Setenv(EnvRaftPeers, "10.0.0.1:8081, 10.0.0.2:8081")
	t.Setenv(EnvRaftCAFile, "/tmp/ca.pem")
	t.Setenv(EnvRaftCertFile, "/tmp/cert.pem")
	t.Setenv(EnvRaftKeyFile, "/tmp/key.pem")
	t.Setenv(EnvRaftSnapshotThreshold, "5000")
	t.Setenv(EnvRaftTrailingLogs, "500")
	t.Setenv(EnvRaftClusterSecret, "secret-env-123")
	t.Setenv(EnvRaftTLSServerName, "custom.raft.server")

	fs := newTestFlagSet(t)
	assert.NoError(t, fs.Parse([]string{}), "unable to parse empty args")

	cfg, err := FromFlagSet(fs)
	assert.NoError(t, err, "unexpected error from FromFlagSet")

	assert.Equal(t, "postgres://env", cfg.Database, "database from env")
	assert.Equal(t, "127.0.0.1:9000", cfg.BindAddr, "bind addr from env")
	assert.Equal(t, "127.0.0.1:9443", cfg.TLSBind, "tls bind addr from env")
	assert.Equal(t, "/tmp/cert.pem", cfg.TLSCert, "tls cert from env")
	assert.Equal(t, "/tmp/key.pem", cfg.TLSKey, "tls key from env")
	assert.Equal(t, "/run/grantory/server.sock", cfg.UnixSocket, "unix socket from env")
	assert.Equal(t, os.FileMode(0o666), cfg.UnixSocketMode, "unix socket mode from env")
	assert.Equal(t, logLevelOrDefault("debug"), cfg.LogLevel, "log level from env")
	assert.Equal(t, "127.0.0.1:8081", cfg.RaftBind, "raft bind from env")
	assert.Equal(t, "10.0.0.2:8081", cfg.RaftAdvertise, "raft advertise from env")
	assert.Equal(t, "node-env", cfg.RaftNodeID, "raft node id from env")
	assert.Equal(t, 3, cfg.RaftBootstrapExpect, "raft bootstrap expect from env")
	assert.Equal(t, []string{"10.0.0.1:8081", "10.0.0.2:8081"}, cfg.RaftPeers, "raft peers from env")
	assert.Equal(t, "/tmp/ca.pem", cfg.RaftCAFile, "raft ca file from env")
	assert.Equal(t, "/tmp/cert.pem", cfg.RaftCertFile, "raft cert file from env")
	assert.Equal(t, "/tmp/key.pem", cfg.RaftKeyFile, "raft key file from env")
	assert.Equal(t, uint64(5000), cfg.RaftSnapshotThreshold, "raft snapshot threshold from env")
	assert.Equal(t, uint64(500), cfg.RaftTrailingLogs, "raft trailing logs from env")
	assert.Equal(t, "secret-env-123", cfg.RaftClusterSecret, "raft cluster secret from env")
	assert.Equal(t, "custom.raft.server", cfg.RaftTLSServerName, "raft tls server name from env")
	assert.True(t, cfg.IsRaftEnabled(), "raft enabled from env")
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
		"--unix-socket=/tmp/grantory.sock",
		"--unix-socket-mode=0600",
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
	assert.Equal(t, "/tmp/grantory.sock", cfg.UnixSocket, "unix socket from flag")
	assert.Equal(t, os.FileMode(0o600), cfg.UnixSocketMode, "unix socket mode from flag")
	assert.Equal(t, logLevelOrDefault("warn"), cfg.LogLevel, "log level from flag")
}

func TestFromFlagSetInvalidLogLevel(t *testing.T) {
	fs := newTestFlagSet(t)
	assert.NoError(t, fs.Parse([]string{"--log-level=unknown"}), "unable to parse args")

	_, err := FromFlagSet(fs)
	assert.Error(t, err, "expected an error for invalid log level")
}

func TestFromFlagSetInvalidUnixSocketMode(t *testing.T) {
	fs := newTestFlagSet(t)
	assert.NoError(t, fs.Parse([]string{"--unix-socket-mode=nope"}), "unable to parse args")

	_, err := FromFlagSet(fs)
	assert.Error(t, err, "expected error for invalid unix socket mode")
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

func TestRaftConfigFromFlagSet(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterFlags(fs)

	args := []string{
		"--raft-bind=0.0.0.0:8081",
		"--raft-advertise=10.0.0.1:8081",
		"--raft-node-id=node-1",
		"--raft-bootstrap-expect=3",
		"--raft-peers=10.0.0.1:8081,10.0.0.2:8081,10.0.0.3:8081",
		"--raft-ca-file=/path/to/ca.pem",
		"--raft-cert-file=/path/to/cert.pem",
		"--raft-key-file=/path/to/key.pem",
		"--raft-cluster-secret=my-cluster-secret",
		"--raft-tls-server-name=raft.node1.cluster",
	}
	require.NoError(t, fs.Parse(args))

	cfg, err := FromFlagSet(fs)
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0:8081", cfg.RaftBind)
	assert.Equal(t, "10.0.0.1:8081", cfg.RaftAdvertise)
	assert.Equal(t, "node-1", cfg.RaftNodeID)
	assert.Equal(t, 3, cfg.RaftBootstrapExpect)
	assert.Equal(t, []string{"10.0.0.1:8081", "10.0.0.2:8081", "10.0.0.3:8081"}, cfg.RaftPeers)
	assert.Equal(t, "/path/to/ca.pem", cfg.RaftCAFile)
	assert.Equal(t, "/path/to/cert.pem", cfg.RaftCertFile)
	assert.Equal(t, "/path/to/key.pem", cfg.RaftKeyFile)
	assert.Equal(t, "my-cluster-secret", cfg.RaftClusterSecret)
	assert.Equal(t, "raft.node1.cluster", cfg.RaftTLSServerName)
	assert.True(t, cfg.IsRaftEnabled())
}

func TestRaftAdvertiseDefaultsToBind(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterFlags(fs)

	args := []string{
		"--raft-bind=0.0.0.0:8081",
	}
	require.NoError(t, fs.Parse(args))

	cfg, err := FromFlagSet(fs)
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0:8081", cfg.RaftBind)
	assert.Equal(t, "0.0.0.0:8081", cfg.RaftAdvertise)
	assert.True(t, cfg.IsRaftEnabled())
}

func TestRaftAdvertiseDynamicPortDiscovery(t *testing.T) {
	t.Run("port 0 leaves RaftAdvertise empty", func(t *testing.T) {
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		RegisterFlags(fs)

		args := []string{
			"--raft-bind=127.0.0.1:0",
		}
		require.NoError(t, fs.Parse(args))

		cfg, err := FromFlagSet(fs)
		require.NoError(t, err)

		assert.Equal(t, "127.0.0.1:0", cfg.RaftBind)
		assert.Equal(t, "", cfg.RaftAdvertise)
		assert.True(t, cfg.IsRaftEnabled())
	})

	t.Run("static port defaults RaftAdvertise to RaftBind", func(t *testing.T) {
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		RegisterFlags(fs)

		args := []string{
			"--raft-bind=127.0.0.1:8081",
		}
		require.NoError(t, fs.Parse(args))

		cfg, err := FromFlagSet(fs)
		require.NoError(t, err)

		assert.Equal(t, "127.0.0.1:8081", cfg.RaftBind)
		assert.Equal(t, "127.0.0.1:8081", cfg.RaftAdvertise)
		assert.True(t, cfg.IsRaftEnabled())
	})
}

func TestRaftInvalidBootstrapExpect(t *testing.T) {
	t.Setenv(EnvRaftBootstrapExpect, "not-a-number")
	fs := newTestFlagSet(t)
	require.NoError(t, fs.Parse([]string{}))

	_, err := FromFlagSet(fs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid RAFT_BOOTSTRAP_EXPECT")
}

func TestRaftInvalidSnapshotThreshold(t *testing.T) {
	t.Setenv(EnvRaftSnapshotThreshold, "bad-threshold")
	fs := newTestFlagSet(t)
	require.NoError(t, fs.Parse([]string{}))

	_, err := FromFlagSet(fs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), EnvRaftSnapshotThreshold)
}

func TestRaftInvalidTrailingLogs(t *testing.T) {
	t.Setenv(EnvRaftTrailingLogs, "bad-trailing")
	fs := newTestFlagSet(t)
	require.NoError(t, fs.Parse([]string{}))

	_, err := FromFlagSet(fs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid RAFT_TRAILING_LOGS")
}

func TestValidateRaftWithPostgresRejected(t *testing.T) {
	// Raft enabled with Postgres database DSN must be rejected
	cfg := Config{
		Database: "postgres://user:pass@localhost:5432/grantory?sslmode=disable",
		RaftBind: "127.0.0.1:8081",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "raft")
	assert.Contains(t, strings.ToLower(err.Error()), "postgres")

	// Raft enabled with SQLite database directory must be accepted
	cfgSQLite := Config{
		Database: "/tmp/data",
		RaftBind: "127.0.0.1:8081",
	}
	assert.NoError(t, cfgSQLite.Validate())

	// Postgres without Raft must be accepted
	cfgPostgresNoRaft := Config{
		Database: "postgres://user:pass@localhost:5432/grantory?sslmode=disable",
		RaftBind: "",
	}
	assert.NoError(t, cfgPostgresNoRaft.Validate())
}

func TestValidateRaftBootstrapExpect(t *testing.T) {
	// Negative RaftBootstrapExpect must be rejected
	negCfg := Config{
		Database:            "/tmp/data",
		RaftBootstrapExpect: -1,
	}
	err := negCfg.Validate()
	require.Error(t, err)
	assert.Equal(t, "--raft-bootstrap-expect cannot be negative", err.Error())

	// Multi-node bootstrap with Raft enabled and empty RaftPeers must be rejected
	noPeersCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftBootstrapExpect: 3,
		RaftPeers:           nil,
	}
	err = noPeersCfg.Validate()
	require.Error(t, err)
	assert.Equal(t, "--raft-peers must be specified when --raft-bootstrap-expect > 1", err.Error())

	// Multi-node bootstrap with Raft enabled and empty slice RaftPeers must be rejected
	emptyPeersCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{},
	}
	err = emptyPeersCfg.Validate()
	require.Error(t, err)
	assert.Equal(t, "--raft-peers must be specified when --raft-bootstrap-expect > 1", err.Error())

	// Multi-node bootstrap with empty RaftAdvertise must be rejected
	emptyAdvCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftAdvertise:       "",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"10.0.0.1:8081", "10.0.0.2:8081"},
	}
	err = emptyAdvCfg.Validate()
	require.Error(t, err)
	assert.Equal(t, "--raft-advertise must be explicitly specified when --raft-bootstrap-expect > 1", err.Error())

	// Valid multi-node bootstrap with peers succeeds
	validMultiCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftAdvertise:       "127.0.0.1:8081",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"10.0.0.1:8081", "10.0.0.2:8081"},
	}
	assert.NoError(t, validMultiCfg.Validate())

	// Single-node bootstrap without peers succeeds
	singleNodeCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftBootstrapExpect: 1,
	}
	assert.NoError(t, singleNodeCfg.Validate())

	// Zero bootstrap expect without peers succeeds
	zeroExpectCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftBootstrapExpect: 0,
	}
	assert.NoError(t, zeroExpectCfg.Validate())

	// Raft disabled with RaftBootstrapExpect > 1 does not require peers
	raftDisabledCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "",
		RaftBootstrapExpect: 3,
	}
	assert.NoError(t, raftDisabledCfg.Validate())
}

func TestValidateRaftBootstrapPeerNodeIDMapping(t *testing.T) {
	// RaftBootstrapExpect > 1 with RaftNodeID set requires all RaftPeers to use node_id=address format
	invalidCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftAdvertise:       "127.0.0.1:8081",
		RaftBootstrapExpect: 3,
		RaftNodeID:          "node-1",
		RaftPeers:           []string{"10.0.0.1:8081", "10.0.0.2:8081"},
	}
	err := invalidCfg.Validate()
	require.Error(t, err)
	assert.Equal(t, "when --raft-node-id is set for multi-node bootstrap (--raft-bootstrap-expect > 1), all --raft-peers entries must use the 'node_id=address' format", err.Error())

	// When peers contain node_id=address format including self, validation succeeds
	validCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftAdvertise:       "127.0.0.1:8081",
		RaftBootstrapExpect: 3,
		RaftNodeID:          "node-1",
		RaftPeers:           []string{"node-1=10.0.0.1:8081", "node-2=10.0.0.2:8081"},
	}
	assert.NoError(t, validCfg.Validate())

	// When RaftNodeID is omitted from RaftPeers for multi-node bootstrap, validation fails
	missingSelfCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftAdvertise:       "127.0.0.1:8081",
		RaftBootstrapExpect: 3,
		RaftNodeID:          "node-1",
		RaftPeers:           []string{"node-2=10.0.0.2:8081", "node-3=10.0.0.3:8081"},
	}
	err = missingSelfCfg.Validate()
	require.Error(t, err)
	assert.Equal(t, `--raft-node-id "node-1" must be included in --raft-peers`, err.Error())

	// Whitespace around node_id in peer mapping is trimmed during self check
	spacedSelfCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftAdvertise:       "127.0.0.1:8081",
		RaftBootstrapExpect: 3,
		RaftNodeID:          "node-1",
		RaftPeers:           []string{" node-1 = 10.0.0.1:8081", "node-2=10.0.0.2:8081"},
	}
	assert.NoError(t, spacedSelfCfg.Validate())

	// Duplicate peer node IDs in --raft-peers fail validation
	dupPeerCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftAdvertise:       "127.0.0.1:8081",
		RaftBootstrapExpect: 3,
		RaftNodeID:          "node-1",
		RaftPeers:           []string{"node-1=10.0.0.1:8081", "node-2=10.0.0.2:8081", "node-1=10.0.0.3:8081"},
	}
	err = dupPeerCfg.Validate()
	require.Error(t, err)
	assert.Equal(t, `duplicate peer node ID "node-1" in --raft-peers`, err.Error())

	// Whitespace around duplicate peer node ID is trimmed
	dupPeerTrimmedCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftAdvertise:       "127.0.0.1:8081",
		RaftBootstrapExpect: 3,
		RaftNodeID:          "node-1",
		RaftPeers:           []string{"node-1=10.0.0.1:8081", "node-2=10.0.0.2:8081", " node-2 =10.0.0.3:8081"},
	}
	err = dupPeerTrimmedCfg.Validate()
	require.Error(t, err)
	assert.Equal(t, `duplicate peer node ID "node-2" in --raft-peers`, err.Error())

	// RaftBootstrapExpect == 1 does not require node_id=address format
	singleNodeCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftBootstrapExpect: 1,
		RaftNodeID:          "node-1",
		RaftPeers:           []string{"10.0.0.1:8081"},
	}
	assert.NoError(t, singleNodeCfg.Validate())

	// Empty RaftNodeID does not enforce node_id=address format
	noNodeIDCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftAdvertise:       "127.0.0.1:8081",
		RaftBootstrapExpect: 3,
		RaftNodeID:          "",
		RaftPeers:           []string{"10.0.0.1:8081", "10.0.0.2:8081"},
	}
	assert.NoError(t, noNodeIDCfg.Validate())

	// Standalone mode (RaftBind == "") with RaftBootstrapExpect > 1, RaftNodeID set,
	// and unformatted RaftPeers must pass Validate() since Raft is disabled.
	standaloneCfg := Config{
		Database:            "/tmp/data",
		RaftBind:            "",
		RaftBootstrapExpect: 3,
		RaftNodeID:          "node-1",
		RaftPeers:           []string{"10.0.0.1:8081", "10.0.0.2:8081"},
	}
	assert.NoError(t, standaloneCfg.Validate())
}

func TestValidate_RaftPeersMixedFormat(t *testing.T) {
	// Mixed formats in --raft-peers are rejected
	mixedCfg := Config{
		Database:      "/tmp/data",
		RaftBind:      "127.0.0.1:8081",
		RaftAdvertise: "127.0.0.1:8081",
		RaftPeers:     []string{"node-1=10.0.0.1:8081", "10.0.0.2:8081"},
	}
	err := mixedCfg.Validate()
	require.Error(t, err)
	assert.Equal(t, "mixed peer formats in --raft-peers: if any peer uses 'node_id=address', all peers must use 'node_id=address'", err.Error())

	// Another order of mixed formats
	mixedCfg2 := Config{
		Database:      "/tmp/data",
		RaftBind:      "127.0.0.1:8081",
		RaftAdvertise: "127.0.0.1:8081",
		RaftPeers:     []string{"10.0.0.1:8081", "node-2=10.0.0.2:8081"},
	}
	err = mixedCfg2.Validate()
	require.Error(t, err)
	assert.Equal(t, "mixed peer formats in --raft-peers: if any peer uses 'node_id=address', all peers must use 'node_id=address'", err.Error())

	// Empty node ID in node_id=address entry is rejected
	emptyIDCfg := Config{
		Database:      "/tmp/data",
		RaftBind:      "127.0.0.1:8081",
		RaftAdvertise: "127.0.0.1:8081",
		RaftPeers:     []string{"=127.0.0.1:8081"},
	}
	err = emptyIDCfg.Validate()
	require.Error(t, err)
	assert.Equal(t, `invalid peer entry "=127.0.0.1:8081": node ID cannot be empty`, err.Error())

	// Whitespace-only node ID is rejected
	whitespaceIDCfg := Config{
		Database:      "/tmp/data",
		RaftBind:      "127.0.0.1:8081",
		RaftAdvertise: "127.0.0.1:8081",
		RaftPeers:     []string{"  =127.0.0.1:8081"},
	}
	err = whitespaceIDCfg.Validate()
	require.Error(t, err)
	assert.Equal(t, `invalid peer entry "  =127.0.0.1:8081": node ID cannot be empty`, err.Error())

	// All plain addresses pass mixed-format check
	allPlainCfg := Config{
		Database:      "/tmp/data",
		RaftBind:      "127.0.0.1:8081",
		RaftAdvertise: "127.0.0.1:8081",
		RaftPeers:     []string{"10.0.0.1:8081", "10.0.0.2:8081"},
	}
	assert.NoError(t, allPlainCfg.Validate())

	// All explicit node_id=address pass mixed-format check
	allExplicitCfg := Config{
		Database:      "/tmp/data",
		RaftBind:      "127.0.0.1:8081",
		RaftAdvertise: "127.0.0.1:8081",
		RaftPeers:     []string{"node-1=10.0.0.1:8081", "node-2=10.0.0.2:8081"},
	}
	assert.NoError(t, allExplicitCfg.Validate())
}

func TestValidate_RaftPeersTrailingComma(t *testing.T) {
	fs := newTestFlagSet(t)
	err := fs.Parse([]string{
		"--raft-bind", "127.0.0.1:8081",
		"--raft-advertise", "127.0.0.1:8081",
		"--raft-node-id", "node-1",
		"--raft-bootstrap-expect", "2",
		"--raft-peers", "node-1=127.0.0.1:8081,node-2=127.0.0.2:8081,",
	})
	require.NoError(t, err)

	cfg, err := FromFlagSet(fs)
	require.NoError(t, err)
	assert.NoError(t, cfg.Validate(), "--raft-peers with trailing commas must parse and validate cleanly")

	// Also test direct Config struct with trailing empty and whitespace entries
	cfgDirect := Config{
		Database:            "/tmp/data",
		RaftBind:            "127.0.0.1:8081",
		RaftAdvertise:       "127.0.0.1:8081",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 2,
		RaftPeers:           []string{"node-1=127.0.0.1:8081", "node-2=127.0.0.2:8081", "", "   "},
	}
	assert.NoError(t, cfgDirect.Validate(), "direct Config with trailing empty/whitespace peers must validate cleanly")
}

func TestValidateRaftMTLSTriad(t *testing.T) {
	// Complete triad succeeds
	completeCfg := Config{
		Database:     "/tmp/data",
		RaftCAFile:   "/path/to/ca.pem",
		RaftCertFile: "/path/to/cert.pem",
		RaftKeyFile:  "/path/to/key.pem",
	}
	assert.NoError(t, completeCfg.Validate())

	// Empty triad succeeds
	emptyCfg := Config{
		Database: "/tmp/data",
	}
	assert.NoError(t, emptyCfg.Validate())

	// Partial configurations must fail
	cases := []struct {
		name string
		cfg  Config
	}{
		{
			name: "CA only",
			cfg: Config{
				Database:   "/tmp/data",
				RaftCAFile: "/path/to/ca.pem",
			},
		},
		{
			name: "Cert only",
			cfg: Config{
				Database:     "/tmp/data",
				RaftCertFile: "/path/to/cert.pem",
			},
		},
		{
			name: "Key only",
			cfg: Config{
				Database:    "/tmp/data",
				RaftKeyFile: "/path/to/key.pem",
			},
		},
		{
			name: "CA and Cert without Key",
			cfg: Config{
				Database:     "/tmp/data",
				RaftCAFile:   "/path/to/ca.pem",
				RaftCertFile: "/path/to/cert.pem",
			},
		},
		{
			name: "Cert and Key without CA",
			cfg: Config{
				Database:     "/tmp/data",
				RaftCertFile: "/path/to/cert.pem",
				RaftKeyFile:  "/path/to/key.pem",
			},
		},
		{
			name: "CA and Key without Cert",
			cfg: Config{
				Database:    "/tmp/data",
				RaftCAFile:  "/path/to/ca.pem",
				RaftKeyFile: "/path/to/key.pem",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			require.Error(t, err)
			assert.Equal(t, "raft TLS requires all of --raft-ca-file, --raft-cert-file, and --raft-key-file to be set", err.Error())
		})
	}
}

func TestExtractPort(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty string", input: "", expected: ""},
		{name: "whitespace only", input: "   ", expected: ""},
		{name: "disabled off lowercase", input: "off", expected: ""},
		{name: "disabled off uppercase", input: "OFF", expected: ""},
		{name: "disabled off mixed case with whitespace", input: "  Off  ", expected: ""},
		{name: "host and port standard", input: "127.0.0.1:8080", expected: "8080"},
		{name: "zero host and port", input: "0.0.0.0:8443", expected: "8443"},
		{name: "hostname and port", input: "localhost:9090", expected: "9090"},
		{name: "ipv6 host and port", input: "[::1]:8080", expected: "8080"},
		{name: "bare port string", input: "8080", expected: "8080"},
		{name: "bare port with whitespace", input: "  9000  ", expected: "9000"},
		{name: "colon port", input: ":8080", expected: "8080"},
		{name: "invalid non-numeric bare string", input: "invalid", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ExtractPort(tt.input))
		})
	}
}

func TestValidateRaftAdvertiseUnspecifiedIP(t *testing.T) {
	unspecifiedAddrs := []string{
		"0.0.0.0:8081",
		"[::]:8081",
		"0.0.0.0",
		"::",
		"[::]",
	}

	for _, addr := range unspecifiedAddrs {
		t.Run("rejects_multi_node_"+addr, func(t *testing.T) {
			cfg := Config{
				Database:            "/tmp/data",
				RaftBind:            "0.0.0.0:8081",
				RaftAdvertise:       addr,
				RaftBootstrapExpect: 3,
				RaftPeers:           []string{"10.0.0.1:8081", "10.0.0.2:8081"},
			}
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--raft-advertise cannot be an unspecified IP address")
			assert.Contains(t, err.Error(), addr)
			assert.Contains(t, err.Error(), "; specify a reachable IP or hostname")
		})
	}

	validAddrs := []string{
		"10.0.0.1:8081",
		"127.0.0.1:8081",
		"[::1]:8081",
		"[2001:db8::1]:8081",
		"node1.cluster.local:8081",
	}

	for _, addr := range validAddrs {
		t.Run("accepts_routable_"+addr, func(t *testing.T) {
			cfg := Config{
				Database:            "/tmp/data",
				RaftBind:            "0.0.0.0:8081",
				RaftAdvertise:       addr,
				RaftBootstrapExpect: 3,
				RaftPeers:           []string{"10.0.0.1:8081", "10.0.0.2:8081"},
			}
			assert.NoError(t, cfg.Validate())
		})
	}

	t.Run("single_node_rejects_unspecified_advertise", func(t *testing.T) {
		cfg := Config{
			Database:            "/tmp/data",
			RaftBind:            "127.0.0.1:7000",
			RaftAdvertise:       "0.0.0.0:7000",
			RaftBootstrapExpect: 1,
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--raft-advertise cannot be an unspecified IP address")
	})

	t.Run("raft_disabled_permits_unspecified_advertise", func(t *testing.T) {
		cfg := Config{
			Database:            "/tmp/data",
			RaftBind:            "",
			RaftAdvertise:       "0.0.0.0:8081",
			RaftBootstrapExpect: 3,
		}
		assert.NoError(t, cfg.Validate())
	})
}

func TestValidateRaftAdvertise_ImplicitUnspecifiedRaftBind(t *testing.T) {
	// RaftBind with unspecified IP address and empty RaftAdvertise fails Validate()
	cfgUnspecified := Config{
		Database: "/tmp/data",
		RaftBind: "0.0.0.0:8081",
	}
	err := cfgUnspecified.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--raft-advertise cannot be an unspecified IP address (0.0.0.0:8081); specify a reachable IP or hostname")

	// RaftBind with IPv6 unspecified address and empty RaftAdvertise also fails
	cfgIPv6Unspecified := Config{
		Database: "/tmp/data",
		RaftBind: "[::]:8081",
	}
	err = cfgIPv6Unspecified.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--raft-advertise cannot be an unspecified IP address ([::]:8081); specify a reachable IP or hostname")

	// RaftBind with loopback/reachable IP and empty RaftAdvertise succeeds
	cfgValid := Config{
		Database: "/tmp/data",
		RaftBind: "127.0.0.1:8081",
	}
	assert.NoError(t, cfgValid.Validate())

	// Dynamic port (:0) on unspecified bind does not fail validation because advertise is left empty for runtime discovery
	cfgDynamic := Config{
		Database: "/tmp/data",
		RaftBind: "0.0.0.0:0",
	}
	assert.NoError(t, cfgDynamic.Validate())
}

func TestValidateRaftAdvertiseRequired(t *testing.T) {
	t.Run("multi_node_requires_raft_advertise", func(t *testing.T) {
		cfg := Config{
			Database:            "/tmp/data",
			RaftBind:            "127.0.0.1:8081",
			RaftAdvertise:       "",
			RaftBootstrapExpect: 3,
			RaftPeers:           []string{"10.0.0.1:8081", "10.0.0.2:8081"},
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Equal(t, "--raft-advertise must be explicitly specified when --raft-bootstrap-expect > 1", err.Error())
	})

	t.Run("multi_node_passes_with_valid_reachable_advertise", func(t *testing.T) {
		cfg := Config{
			Database:            "/tmp/data",
			RaftBind:            "0.0.0.0:8081",
			RaftAdvertise:       "10.0.0.1:8081",
			RaftBootstrapExpect: 3,
			RaftPeers:           []string{"10.0.0.1:8081", "10.0.0.2:8081"},
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("single_node_permits_empty_advertise", func(t *testing.T) {
		cfg := Config{
			Database:            "/tmp/data",
			RaftBind:            "127.0.0.1:8081",
			RaftAdvertise:       "",
			RaftBootstrapExpect: 1,
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("raft_disabled_permits_empty_advertise", func(t *testing.T) {
		cfg := Config{
			Database:            "/tmp/data",
			RaftBind:            "",
			RaftAdvertise:       "",
			RaftBootstrapExpect: 3,
		}
		assert.NoError(t, cfg.Validate())
	})
}

func TestRegisterFlags_MultiNodeBootstrapUsageDocs(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterFlags(fs)

	nodeIDFlag := fs.Lookup("raft-node-id")
	require.NotNil(t, nodeIDFlag)
	assert.Contains(t, nodeIDFlag.Usage, "when set with --raft-bootstrap-expect > 1, all --raft-peers must use 'node_id=address' format")
	assert.Contains(t, nodeIDFlag.Usage, "For headless DNS discovery, omit this flag to derive consistent IDs from addresses")

	peersFlag := fs.Lookup("raft-peers")
	require.NotNil(t, peersFlag)
	assert.Contains(t, peersFlag.Usage, "node_id=address pairs")
	assert.Contains(t, peersFlag.Usage, "if --raft-node-id is set with --raft-bootstrap-expect > 1, all entries must use 'node_id=address'")
	assert.Contains(t, peersFlag.Usage, "@http-address")
}

func TestRegisterFlags_RaftTLSServerNameUsageDocs(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterFlags(fs)

	flag := fs.Lookup("raft-tls-server-name")
	require.NotNil(t, flag)
	assert.Equal(t, "expected TLS server name (DNS SAN) for peer verification (env: RAFT_TLS_SERVER_NAME); required when peer certificates use DNS SANs but peers dial via IP addresses", flag.Usage)
}

func TestConfig_IsTLSEnabled(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{
			name: "empty cert and key",
			cfg:  Config{TLSBind: DefaultTLSBind},
			want: false,
		},
		{
			name: "cert only",
			cfg: Config{
				TLSCert: "/path/to/cert.pem",
				TLSBind: DefaultTLSBind,
			},
			want: false,
		},
		{
			name: "key only",
			cfg: Config{
				TLSKey:  "/path/to/key.pem",
				TLSBind: DefaultTLSBind,
			},
			want: false,
		},
		{
			name: "cert and key with default bind",
			cfg: Config{
				TLSCert: "/path/to/cert.pem",
				TLSKey:  "/path/to/key.pem",
				TLSBind: DefaultTLSBind,
			},
			want: true,
		},
		{
			name: "cert and key with TLSBind off",
			cfg: Config{
				TLSCert: "/path/to/cert.pem",
				TLSKey:  "/path/to/key.pem",
				TLSBind: "off",
			},
			want: false,
		},
		{
			name: "cert and key with TLSBind OFF case-insensitive",
			cfg: Config{
				TLSCert: "/path/to/cert.pem",
				TLSKey:  "/path/to/key.pem",
				TLSBind: "  OFF  ",
			},
			want: false,
		},
		{
			name: "cert and key with empty TLSBind",
			cfg: Config{
				TLSCert: "/path/to/cert.pem",
				TLSKey:  "/path/to/key.pem",
				TLSBind: "",
			},
			want: false,
		},
		{
			name: "cert and key with whitespace-only TLSBind",
			cfg: Config{
				TLSCert: "/path/to/cert.pem",
				TLSKey:  "/path/to/key.pem",
				TLSBind: "   ",
			},
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.cfg.IsTLSEnabled())
		})
	}
}

func TestFromFlagSet_RaftAdvertiseMultiNodeBootstrap(t *testing.T) {
	t.Run("multi-node bootstrap preserves empty RaftAdvertise and fails Validate", func(t *testing.T) {
		fs := newTestFlagSet(t)
		args := []string{
			"--raft-bind=127.0.0.1:8081",
			"--raft-bootstrap-expect=3",
			"--raft-peers=127.0.0.1:8081,10.0.0.2:8081,10.0.0.3:8081",
		}
		require.NoError(t, fs.Parse(args))

		cfg, err := FromFlagSet(fs)
		require.NoError(t, err)

		assert.Equal(t, "", cfg.RaftAdvertise, "RaftAdvertise must not default to RaftBind when RaftBootstrapExpect > 1")
		assert.Equal(t, "127.0.0.1:8081", cfg.RaftBind)
		assert.Equal(t, 3, cfg.RaftBootstrapExpect)

		valErr := cfg.Validate()
		require.Error(t, valErr)
		assert.Contains(t, valErr.Error(), "--raft-advertise must be explicitly specified when --raft-bootstrap-expect > 1")
	})

	t.Run("single-node bootstrap defaults RaftAdvertise to RaftBind and passes Validate", func(t *testing.T) {
		fs := newTestFlagSet(t)
		args := []string{
			"--raft-bind=127.0.0.1:8081",
			"--raft-bootstrap-expect=1",
		}
		require.NoError(t, fs.Parse(args))

		cfg, err := FromFlagSet(fs)
		require.NoError(t, err)

		assert.Equal(t, "127.0.0.1:8081", cfg.RaftAdvertise, "RaftAdvertise should default to RaftBind when RaftBootstrapExpect <= 1")
		assert.NoError(t, cfg.Validate())
	})
}

func TestRaftSnapshotThreshold(t *testing.T) {
	t.Run("default snapshot threshold", func(t *testing.T) {
		fs := newTestFlagSet(t)
		require.NoError(t, fs.Parse([]string{}))

		cfg, err := FromFlagSet(fs)
		require.NoError(t, err)
		assert.Equal(t, uint64(DefaultRaftSnapshotThreshold), cfg.RaftSnapshotThreshold)
	})

	t.Run("canonical flag sets threshold", func(t *testing.T) {
		fs := newTestFlagSet(t)
		require.NoError(t, fs.Parse([]string{"--raft-snapshot-threshold=15000"}))

		cfg, err := FromFlagSet(fs)
		require.NoError(t, err)
		assert.Equal(t, uint64(15000), cfg.RaftSnapshotThreshold)
	})

	t.Run("canonical env var sets threshold", func(t *testing.T) {
		t.Setenv(EnvRaftSnapshotThreshold, "25000")
		fs := newTestFlagSet(t)
		require.NoError(t, fs.Parse([]string{}))

		cfg, err := FromFlagSet(fs)
		require.NoError(t, err)
		assert.Equal(t, uint64(25000), cfg.RaftSnapshotThreshold)
	})

	t.Run("precedence: canonical flag overrides canonical env", func(t *testing.T) {
		t.Setenv(EnvRaftSnapshotThreshold, "99999")
		fs := newTestFlagSet(t)
		require.NoError(t, fs.Parse([]string{"--raft-snapshot-threshold=12345"}))

		cfg, err := FromFlagSet(fs)
		require.NoError(t, err)
		assert.Equal(t, uint64(12345), cfg.RaftSnapshotThreshold)
	})

	t.Run("deprecated flag raft-snapshot-interval does not exist", func(t *testing.T) {
		fs := newTestFlagSet(t)
		fl := fs.Lookup("raft-snapshot-interval")
		assert.Nil(t, fl, "--raft-snapshot-interval should be removed")

		flThreshold := fs.Lookup("raft-snapshot-threshold")
		require.NotNil(t, flThreshold)
		assert.Equal(t, "10000", flThreshold.DefValue)
	})
}
