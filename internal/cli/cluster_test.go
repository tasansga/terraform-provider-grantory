package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	hashiraft "github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	clusterraft "github.com/tasansga/terraform-provider-grantory/internal/cluster/raft"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
)

func TestClusterRecoverCommand(t *testing.T) {
	dir := t.TempDir()
	raftDir := filepath.Join(dir, "raft")
	require.NoError(t, os.MkdirAll(raftDir, 0o755))

	cmd := newClusterRecoverCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--database", dir, "--node-id", "survivor-1", "--bind", "127.0.0.1:8081"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing recovery: no existing Raft state found in database directory")
	assert.NoFileExists(t, filepath.Join(raftDir, "raft.db"))
}

func TestClusterRecoverEmptyDirDoesNotCreateRaftDB(t *testing.T) {
	dir := t.TempDir()

	cmd := newClusterRecoverCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--database", dir, "--node-id", "survivor-1", "--bind", "127.0.0.1:8081"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing recovery: no existing Raft state found in database directory")
	assert.NoFileExists(t, filepath.Join(dir, "raft", "raft.db"))
}

func TestClusterRecoverBoltStoreOpenFailure(t *testing.T) {
	dir := t.TempDir()
	raftDir := filepath.Join(dir, "raft")
	require.NoError(t, os.MkdirAll(raftDir, 0o755))

	// Create a directory where raft.db should be to cause raftboltdb.NewBoltStore to fail
	dbPath := filepath.Join(raftDir, "raft.db")
	require.NoError(t, os.Mkdir(dbPath, 0o755))

	cmd := newClusterRecoverCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--database", dir, "--node-id", "survivor-1", "--bind", "127.0.0.1:8081"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open bolt store")
	assert.Contains(t, err.Error(), "ensure grantory serve is stopped before running cluster recovery")
}

func TestClusterRecoverWithExistingState(t *testing.T) {
	dir := t.TempDir()
	raftDir := filepath.Join(dir, "raft")
	require.NoError(t, os.MkdirAll(raftDir, 0o755))

	// Pre-populate BoltDB with initial term and log entries
	dbPath := filepath.Join(raftDir, "raft.db")
	boltStore, err := raftboltdb.NewBoltStore(dbPath)
	require.NoError(t, err)
	require.NoError(t, boltStore.SetUint64([]byte("CurrentTerm"), 5))

	logEntry := &hashiraft.Log{
		Index: 1,
		Term:  5,
		Type:  hashiraft.LogNoop,
		Data:  []byte("noop"),
	}
	require.NoError(t, boltStore.StoreLog(logEntry))
	require.NoError(t, boltStore.Close())

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"cluster", "recover", "--database", dir, "--node-id", "survivor-1", "--bind", "127.0.0.1:8081"})

	err = root.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Cluster recovered successfully")

	// Verify the snapshot contains the recovered configuration
	snapshotStore, err := hashiraft.NewFileSnapshotStore(filepath.Join(raftDir, "snapshots"), 3, os.Stderr)
	require.NoError(t, err)
	snaps, err := snapshotStore.List()
	require.NoError(t, err)
	require.NotEmpty(t, snaps)

	meta, rc, err := snapshotStore.Open(snaps[0].ID)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	assert.Equal(t, 1, len(meta.Configuration.Servers))
	assert.Equal(t, hashiraft.ServerID("survivor-1"), meta.Configuration.Servers[0].ID)
	assert.Equal(t, hashiraft.ServerAddress("127.0.0.1:8081"), meta.Configuration.Servers[0].Address)
	assert.Equal(t, hashiraft.Voter, meta.Configuration.Servers[0].Suffrage)
}

func TestClusterRecoverCommandMissingFlags(t *testing.T) {
	t.Run("missing node-id", func(t *testing.T) {
		t.Setenv(config.EnvRaftNodeID, "")
		cmd := newClusterRecoverCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"--bind", "127.0.0.1:8081"})

		err := cmd.Execute()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--node-id is required (or set "+config.EnvRaftNodeID+")")
	})

	t.Run("missing bind", func(t *testing.T) {
		t.Setenv(config.EnvRaftBind, "")
		t.Setenv(config.EnvRaftAdvertise, "")
		cmd := newClusterRecoverCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"--node-id", "survivor-1"})

		err := cmd.Execute()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--bind is required (or set "+config.EnvRaftAdvertise+" or "+config.EnvRaftBind+")")
	})

	t.Run("postgres backend rejected", func(t *testing.T) {
		cmd := newClusterRecoverCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"--database", "postgres://user:pass@localhost:5432/grantory", "--node-id", "survivor-1", "--bind", "127.0.0.1:8081"})

		err := cmd.Execute()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "raft cluster recovery is not supported for postgresql backend")
	})

	t.Run("invalid bind address without port", func(t *testing.T) {
		cmd := newClusterRecoverCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"--database", t.TempDir(), "--node-id", "node-1", "--bind", "127.0.0.1"})

		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `invalid --bind address "127.0.0.1": must be in host:port format`)
	})

	t.Run("unspecified ipv4 rejected in --bind", func(t *testing.T) {
		cmd := newClusterRecoverCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"--database", t.TempDir(), "--node-id", "node-1", "--bind", "0.0.0.0:8081"})

		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `cluster recover address "0.0.0.0:8081" cannot have an unspecified IP host (0.0.0.0 or ::); provide a routable address via --bind or `+config.EnvRaftAdvertise)
	})

	t.Run("unspecified ipv6 rejected in --bind", func(t *testing.T) {
		cmd := newClusterRecoverCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"--database", t.TempDir(), "--node-id", "node-1", "--bind", "[::]:8081"})

		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `cluster recover address "[::]:8081" cannot have an unspecified IP host (0.0.0.0 or ::); provide a routable address via --bind or `+config.EnvRaftAdvertise)
	})

	t.Run("unspecified ipv4 rejected in env", func(t *testing.T) {
		t.Setenv(config.EnvRaftNodeID, "node-1")
		t.Setenv(config.EnvRaftAdvertise, "0.0.0.0:8081")
		t.Setenv(config.EnvRaftBind, "")
		cmd := newClusterRecoverCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"--database", t.TempDir()})

		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `cluster recover address "0.0.0.0:8081" cannot have an unspecified IP host (0.0.0.0 or ::); provide a routable address via --bind or `+config.EnvRaftAdvertise)
	})
}

func TestClusterRecoverCommandEnvVarFallbacks(t *testing.T) {
	dir := t.TempDir()
	raftDir := filepath.Join(dir, "raft")
	require.NoError(t, os.MkdirAll(raftDir, 0o755))

	dbPath := filepath.Join(raftDir, "raft.db")
	boltStore, err := raftboltdb.NewBoltStore(dbPath)
	require.NoError(t, err)
	require.NoError(t, boltStore.SetUint64([]byte("CurrentTerm"), 5))
	logEntry := &hashiraft.Log{
		Index: 1,
		Term:  5,
		Type:  hashiraft.LogNoop,
		Data:  []byte("noop"),
	}
	require.NoError(t, boltStore.StoreLog(logEntry))
	require.NoError(t, boltStore.Close())

	t.Setenv(config.EnvRaftNodeID, "env-node-1")
	t.Setenv(config.EnvRaftAdvertise, "")
	t.Setenv(config.EnvRaftBind, "127.0.0.1:8082")

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"cluster", "recover", "--database", dir})

	err = root.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Cluster recovered successfully")

	snapshotStore, err := hashiraft.NewFileSnapshotStore(filepath.Join(raftDir, "snapshots"), 3, os.Stderr)
	require.NoError(t, err)
	snaps, err := snapshotStore.List()
	require.NoError(t, err)
	require.NotEmpty(t, snaps)

	meta, rc, err := snapshotStore.Open(snaps[0].ID)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	assert.Equal(t, 1, len(meta.Configuration.Servers))
	assert.Equal(t, hashiraft.ServerID("env-node-1"), meta.Configuration.Servers[0].ID)
	assert.Equal(t, hashiraft.ServerAddress("127.0.0.1:8082"), meta.Configuration.Servers[0].Address)
	assert.Equal(t, hashiraft.Voter, meta.Configuration.Servers[0].Suffrage)

	t.Run("fallback to RAFT_ADVERTISE when RAFT_BIND is empty", func(t *testing.T) {
		dir2 := t.TempDir()
		raftDir2 := filepath.Join(dir2, "raft")
		require.NoError(t, os.MkdirAll(raftDir2, 0o755))

		dbPath2 := filepath.Join(raftDir2, "raft.db")
		boltStore2, err := raftboltdb.NewBoltStore(dbPath2)
		require.NoError(t, err)
		require.NoError(t, boltStore2.SetUint64([]byte("CurrentTerm"), 6))
		require.NoError(t, boltStore2.StoreLog(&hashiraft.Log{
			Index: 1,
			Term:  6,
			Type:  hashiraft.LogNoop,
			Data:  []byte("noop"),
		}))
		require.NoError(t, boltStore2.Close())

		t.Setenv(config.EnvRaftNodeID, "env-node-adv")
		t.Setenv(config.EnvRaftBind, "")
		t.Setenv(config.EnvRaftAdvertise, "127.0.0.1:8083")

		root2 := NewRootCommand()
		var out2 bytes.Buffer
		root2.SetOut(&out2)
		root2.SetArgs([]string{"cluster", "recover", "--database", dir2})

		err = root2.Execute()
		require.NoError(t, err)
		assert.Contains(t, out2.String(), "Cluster recovered successfully")

		snapshotStore2, err := hashiraft.NewFileSnapshotStore(filepath.Join(raftDir2, "snapshots"), 3, os.Stderr)
		require.NoError(t, err)
		snaps2, err := snapshotStore2.List()
		require.NoError(t, err)
		require.NotEmpty(t, snaps2)

		meta2, rc2, err := snapshotStore2.Open(snaps2[0].ID)
		require.NoError(t, err)
		require.NoError(t, rc2.Close())

		assert.Equal(t, 1, len(meta2.Configuration.Servers))
		assert.Equal(t, hashiraft.ServerID("env-node-adv"), meta2.Configuration.Servers[0].ID)
		assert.Equal(t, hashiraft.ServerAddress("127.0.0.1:8083"), meta2.Configuration.Servers[0].Address)
	})

	t.Run("precedence: RAFT_ADVERTISE takes precedence over RAFT_BIND", func(t *testing.T) {
		dir3 := t.TempDir()
		raftDir3 := filepath.Join(dir3, "raft")
		require.NoError(t, os.MkdirAll(raftDir3, 0o755))

		dbPath3 := filepath.Join(raftDir3, "raft.db")
		boltStore3, err := raftboltdb.NewBoltStore(dbPath3)
		require.NoError(t, err)
		require.NoError(t, boltStore3.SetUint64([]byte("CurrentTerm"), 7))
		require.NoError(t, boltStore3.StoreLog(&hashiraft.Log{
			Index: 1,
			Term:  7,
			Type:  hashiraft.LogNoop,
			Data:  []byte("noop"),
		}))
		require.NoError(t, boltStore3.Close())

		t.Setenv(config.EnvRaftNodeID, "env-node-prec")
		t.Setenv(config.EnvRaftBind, "127.0.0.1:8082")
		t.Setenv(config.EnvRaftAdvertise, "127.0.0.1:8084")

		root3 := NewRootCommand()
		var out3 bytes.Buffer
		root3.SetOut(&out3)
		root3.SetArgs([]string{"cluster", "recover", "--database", dir3})

		err = root3.Execute()
		require.NoError(t, err)
		assert.Contains(t, out3.String(), "Cluster recovered successfully")

		snapshotStore3, err := hashiraft.NewFileSnapshotStore(filepath.Join(raftDir3, "snapshots"), 3, os.Stderr)
		require.NoError(t, err)
		snaps3, err := snapshotStore3.List()
		require.NoError(t, err)
		require.NotEmpty(t, snaps3)

		meta3, rc3, err := snapshotStore3.Open(snaps3[0].ID)
		require.NoError(t, err)
		require.NoError(t, rc3.Close())

		assert.Equal(t, 1, len(meta3.Configuration.Servers))
		assert.Equal(t, hashiraft.ServerID("env-node-prec"), meta3.Configuration.Servers[0].ID)
		assert.Equal(t, hashiraft.ServerAddress("127.0.0.1:8084"), meta3.Configuration.Servers[0].Address)
	})
}

func TestClusterParentCommandHelp(t *testing.T) {
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"cluster"})

	err := root.Execute()
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "Commands for managing Grantory cluster operations")
	assert.Contains(t, out.String(), "recover")
	assert.Contains(t, out.String(), "status")
	assert.Contains(t, out.String(), "remove")
	assert.Contains(t, out.String(), "step-down")
}

func TestClusterRecoverCleansUpOrphanedStagingDirs(t *testing.T) {
	dir := t.TempDir()
	raftDir := filepath.Join(dir, "raft")
	require.NoError(t, os.MkdirAll(raftDir, 0o755))

	// Pre-populate BoltDB with initial term and log entries
	dbPath := filepath.Join(raftDir, "raft.db")
	boltStore, err := raftboltdb.NewBoltStore(dbPath)
	require.NoError(t, err)
	require.NoError(t, boltStore.SetUint64([]byte("CurrentTerm"), 3))
	require.NoError(t, boltStore.StoreLog(&hashiraft.Log{
		Index: 1,
		Term:  3,
		Type:  hashiraft.LogNoop,
		Data:  []byte("noop"),
	}))
	require.NoError(t, boltStore.Close())

	// Create orphaned staging directories in dataDir and staging dir
	stagingDir := filepath.Join(raftDir, "staging")
	require.NoError(t, os.MkdirAll(stagingDir, 0o755))

	orphanedDataStage := filepath.Join(dir, "snap-stage-11111")
	orphanedDataRestore := filepath.Join(dir, "grantory-restore-22222")
	require.NoError(t, os.MkdirAll(orphanedDataStage, 0o755))
	require.NoError(t, os.MkdirAll(orphanedDataRestore, 0o755))

	orphanedRaftStage := filepath.Join(stagingDir, "snap-stage-33333")
	orphanedRaftRestore := filepath.Join(stagingDir, "grantory-restore-44444")
	require.NoError(t, os.MkdirAll(orphanedRaftStage, 0o755))
	require.NoError(t, os.MkdirAll(orphanedRaftRestore, 0o755))

	// Also create normal files/dirs that must not be cleaned up
	preservedDir := filepath.Join(dir, "keep-me")
	preservedFile := filepath.Join(dir, "normal.txt")
	require.NoError(t, os.MkdirAll(preservedDir, 0o755))
	require.NoError(t, os.WriteFile(preservedFile, []byte("ok"), 0o644))

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"cluster", "recover", "--database", dir, "--node-id", "survivor-cleanup", "--bind", "127.0.0.1:8081"})

	err = root.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Cluster recovered successfully")

	// Verify orphaned directories were cleaned up
	_, err = os.Stat(orphanedDataStage)
	assert.True(t, os.IsNotExist(err), "snap-stage in dataDir should be removed")
	_, err = os.Stat(orphanedDataRestore)
	assert.True(t, os.IsNotExist(err), "grantory-restore in dataDir should be removed")
	_, err = os.Stat(orphanedRaftStage)
	assert.True(t, os.IsNotExist(err), "snap-stage in staging dir should be removed")
	_, err = os.Stat(orphanedRaftRestore)
	assert.True(t, os.IsNotExist(err), "grantory-restore in staging dir should be removed")

	// Verify normal files/dirs were preserved
	_, err = os.Stat(preservedDir)
	assert.NoError(t, err, "non-staging dir must be preserved")
	_, err = os.Stat(preservedFile)
	assert.NoError(t, err, "normal file must be preserved")
}

func TestClusterStepDownCommand(t *testing.T) {
	t.Run("missing server-url flag and env returns error", func(t *testing.T) {
		t.Setenv(EnvServerURL, "")
		t.Setenv(EnvGrantoryControllerServerURL, "")
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"cluster", "step-down"})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--server-url is required")
	})

	t.Run("successful step-down with explicit flags", func(t *testing.T) {
		var receivedHeader string
		var receivedAuthHeader string
		var receivedMethod string
		var receivedPath string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedPath = r.URL.Path
			receivedHeader = r.Header.Get("X-Grantory-Cluster-Secret")
			receivedAuthHeader = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","message":"leadership transfer initiated"}`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{
			"cluster", "step-down",
			"--server-url", server.URL,
			"--cluster-secret", "super-secret",
		})

		err := root.Execute()
		require.NoError(t, err)
		assert.Equal(t, http.MethodPost, receivedMethod)
		assert.Equal(t, "/api/v1/cluster/step-down", receivedPath)
		assert.Empty(t, receivedHeader)
		assert.Equal(t, "Bearer super-secret", receivedAuthHeader)
		assert.Contains(t, out.String(), "leadership transfer initiated")
		assert.Contains(t, out.String(), `"status":"ok"`)
	})

	t.Run("successful step-down with environment variables", func(t *testing.T) {
		var receivedHeader string
		var receivedAuthHeader string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeader = r.Header.Get("X-Grantory-Cluster-Secret")
			receivedAuthHeader = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","message":"leadership transfer initiated"}`))
		}))
		defer server.Close()

		t.Setenv(EnvServerURL, server.URL)
		t.Setenv(config.EnvRaftClusterSecret, "env-cluster-secret")

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"cluster", "step-down"})

		err := root.Execute()
		require.NoError(t, err)
		assert.Empty(t, receivedHeader)
		assert.Equal(t, "Bearer env-cluster-secret", receivedAuthHeader)
		assert.Contains(t, out.String(), "leadership transfer initiated")
	})

	t.Run("server returns 503 error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`node is not cluster leader`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "step-down",
			"--server-url", server.URL,
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 503")
		assert.Contains(t, err.Error(), "node is not cluster leader")
	})

	t.Run("server returns 401 unauthorized", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`unauthorized cluster management request`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "step-down",
			"--server-url", server.URL,
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 401")
		assert.Contains(t, err.Error(), "unauthorized cluster management request")
	})
}

func TestClusterStatusCommand(t *testing.T) {
	t.Run("missing server-url flag and env returns error", func(t *testing.T) {
		t.Setenv(EnvServerURL, "")
		t.Setenv("GRANTORY_SERVER_URL", "")
		t.Setenv("SERVER_URL", "")
		t.Setenv(EnvGrantoryControllerServerURL, "")
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"cluster", "status"})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--server-url is required")
	})

	t.Run("successful status with explicit flags", func(t *testing.T) {
		var receivedHeader string
		var receivedAuthHeader string
		var receivedMethod string
		var receivedPath string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedPath = r.URL.Path
			receivedHeader = r.Header.Get("X-Grantory-Cluster-Secret")
			receivedAuthHeader = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","cluster":{"leader_id":"node-1","state":"Leader"}}`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{
			"cluster", "status",
			"--server-url", server.URL,
			"--cluster-secret", "status-secret",
		})

		err := root.Execute()
		require.NoError(t, err)
		assert.Equal(t, http.MethodGet, receivedMethod)
		assert.Equal(t, "/api/v1/cluster/status", receivedPath)
		assert.Empty(t, receivedHeader)
		assert.Equal(t, "Bearer status-secret", receivedAuthHeader)
		assert.Contains(t, out.String(), "leader_id")
		assert.Contains(t, out.String(), "node-1")
	})

	t.Run("successful status with environment variables", func(t *testing.T) {
		var receivedHeader string
		var receivedAuthHeader string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeader = r.Header.Get("X-Grantory-Cluster-Secret")
			receivedAuthHeader = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","cluster":{"leader_id":"node-env"}}`))
		}))
		defer server.Close()

		t.Setenv(EnvServerURL, server.URL)
		t.Setenv(config.EnvRaftClusterSecret, "env-status-secret")

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"cluster", "status"})

		err := root.Execute()
		require.NoError(t, err)
		assert.Empty(t, receivedHeader)
		assert.Equal(t, "Bearer env-status-secret", receivedAuthHeader)
		assert.Contains(t, out.String(), "node-env")
	})

	t.Run("server returns 503 error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`node is not cluster leader`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "status",
			"--server-url", server.URL,
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 503")
		assert.Contains(t, err.Error(), "node is not cluster leader")
	})

	t.Run("server returns 401 unauthorized", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`unauthorized cluster management request`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "status",
			"--server-url", server.URL,
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 401")
		assert.Contains(t, err.Error(), "unauthorized cluster management request")
	})
}

func TestClusterRemoveCommand(t *testing.T) {
	t.Run("missing server-url flag and env returns error", func(t *testing.T) {
		t.Setenv(EnvServerURL, "")
		t.Setenv("GRANTORY_SERVER_URL", "")
		t.Setenv("SERVER_URL", "")
		t.Setenv(EnvGrantoryControllerServerURL, "")
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"cluster", "remove", "--node-id", "node-2"})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--server-url is required")
	})

	t.Run("missing node-id returns error", func(t *testing.T) {
		t.Setenv(config.EnvRaftNodeID, "")
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"cluster", "remove", "--server-url", "http://127.0.0.1:8080"})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--node-id is required (or set "+config.EnvRaftNodeID+")")
	})

	t.Run("successful remove with explicit flags and address", func(t *testing.T) {
		var receivedHeader string
		var receivedAuthHeader string
		var receivedMethod string
		var receivedPath string
		var receivedPayload map[string]string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedPath = r.URL.Path
			receivedHeader = r.Header.Get("X-Grantory-Cluster-Secret")
			receivedAuthHeader = r.Header.Get("Authorization")

			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &receivedPayload)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","removed":"node-2","address":"127.0.0.1:8082"}`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{
			"cluster", "remove",
			"--server-url", server.URL,
			"--node-id", "node-2",
			"--address", "127.0.0.1:8082",
			"--cluster-secret", "remove-secret",
		})

		err := root.Execute()
		require.NoError(t, err)
		assert.Equal(t, http.MethodPost, receivedMethod)
		assert.Equal(t, "/api/v1/cluster/remove", receivedPath)
		assert.Empty(t, receivedHeader)
		assert.Equal(t, "Bearer remove-secret", receivedAuthHeader)
		assert.Equal(t, "node-2", receivedPayload["node_id"])
		assert.Equal(t, "127.0.0.1:8082", receivedPayload["address"])
		assert.Contains(t, out.String(), `"removed":"node-2"`)
	})

	t.Run("successful remove with environment variables and omitted address", func(t *testing.T) {
		var receivedPayload map[string]any

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &receivedPayload)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","removed":"node-3"}`))
		}))
		defer server.Close()

		t.Setenv(EnvServerURL, server.URL)
		t.Setenv(config.EnvRaftClusterSecret, "env-remove-secret")

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"cluster", "remove", "--node-id", "node-3"})

		err := root.Execute()
		require.NoError(t, err)
		assert.Equal(t, "node-3", receivedPayload["node_id"])
		assert.Nil(t, receivedPayload["address"])
		assert.Contains(t, out.String(), `"removed":"node-3"`)
	})

	t.Run("server returns 400 when removing active cluster leader", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`cannot remove active cluster leader; step down leadership via /api/v1/cluster/step-down or stop the node to elect a new leader before removal`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "remove",
			"--server-url", server.URL,
			"--node-id", "leader-node",
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 400")
		assert.Contains(t, err.Error(), "cannot remove active cluster leader")
	})

	t.Run("server returns 401 unauthorized", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`unauthorized cluster management request`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "remove",
			"--server-url", server.URL,
			"--node-id", "node-x",
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 401")
		assert.Contains(t, err.Error(), "unauthorized cluster management request")
	})
}

func TestClusterRemoveCommand_EnvVarFallback(t *testing.T) {
	t.Run("node-id from env var when flag omitted", func(t *testing.T) {
		var receivedPayload map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &receivedPayload)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","removed":"env-node-1"}`))
		}))
		defer server.Close()

		t.Setenv(EnvServerURL, server.URL)
		t.Setenv(config.EnvRaftNodeID, "env-node-1")
		t.Setenv(config.EnvRaftAdvertise, "")
		t.Setenv(config.EnvRaftBind, "")

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"cluster", "remove"})

		err := root.Execute()
		require.NoError(t, err)
		assert.Equal(t, "env-node-1", receivedPayload["node_id"])
		assert.Nil(t, receivedPayload["address"])
		assert.Contains(t, out.String(), `"removed":"env-node-1"`)
	})

	t.Run("address from EnvRaftAdvertise fallback", func(t *testing.T) {
		var receivedPayload map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &receivedPayload)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","removed":"env-node-2"}`))
		}))
		defer server.Close()

		t.Setenv(EnvServerURL, server.URL)
		t.Setenv(config.EnvRaftNodeID, "env-node-2")
		t.Setenv(config.EnvRaftAdvertise, "127.0.0.1:8084")
		t.Setenv(config.EnvRaftBind, "127.0.0.1:8085")

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"cluster", "remove"})

		err := root.Execute()
		require.NoError(t, err)
		assert.Equal(t, "env-node-2", receivedPayload["node_id"])
		assert.Equal(t, "127.0.0.1:8084", receivedPayload["address"])
	})

	t.Run("address from EnvRaftBind fallback when advertise empty", func(t *testing.T) {
		var receivedPayload map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &receivedPayload)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","removed":"env-node-3"}`))
		}))
		defer server.Close()

		t.Setenv(EnvServerURL, server.URL)
		t.Setenv(config.EnvRaftNodeID, "env-node-3")
		t.Setenv(config.EnvRaftAdvertise, "")
		t.Setenv(config.EnvRaftBind, "127.0.0.1:8085")

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"cluster", "remove"})

		err := root.Execute()
		require.NoError(t, err)
		assert.Equal(t, "env-node-3", receivedPayload["node_id"])
		assert.Equal(t, "127.0.0.1:8085", receivedPayload["address"])
	})

	t.Run("invalid address format returns error", func(t *testing.T) {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "remove",
			"--server-url", "http://127.0.0.1:8080",
			"--node-id", "node-2",
			"--address", "invalid-host",
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `invalid --address "invalid-host": must be in host:port format`)
	})

	t.Run("invalid address format from env returns error", func(t *testing.T) {
		t.Setenv(config.EnvRaftNodeID, "node-2")
		t.Setenv(config.EnvRaftAdvertise, "invalid-host")
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "remove",
			"--server-url", "http://127.0.0.1:8080",
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `invalid --address "invalid-host": must be in host:port format`)
	})

	t.Run("address flag description mentions self-removal fallback", func(t *testing.T) {
		cmd := newClusterRemoveCmd()
		flag := cmd.Flags().Lookup("address")
		require.NotNil(t, flag)
		expectedUsage := "network address of the node to remove (defaults from " + config.EnvRaftAdvertise + " or " + config.EnvRaftBind + " when operating on the local node)"
		assert.Equal(t, expectedUsage, flag.Usage)
	})

	t.Run("node-id from env and address from explicit flag", func(t *testing.T) {
		var receivedPayload map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &receivedPayload)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","removed":"env-node-explicit-addr"}`))
		}))
		defer server.Close()

		t.Setenv(EnvServerURL, server.URL)
		t.Setenv(config.EnvRaftNodeID, "env-node-explicit-addr")
		t.Setenv(config.EnvRaftAdvertise, "10.0.0.1:9300")

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"cluster", "remove", "--address", "127.0.0.1:8089"})

		err := root.Execute()
		require.NoError(t, err)
		assert.Equal(t, "env-node-explicit-addr", receivedPayload["node_id"])
		assert.Equal(t, "127.0.0.1:8089", receivedPayload["address"])
	})

	t.Run("explicit node-id and address flags take precedence over env vars", func(t *testing.T) {
		var receivedPayload map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &receivedPayload)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","removed":"explicit-node"}`))
		}))
		defer server.Close()

		t.Setenv(EnvServerURL, server.URL)
		t.Setenv(config.EnvRaftNodeID, "env-node-ignored")
		t.Setenv(config.EnvRaftAdvertise, "10.0.0.1:9300")
		t.Setenv(config.EnvRaftBind, "10.0.0.2:9300")

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"cluster", "remove", "--node-id", "explicit-node", "--address", "127.0.0.1:8099"})

		err := root.Execute()
		require.NoError(t, err)
		assert.Equal(t, "explicit-node", receivedPayload["node_id"])
		assert.Equal(t, "127.0.0.1:8099", receivedPayload["address"])
	})
}

func TestClusterRemoveCommand_NoAddressContaminationWhenNodeIDExplicit(t *testing.T) {
	var receivedPayload map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","removed":"node-2"}`))
	}))
	defer server.Close()

	t.Setenv(config.EnvRaftAdvertise, "10.0.0.1:9300")
	t.Setenv(config.EnvRaftBind, "10.0.0.1:9300")

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{
		"cluster", "remove",
		"--node-id", "node-2",
		"--server-url", server.URL,
	})

	err := root.Execute()
	require.NoError(t, err)
	assert.Equal(t, "node-2", receivedPayload["node_id"])
	assert.Equal(t, "", receivedPayload["address"])
	assert.NotEqual(t, "10.0.0.1:9300", receivedPayload["address"])
}

func TestClusterRemoveCommand_RejectUnspecifiedIP(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:9300", "[::]:9300"} {
		t.Run(addr, func(t *testing.T) {
			root := NewRootCommand()
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs([]string{
				"cluster", "remove",
				"--server-url", "http://127.0.0.1:8080",
				"--node-id", "node-1",
				"--address", addr,
			})

			err := root.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf("invalid --address %q: address cannot be an unspecified IP (0.0.0.0 or ::)", addr))
		})
	}
}

func TestClusterRemoveCommand_AddressFallbackWhenLocalNode(t *testing.T) {
	var receivedPayload map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","removed":"local-1"}`))
	}))
	defer server.Close()

	t.Setenv(config.EnvRaftNodeID, "local-1")
	t.Setenv(config.EnvRaftAdvertise, "10.0.0.1:9300")

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{
		"cluster", "remove",
		"--node-id", "local-1",
		"--server-url", server.URL,
	})

	err := root.Execute()
	require.NoError(t, err)
	assert.Equal(t, "local-1", receivedPayload["node_id"])
	assert.Equal(t, "10.0.0.1:9300", receivedPayload["address"])
}

func TestClusterJoinCommand_RemoteNodeIDRequiresExplicitAddress(t *testing.T) {
	var receivedPayload map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","joined":"node-2"}`))
	}))
	defer server.Close()

	t.Setenv(config.EnvRaftAdvertise, "10.0.0.1:9300")
	t.Setenv(config.EnvRaftNodeID, "node-1")

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{
		"cluster", "join",
		"--node-id", "node-2",
		"--server-url", server.URL,
	})

	err := root.Execute()
	require.Error(t, err)
	assert.EqualError(t, err, "--address is required when specifying --node-id for a remote node")

	// When node-id matches local node ID, address is inherited from RAFT_ADVERTISE
	t.Setenv(config.EnvRaftNodeID, "node-2")
	root = NewRootCommand()
	out.Reset()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{
		"cluster", "join",
		"--node-id", "node-2",
		"--server-url", server.URL,
	})

	err = root.Execute()
	require.NoError(t, err)
	assert.Equal(t, "node-2", receivedPayload["node_id"])
	assert.Equal(t, "10.0.0.1:9300", receivedPayload["address"])
}

func TestClusterJoinCommand(t *testing.T) {
	t.Run("missing server-url flag and env returns error", func(t *testing.T) {
		t.Setenv(EnvServerURL, "")
		t.Setenv("GRANTORY_SERVER_URL", "")
		t.Setenv("SERVER_URL", "")
		t.Setenv(EnvGrantoryControllerServerURL, "")
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"cluster", "join", "--node-id", "node-2", "--address", "127.0.0.1:8082"})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--server-url is required")
	})

	t.Run("missing node-id returns error", func(t *testing.T) {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"cluster", "join", "--server-url", "http://127.0.0.1:8080", "--address", "127.0.0.1:8082"})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--node-id is required (or set "+config.EnvRaftNodeID+")")
	})

	t.Run("missing address returns error", func(t *testing.T) {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"cluster", "join", "--server-url", "http://127.0.0.1:8080", "--node-id", "node-2"})

		err := root.Execute()
		require.Error(t, err)
		assert.EqualError(t, err, "--address is required when specifying --node-id for a remote node")
	})

	t.Run("missing address returns error when local node-id", func(t *testing.T) {
		t.Setenv(config.EnvRaftNodeID, "node-2")
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"cluster", "join", "--server-url", "http://127.0.0.1:8080", "--node-id", "node-2"})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--address is required (or set "+config.EnvRaftAdvertise+" or "+config.EnvRaftBind+")")
	})

	t.Run("invalid address format returns error", func(t *testing.T) {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "join",
			"--server-url", "http://127.0.0.1:8080",
			"--node-id", "node-2",
			"--address", "invalid-host",
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `invalid --address "invalid-host": must be in host:port format`)
	})

	t.Run("invalid http-address format returns error client-side", func(t *testing.T) {
		invalidAddresses := []string{
			"invalid-url",
			"ftp://127.0.0.1:8080",
			"http://",
			"://bad-url",
		}

		for _, addr := range invalidAddresses {
			t.Run(addr, func(t *testing.T) {
				root := NewRootCommand()
				var out bytes.Buffer
				root.SetOut(&out)
				root.SetErr(&out)
				root.SetArgs([]string{
					"cluster", "join",
					"--server-url", "http://127.0.0.1:8080",
					"--node-id", "node-2",
					"--address", "127.0.0.1:8082",
					"--http-address", addr,
				})

				err := root.Execute()
				require.Error(t, err)
				expected := fmt.Sprintf("invalid --http-address %q: must be a valid http:// or https:// URL", addr)
				assert.Equal(t, expected, err.Error())
			})
		}
	})

	t.Run("unspecified ip in http-address returns error client-side", func(t *testing.T) {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "join",
			"--server-url", "http://127.0.0.1:8080",
			"--node-id", "node-2",
			"--address", "127.0.0.1:8082",
			"--http-address", "http://0.0.0.0:8080",
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "http_address cannot have an unspecified IP host")
	})

	t.Run("successful join with explicit flags", func(t *testing.T) {
		var receivedHeader string
		var receivedAuthHeader string
		var receivedMethod string
		var receivedPath string
		var receivedPayload map[string]string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedPath = r.URL.Path
			receivedHeader = r.Header.Get("X-Grantory-Cluster-Secret")
			receivedAuthHeader = r.Header.Get("Authorization")

			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &receivedPayload)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","joined":"node-2","address":"127.0.0.1:8082"}`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{
			"cluster", "join",
			"--server-url", server.URL,
			"--node-id", "node-2",
			"--address", "127.0.0.1:8082",
			"--http-address", "http://127.0.0.1:8080",
			"--cluster-secret", "join-secret",
		})

		err := root.Execute()
		require.NoError(t, err)
		assert.Equal(t, http.MethodPost, receivedMethod)
		assert.Equal(t, "/api/v1/cluster/join", receivedPath)
		assert.Empty(t, receivedHeader)
		assert.Equal(t, "Bearer join-secret", receivedAuthHeader)
		assert.Equal(t, "node-2", receivedPayload["node_id"])
		assert.Equal(t, "127.0.0.1:8082", receivedPayload["address"])
		assert.Equal(t, "http://127.0.0.1:8080", receivedPayload["http_address"])
		assert.Contains(t, out.String(), `"joined":"node-2"`)
	})

	t.Run("successful join with environment variables", func(t *testing.T) {
		var receivedPayload map[string]any

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &receivedPayload)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","joined":"node-env"}`))
		}))
		defer server.Close()

		t.Setenv(EnvServerURL, server.URL)
		t.Setenv(config.EnvRaftNodeID, "node-env")
		t.Setenv(config.EnvRaftAdvertise, "127.0.0.1:8083")
		t.Setenv(config.EnvRaftClusterSecret, "env-join-secret")

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"cluster", "join"})

		err := root.Execute()
		require.NoError(t, err)
		assert.Equal(t, "node-env", receivedPayload["node_id"])
		assert.Equal(t, "127.0.0.1:8083", receivedPayload["address"])
		assert.Contains(t, out.String(), `"joined":"node-env"`)
	})

	t.Run("server returns 400 error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`http_address cannot have an unspecified IP host`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "join",
			"--server-url", server.URL,
			"--node-id", "node-2",
			"--address", "127.0.0.1:8082",
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 400")
		assert.Contains(t, err.Error(), "http_address cannot have an unspecified IP host")
	})

	t.Run("server returns 401 unauthorized", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`unauthorized cluster management request`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "join",
			"--server-url", server.URL,
			"--node-id", "node-2",
			"--address", "127.0.0.1:8082",
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 401")
		assert.Contains(t, err.Error(), "unauthorized cluster management request")
	})

	t.Run("server returns 409 conflict", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`configuration conflict`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "join",
			"--server-url", server.URL,
			"--node-id", "node-2",
			"--address", "127.0.0.1:8082",
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 409")
		assert.Contains(t, err.Error(), "configuration conflict")
	})

	t.Run("server returns 503 error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`node is not cluster leader`))
		}))
		defer server.Close()

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "join",
			"--server-url", server.URL,
			"--node-id", "node-2",
			"--address", "127.0.0.1:8082",
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 503")
		assert.Contains(t, err.Error(), "node is not cluster leader")
	})

	t.Run("unspecified ipv4 address rejected immediately", func(t *testing.T) {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "join",
			"--server-url", "http://127.0.0.1:8080",
			"--node-id", "node-2",
			"--address", "0.0.0.0:9300",
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `invalid --address "0.0.0.0:9300": address cannot be an unspecified IP (0.0.0.0 or ::)`)
	})

	t.Run("unspecified ipv6 address rejected immediately", func(t *testing.T) {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "join",
			"--server-url", "http://127.0.0.1:8080",
			"--node-id", "node-2",
			"--address", "[::]:9300",
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `invalid --address "[::]:9300": address cannot be an unspecified IP (0.0.0.0 or ::)`)
	})

	t.Run("unspecified ipv4 address from env rejected immediately", func(t *testing.T) {
		t.Setenv(EnvServerURL, "http://127.0.0.1:8080")
		t.Setenv(config.EnvRaftNodeID, "node-2")
		t.Setenv(config.EnvRaftAdvertise, "")
		t.Setenv(config.EnvRaftBind, "0.0.0.0:9300")

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"cluster", "join"})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "address cannot be an unspecified IP")
	})

	t.Run("address flag description mentions local node fallback", func(t *testing.T) {
		cmd := newClusterJoinCmd()
		flag := cmd.Flags().Lookup("address")
		require.NotNil(t, flag)
		expectedUsage := "Raft peer network address of the node to join (defaults to " + config.EnvRaftAdvertise + " or " + config.EnvRaftBind + " when joining the local node)"
		assert.Equal(t, expectedUsage, flag.Usage)
	})
}

func TestExecuteClusterRequest(t *testing.T) {
	t.Run("bounded response reading caps at 1MB", func(t *testing.T) {
		largePayload := bytes.Repeat([]byte("a"), 2*1024*1024) // 2MB
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(largePayload)
		}))
		defer server.Close()

		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)

		cmd := newClusterStatusCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)

		err = executeClusterRequest(cmd, req)
		require.NoError(t, err)
		// 1MB read + 1 newline from Fprintln
		assert.Equal(t, (1<<20)+1, out.Len())
	})

	t.Run("non-200 with empty body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)

		cmd := newClusterStatusCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)

		err = executeClusterRequest(cmd, req)
		require.Error(t, err)
		assert.Equal(t, "cluster request failed (HTTP 500)", err.Error())
	})

	t.Run("nil cmd writes to stdout without panicking", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`cluster operation completed`))
		}))
		defer server.Close()

		req, err := http.NewRequest(http.MethodPost, server.URL, nil)
		require.NoError(t, err)

		oldStdout := os.Stdout
		defer func() { os.Stdout = oldStdout }()
		rPipe, wPipe, err := os.Pipe()
		require.NoError(t, err)
		os.Stdout = wPipe

		err = executeClusterRequest(nil, req)

		_ = wPipe.Close()
		os.Stdout = oldStdout

		require.NoError(t, err)
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rPipe)
		_ = rPipe.Close()

		assert.Contains(t, buf.String(), "cluster operation completed")
	})

	t.Run("uses optionalClient when provided", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`custom client response`))
		}))
		defer server.Close()

		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)

		cmd := newClusterStatusCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)

		err = executeClusterRequest(cmd, req, server.Client())
		require.NoError(t, err)
		assert.Contains(t, out.String(), "custom client response")
	})
}

func TestRunSimpleClusterRequest(t *testing.T) {
	var receivedMethod, receivedPath, receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedPath = r.URL.Path
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`simple response`))
	}))
	defer server.Close()

	cmd := newClusterCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.ParseFlags([]string{"--server-url", server.URL, "--cluster-secret", "sec123"}))

	err := runSimpleClusterRequest(cmd, http.MethodGet, "/api/v1/cluster/status")
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, receivedMethod)
	assert.Equal(t, "/api/v1/cluster/status", receivedPath)
	assert.Equal(t, "Bearer sec123", receivedAuth)
	assert.Contains(t, out.String(), "simple response")
}

func TestApplyClusterAuth(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		wantHeader string
	}{
		{
			name:       "raw secret sets Bearer header",
			secret:     "my-secret",
			wantHeader: "Bearer my-secret",
		},
		{
			name:       "already prefixed with Bearer sets single Bearer header",
			secret:     "Bearer my-secret",
			wantHeader: "Bearer my-secret",
		},
		{
			name:       "lowercase bearer sets properly capitalized Bearer header",
			secret:     "bearer my-secret",
			wantHeader: "Bearer my-secret",
		},
		{
			name:       "uppercase BEARER sets properly capitalized Bearer header",
			secret:     "BEARER my-secret",
			wantHeader: "Bearer my-secret",
		},
		{
			name:       "empty secret does not set header",
			secret:     "",
			wantHeader: "",
		},
		{
			name:       "whitespace only secret does not set header",
			secret:     "   ",
			wantHeader: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://localhost:8080", nil)
			require.NoError(t, err)
			clusterraft.ApplyClusterAuth(req, tt.secret)
			assert.Equal(t, tt.wantHeader, req.Header.Get("Authorization"))
		})
	}
}


func generateTestCACert(t *testing.T, dir string) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Grantory Custom Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPath := filepath.Join(dir, "ca.pem")
	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	require.NoError(t, certOut.Close())

	return certPath
}

func TestResolveClusterHTTPClient(t *testing.T) {
	t.Run("configures custom root CA when --raft-ca-file is supplied via flag", func(t *testing.T) {
		dir := t.TempDir()
		caPath := generateTestCACert(t, dir)

		cmd := newClusterCmd()
		require.NoError(t, cmd.PersistentFlags().Set("raft-ca-file", caPath))

		client, err := resolveClusterHTTPClient(cmd)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NotNil(t, client.Transport)

		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, transport.TLSClientConfig)
		require.NotNil(t, transport.TLSClientConfig.RootCAs)
	})

	t.Run("configures custom root CA via root persistent flags", func(t *testing.T) {
		dir := t.TempDir()
		caPath := generateTestCACert(t, dir)

		root := NewRootCommand()
		root.SetArgs([]string{"cluster", "status", "--raft-ca-file", caPath})
		cmd, _, err := root.Find([]string{"cluster", "status"})
		require.NoError(t, err)
		require.NoError(t, root.ParseFlags([]string{"--raft-ca-file", caPath}))

		client, err := resolveClusterHTTPClient(cmd)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NotNil(t, client.Transport)

		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, transport.TLSClientConfig)
		require.NotNil(t, transport.TLSClientConfig.RootCAs)
	})

	t.Run("configures custom root CA from environment variable", func(t *testing.T) {
		dir := t.TempDir()
		caPath := generateTestCACert(t, dir)

		t.Setenv(config.EnvRaftCAFile, caPath)

		cmd := newClusterStatusCmd()
		client, err := resolveClusterHTTPClient(cmd)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NotNil(t, client.Transport)

		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, transport.TLSClientConfig)
		require.NotNil(t, transport.TLSClientConfig.RootCAs)
	})

	t.Run("configures custom server name and tls-cert", func(t *testing.T) {
		dir := t.TempDir()
		certPath := generateTestCACert(t, dir)

		t.Setenv(config.EnvTLSCert, certPath)
		t.Setenv(config.EnvRaftTLSServerName, "peer.grantory.internal")

		cmd := newClusterStatusCmd()
		client, err := resolveClusterHTTPClient(cmd)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NotNil(t, client.Transport)

		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, transport.TLSClientConfig)
		assert.Equal(t, "peer.grantory.internal", transport.TLSClientConfig.ServerName)
	})

	t.Run("cluster status with HTTPS server and --raft-ca-file", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","cluster":{"leader_id":"node-tls"}}`))
		}))
		defer server.Close()

		dir := t.TempDir()
		caPath := filepath.Join(dir, "ca.pem")
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: server.Certificate().Raw,
		})
		require.NoError(t, os.WriteFile(caPath, certPEM, 0o644))

		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{
			"cluster", "status",
			"--server-url", server.URL,
			"--raft-ca-file", caPath,
		})

		err := root.Execute()
		require.NoError(t, err)
		assert.Contains(t, out.String(), "node-tls")
	})

	t.Run("resolveClusterHTTPClient returns error on invalid CA", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("raft-ca-file", "", "")
		require.NoError(t, cmd.Flags().Set("raft-ca-file", "/nonexistent/ca.pem"))

		client, err := resolveClusterHTTPClient(cmd)
		require.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "build cluster TLS config: read raft CA file:")
	})
}

func TestResolveClusterServerURL(t *testing.T) {
	t.Run("resolves from flag", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("server-url", "", "")
		require.NoError(t, cmd.Flags().Set("server-url", "http://127.0.0.1:8080"))

		url, err := resolveClusterServerURL(cmd)
		require.NoError(t, err)
		assert.Equal(t, "http://127.0.0.1:8080", url)
	})

	t.Run("resolves from GRANTORY_URL env", func(t *testing.T) {
		t.Setenv(EnvServerURL, "")
		t.Setenv("GRANTORY_SERVER_URL", "")
		t.Setenv("SERVER_URL", "")
		t.Setenv(EnvGrantoryControllerServerURL, "")
		t.Setenv("GRANTORY_ADDR", "")
		t.Setenv("GRANTORY_URL", "http://grantory-url:8080")

		cmd := &cobra.Command{}
		url, err := resolveClusterServerURL(cmd)
		require.NoError(t, err)
		assert.Equal(t, "http://grantory-url:8080", url)
	})

	t.Run("resolves from GRANTORY_ADDR env", func(t *testing.T) {
		t.Setenv(EnvServerURL, "")
		t.Setenv("GRANTORY_SERVER_URL", "")
		t.Setenv("SERVER_URL", "")
		t.Setenv(EnvGrantoryControllerServerURL, "")
		t.Setenv("GRANTORY_URL", "")
		t.Setenv("GRANTORY_ADDR", "http://grantory-addr:8080")

		cmd := &cobra.Command{}
		url, err := resolveClusterServerURL(cmd)
		require.NoError(t, err)
		assert.Equal(t, "http://grantory-addr:8080", url)
	})

	t.Run("resolves from GRANTORY_SERVER_URL env", func(t *testing.T) {
		t.Setenv(EnvServerURL, "")
		t.Setenv("SERVER_URL", "")
		t.Setenv(EnvGrantoryControllerServerURL, "")
		t.Setenv("GRANTORY_URL", "")
		t.Setenv("GRANTORY_ADDR", "")
		t.Setenv("GRANTORY_SERVER_URL", "http://grantory-server-url:8080")

		cmd := &cobra.Command{}
		url, err := resolveClusterServerURL(cmd)
		require.NoError(t, err)
		assert.Equal(t, "http://grantory-server-url:8080", url)
	})

	t.Run("resolves from flag overriding env", func(t *testing.T) {
		t.Setenv(EnvServerURL, "http://env-server:8080")
		cmd := &cobra.Command{}
		cmd.Flags().String("server-url", "", "")
		require.NoError(t, cmd.Flags().Set("server-url", "http://flag-server:8080"))

		url, err := resolveClusterServerURL(cmd)
		require.NoError(t, err)
		assert.Equal(t, "http://flag-server:8080", url)
	})

	t.Run("flag with default value does not override env when unchanged", func(t *testing.T) {
		t.Setenv(EnvServerURL, "http://env-server:8080")
		cmd := &cobra.Command{}
		cmd.Flags().String("server-url", "http://default-server:8080", "")

		url, err := resolveClusterServerURL(cmd)
		require.NoError(t, err)
		assert.Equal(t, "http://env-server:8080", url)
	})

	t.Run("resolves from root persistent flag overriding env", func(t *testing.T) {
		t.Setenv(EnvServerURL, "http://env-server:8080")
		root := &cobra.Command{Use: "root"}
		root.PersistentFlags().String("server-url", "", "")
		cmd := &cobra.Command{Use: "sub"}
		root.AddCommand(cmd)
		require.NoError(t, root.PersistentFlags().Set("server-url", "http://root-server:8080"))

		url, err := resolveClusterServerURL(cmd)
		require.NoError(t, err)
		assert.Equal(t, "http://root-server:8080", url)
	})

	t.Run("error when no flag or env provided", func(t *testing.T) {
		t.Setenv(EnvServerURL, "")
		t.Setenv("GRANTORY_SERVER_URL", "")
		t.Setenv("SERVER_URL", "")
		t.Setenv(EnvGrantoryControllerServerURL, "")
		t.Setenv("GRANTORY_URL", "")
		t.Setenv("GRANTORY_ADDR", "")

		cmd := &cobra.Command{}
		_, err := resolveClusterServerURL(cmd)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--server-url is required")
	})
}

func TestResolveClusterServerURL_NormalizesScheme(t *testing.T) {
	t.Run("normalizes host:port without scheme to http", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("server-url", "", "")
		require.NoError(t, cmd.Flags().Set("server-url", "127.0.0.1:8080"))

		url, err := resolveClusterServerURL(cmd)
		require.NoError(t, err)
		assert.Equal(t, "http://127.0.0.1:8080", url)
	})

	t.Run("preserves https scheme", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("server-url", "", "")
		require.NoError(t, cmd.Flags().Set("server-url", "https://127.0.0.1:8443"))

		url, err := resolveClusterServerURL(cmd)
		require.NoError(t, err)
		assert.Equal(t, "https://127.0.0.1:8443", url)
	})

	t.Run("trims trailing slashes", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("server-url", "", "")
		require.NoError(t, cmd.Flags().Set("server-url", "http://127.0.0.1:8080/"))

		url, err := resolveClusterServerURL(cmd)
		require.NoError(t, err)
		assert.Equal(t, "http://127.0.0.1:8080", url)
	})

	t.Run("returns error for invalid URL", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("server-url", "", "")
		require.NoError(t, cmd.Flags().Set("server-url", "http://"))

		_, err := resolveClusterServerURL(cmd)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be a valid host:port or URL")
	})
}

func TestResolveClusterSecret(t *testing.T) {
	t.Run("resolves from flag", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("cluster-secret", "", "")
		require.NoError(t, cmd.Flags().Set("cluster-secret", "flag-secret"))

		secret := resolveClusterSecret(cmd)
		assert.Equal(t, "flag-secret", secret)
	})

	t.Run("resolves from GRANTORY_CLUSTER_SECRET env", func(t *testing.T) {
		t.Setenv(config.EnvRaftClusterSecret, "")
		t.Setenv("GRANTORY_TOKEN", "")
		t.Setenv(EnvToken, "")
		t.Setenv("GRANTORY_CLUSTER_SECRET", "env-grantory-cluster-secret")

		cmd := &cobra.Command{}
		secret := resolveClusterSecret(cmd)
		assert.Equal(t, "env-grantory-cluster-secret", secret)
	})

	t.Run("resolves from RAFT_CLUSTER_SECRET env", func(t *testing.T) {
		t.Setenv("GRANTORY_CLUSTER_SECRET", "")
		t.Setenv("GRANTORY_TOKEN", "")
		t.Setenv(EnvToken, "")
		t.Setenv(config.EnvRaftClusterSecret, "env-raft-cluster-secret")

		cmd := &cobra.Command{}
		secret := resolveClusterSecret(cmd)
		assert.Equal(t, "env-raft-cluster-secret", secret)
	})

	t.Run("resolves from GRANTORY_TOKEN env", func(t *testing.T) {
		t.Setenv(config.EnvRaftClusterSecret, "")
		t.Setenv("GRANTORY_CLUSTER_SECRET", "")
		t.Setenv(EnvToken, "")
		t.Setenv("GRANTORY_TOKEN", "env-grantory-token")

		cmd := &cobra.Command{}
		secret := resolveClusterSecret(cmd)
		assert.Equal(t, "env-grantory-token", secret)
	})

	t.Run("cluster-secret flag overrides GRANTORY_TOKEN env", func(t *testing.T) {
		t.Setenv("GRANTORY_TOKEN", "env-token-secret")

		cmd := &cobra.Command{}
		cmd.Flags().String("cluster-secret", "", "")
		require.NoError(t, cmd.Flags().Set("cluster-secret", "explicit-cluster-secret"))

		secret := resolveClusterSecret(cmd)
		assert.Equal(t, "explicit-cluster-secret", secret)
	})

	t.Run("token flag overrides GRANTORY_CLUSTER_SECRET env", func(t *testing.T) {
		t.Setenv("GRANTORY_CLUSTER_SECRET", "env-cluster-secret")

		cmd := &cobra.Command{}
		cmd.Flags().String("token", "", "")
		require.NoError(t, cmd.Flags().Set("token", "explicit-token"))

		secret := resolveClusterSecret(cmd)
		assert.Equal(t, "explicit-token", secret)
	})

	t.Run("cluster-secret flag with default value does not override env when unchanged", func(t *testing.T) {
		t.Setenv("GRANTORY_CLUSTER_SECRET", "env-cluster-secret")

		cmd := &cobra.Command{}
		cmd.Flags().String("cluster-secret", "default-secret", "")

		secret := resolveClusterSecret(cmd)
		assert.Equal(t, "env-cluster-secret", secret)
	})

	t.Run("root persistent token flag overrides env", func(t *testing.T) {
		t.Setenv("GRANTORY_TOKEN", "env-token-secret")

		root := &cobra.Command{Use: "root"}
		root.PersistentFlags().String(FlagToken, "", "")
		cmd := &cobra.Command{Use: "sub"}
		root.AddCommand(cmd)
		require.NoError(t, root.PersistentFlags().Set(FlagToken, "root-token-secret"))

		secret := resolveClusterSecret(cmd)
		assert.Equal(t, "root-token-secret", secret)
	})

	t.Run("empty string when nothing provided", func(t *testing.T) {
		t.Setenv(config.EnvRaftClusterSecret, "")
		t.Setenv("GRANTORY_CLUSTER_SECRET", "")
		t.Setenv("GRANTORY_TOKEN", "")
		t.Setenv(EnvToken, "")

		cmd := &cobra.Command{}
		secret := resolveClusterSecret(cmd)
		assert.Empty(t, secret)
	})
}

func TestResolveClusterSecret_FlagOverridesEnvToken(t *testing.T) {
	t.Setenv("GRANTORY_TOKEN", "env-token-secret")

	cmd := &cobra.Command{}
	cmd.Flags().String("raft-cluster-secret", "", "")
	require.NoError(t, cmd.Flags().Set("raft-cluster-secret", "explicit-flag-secret"))

	secret := resolveClusterSecret(cmd)
	assert.Equal(t, "explicit-flag-secret", secret)
}

func TestResolveClusterFlagOrEnv_RespectsFlagChanged(t *testing.T) {
	t.Run("default value does not override env var when flag not changed", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR", "env-value")
		cmd := &cobra.Command{}
		cmd.Flags().String("my-flag", "default-value", "")

		val := resolveClusterFlagOrEnv(cmd, "my-flag", "TEST_ENV_VAR")
		assert.Equal(t, "env-value", val)
	})

	t.Run("explicitly changed flag overrides env var even with default", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR", "env-value")
		cmd := &cobra.Command{}
		cmd.Flags().String("my-flag", "default-value", "")
		require.NoError(t, cmd.Flags().Set("my-flag", "flag-override"))

		val := resolveClusterFlagOrEnv(cmd, "my-flag", "TEST_ENV_VAR")
		assert.Equal(t, "flag-override", val)
	})

	t.Run("root persistent flag with default does not override env var when not changed", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR", "env-value")
		root := &cobra.Command{Use: "root"}
		root.PersistentFlags().String("my-flag", "default-value", "")
		cmd := &cobra.Command{Use: "sub"}
		root.AddCommand(cmd)

		val := resolveClusterFlagOrEnv(cmd, "my-flag", "TEST_ENV_VAR")
		assert.Equal(t, "env-value", val)
	})

	t.Run("root persistent flag explicitly changed overrides env var", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR", "env-value")
		root := &cobra.Command{Use: "root"}
		root.PersistentFlags().String("my-flag", "default-value", "")
		cmd := &cobra.Command{Use: "sub"}
		root.AddCommand(cmd)
		require.NoError(t, root.PersistentFlags().Set("my-flag", "root-flag-override"))

		val := resolveClusterFlagOrEnv(cmd, "my-flag", "TEST_ENV_VAR")
		assert.Equal(t, "root-flag-override", val)
	})
}

func TestClusterPersistentFlags(t *testing.T) {
	clusterCmd := newClusterCmd()
	persistentFlags := []string{
		"server-url",
		"cluster-secret",
		"raft-ca-file",
		"raft-cert-file",
		"raft-key-file",
		"tls-cert",
		"tls-key",
		"raft-tls-server-name",
	}
	for _, flagName := range persistentFlags {
		assert.NotNil(t, clusterCmd.PersistentFlags().Lookup(flagName), "expected persistent flag --%s on clusterCmd", flagName)
	}

	subcommands := []string{"status", "join", "remove", "step-down"}
	for _, name := range subcommands {
		cmd, _, err := clusterCmd.Find([]string{name})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		// Verify --server-url and --cluster-secret are not duplicated as local flags
		assert.Nil(t, cmd.NonInheritedFlags().Lookup("server-url"), "subcommand %s should not have local --server-url flag", name)
		assert.Nil(t, cmd.NonInheritedFlags().Lookup("cluster-secret"), "subcommand %s should not have local --cluster-secret flag", name)
	}

	t.Run("subcommands inherit persistent flags", func(t *testing.T) {
		cmd := newClusterCmd()
		require.NoError(t, cmd.PersistentFlags().Set("server-url", "https://leader.example.com:8443"))
		require.NoError(t, cmd.PersistentFlags().Set("cluster-secret", "super-secret-token"))

		for _, name := range subcommands {
			subcmd, _, err := cmd.Find([]string{name})
			require.NoError(t, err)

			serverURL, err := resolveClusterServerURL(subcmd)
			require.NoError(t, err)
			assert.Equal(t, "https://leader.example.com:8443", serverURL)

			secret := resolveClusterSecret(subcmd)
			assert.Equal(t, "super-secret-token", secret)
		}
	})

	t.Run("subcommands resolve flags passed via CLI args", func(t *testing.T) {
		for _, name := range subcommands {
			root := NewRootCommand()
			subcmd, _, err := root.Find([]string{"cluster", name})
			require.NoError(t, err)
			require.NoError(t, subcmd.ParseFlags([]string{"--server-url", "https://cli-arg.example.com:8443", "--cluster-secret", "arg-secret"}))

			serverURL, err := resolveClusterServerURL(subcmd)
			require.NoError(t, err)
			assert.Equal(t, "https://cli-arg.example.com:8443", serverURL)

			secret := resolveClusterSecret(subcmd)
			assert.Equal(t, "arg-secret", secret)
		}
	})
}

func TestClusterCommands_InvalidTLSConfigurationFailsFast(t *testing.T) {
	nonexistentCA := filepath.Join(t.TempDir(), "nonexistent-ca.crt")

	t.Run("cluster status fails fast on invalid TLS CA file", func(t *testing.T) {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "status",
			"--server-url", "https://127.0.0.1:8443",
			"--raft-ca-file", nonexistentCA,
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build cluster TLS config: read raft CA file:")
	})

	t.Run("cluster join fails fast on invalid TLS CA file", func(t *testing.T) {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "join",
			"--server-url", "https://127.0.0.1:8443",
			"--node-id", "node-2",
			"--address", "127.0.0.1:8082",
			"--raft-ca-file", nonexistentCA,
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build cluster TLS config: read raft CA file:")
	})

	t.Run("cluster remove fails fast on invalid TLS CA file", func(t *testing.T) {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "remove",
			"--server-url", "https://127.0.0.1:8443",
			"--node-id", "node-2",
			"--raft-ca-file", nonexistentCA,
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build cluster TLS config: read raft CA file:")
	})

	t.Run("cluster step-down fails fast on invalid TLS CA file", func(t *testing.T) {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{
			"cluster", "step-down",
			"--server-url", "https://127.0.0.1:8443",
			"--raft-ca-file", nonexistentCA,
		})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build cluster TLS config: read raft CA file:")
	})

	t.Run("resolveClusterHTTPClient returns error on invalid TLS config", func(t *testing.T) {
		cmd := newClusterCmd()
		require.NoError(t, cmd.PersistentFlags().Set("raft-ca-file", nonexistentCA))
		client, err := resolveClusterHTTPClient(cmd)
		assert.Nil(t, client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build cluster TLS config: read raft CA file:")
	})
}

func TestResolveClusterFlagOrEnv_DefaultValueFallback(t *testing.T) {
	t.Run("returns flag default value when flag not changed and env vars not set", func(t *testing.T) {
		t.Setenv("TEST_ENV_FALLBACK_1", "")
		t.Setenv("TEST_ENV_FALLBACK_2", "")

		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("my-flag", "my-default-value", "usage")

		val := resolveClusterFlagOrEnv(cmd, "my-flag", "TEST_ENV_FALLBACK_1", "TEST_ENV_FALLBACK_2")
		assert.Equal(t, "my-default-value", val)
	})

	t.Run("env var takes precedence over unchanged flag default value", func(t *testing.T) {
		t.Setenv("TEST_ENV_FALLBACK", "env-precedence-value")

		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("my-flag", "my-default-value", "usage")

		val := resolveClusterFlagOrEnv(cmd, "my-flag", "TEST_ENV_FALLBACK")
		assert.Equal(t, "env-precedence-value", val)
	})

	t.Run("changed flag takes precedence over env var and default value", func(t *testing.T) {
		t.Setenv("TEST_ENV_FALLBACK", "env-precedence-value")

		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("my-flag", "my-default-value", "usage")
		require.NoError(t, cmd.Flags().Set("my-flag", "explicit-cli-val"))

		val := resolveClusterFlagOrEnv(cmd, "my-flag", "TEST_ENV_FALLBACK")
		assert.Equal(t, "explicit-cli-val", val)
	})
}

func TestClusterCommands_RaftCertAndKeyFlags(t *testing.T) {
	clusterCmd := newClusterCmd()
	assert.NotNil(t, clusterCmd.PersistentFlags().Lookup("raft-cert-file"), "expected persistent flag --raft-cert-file on clusterCmd")
	assert.NotNil(t, clusterCmd.PersistentFlags().Lookup("raft-key-file"), "expected persistent flag --raft-key-file on clusterCmd")

	subcommands := []string{"status", "join", "remove", "step-down"}
	for _, name := range subcommands {
		t.Run("subcommand "+name+" inherits raft cert and key flags from clusterCmd", func(t *testing.T) {
			cCmd := newClusterCmd()
			subcmd, _, err := cCmd.Find([]string{name})
			require.NoError(t, err)
			require.NotNil(t, subcmd)

			err = subcmd.ParseFlags([]string{
				"--raft-cert-file", "/etc/ssl/raft-client.crt",
				"--raft-key-file", "/etc/ssl/raft-client.key",
			})
			require.NoError(t, err, "subcommand %s should accept --raft-cert-file and --raft-key-file without error", name)

			certFlag := lookupFlag(subcmd, "raft-cert-file")
			require.NotNil(t, certFlag)
			assert.Equal(t, "/etc/ssl/raft-client.crt", certFlag.Value.String())

			keyFlag := lookupFlag(subcmd, "raft-key-file")
			require.NotNil(t, keyFlag)
			assert.Equal(t, "/etc/ssl/raft-client.key", keyFlag.Value.String())
		})

		t.Run("subcommand "+name+" accepts raft cert and key flags from root", func(t *testing.T) {
			root := NewRootCommand()
			subcmd, _, err := root.Find([]string{"cluster", name})
			require.NoError(t, err)
			require.NotNil(t, subcmd)

			err = subcmd.ParseFlags([]string{
				"--raft-cert-file", "/etc/ssl/raft-client.crt",
				"--raft-key-file", "/etc/ssl/raft-client.key",
			})
			require.NoError(t, err, "subcommand %s should accept --raft-cert-file and --raft-key-file without error", name)

			certFlag := lookupFlag(subcmd, "raft-cert-file")
			require.NotNil(t, certFlag)
			assert.Equal(t, "/etc/ssl/raft-client.crt", certFlag.Value.String())

			keyFlag := lookupFlag(subcmd, "raft-key-file")
			require.NotNil(t, keyFlag)
			assert.Equal(t, "/etc/ssl/raft-client.key", keyFlag.Value.String())
		})
	}
}

func TestClusterRecoverCommand_FlagResolutionConsistency(t *testing.T) {
	t.Run("database flag takes precedence over GRANTORY_DATABASE env var", func(t *testing.T) {
		t.Setenv(config.EnvDatabase, "/env/database/path")
		cmd := newClusterRecoverCmd()
		require.NoError(t, cmd.Flags().Set("database", "/cli/database/path"))

		dataDir := resolveClusterFlagOrEnv(cmd, "database", config.EnvDatabase)
		assert.Equal(t, "/cli/database/path", dataDir)
	})

	t.Run("GRANTORY_DATABASE env var used when database flag omitted", func(t *testing.T) {
		t.Setenv(config.EnvDatabase, "/env/database/path")
		cmd := newClusterRecoverCmd()

		dataDir := resolveClusterFlagOrEnv(cmd, "database", config.EnvDatabase)
		assert.Equal(t, "/env/database/path", dataDir)
	})

	t.Run("default data dir used when database flag and env var omitted", func(t *testing.T) {
		t.Setenv(config.EnvDatabase, "")
		cmd := newClusterRecoverCmd()

		dataDir := resolveClusterFlagOrEnv(cmd, "database", config.EnvDatabase)
		if dataDir == "" {
			dataDir = config.DefaultDataDir
		}
		assert.Equal(t, config.DefaultDataDir, dataDir)
	})

	t.Run("node-id flag takes precedence over GRANTORY_RAFT_NODE_ID env var", func(t *testing.T) {
		t.Setenv(config.EnvRaftNodeID, "env-node-id")
		cmd := newClusterRecoverCmd()
		require.NoError(t, cmd.Flags().Set("node-id", "cli-node-id"))

		nodeID := resolveClusterFlagOrEnv(cmd, "node-id", config.EnvRaftNodeID)
		assert.Equal(t, "cli-node-id", nodeID)
	})

	t.Run("GRANTORY_RAFT_NODE_ID env var used when node-id flag omitted", func(t *testing.T) {
		t.Setenv(config.EnvRaftNodeID, "env-node-id")
		cmd := newClusterRecoverCmd()

		nodeID := resolveClusterFlagOrEnv(cmd, "node-id", config.EnvRaftNodeID)
		assert.Equal(t, "env-node-id", nodeID)
	})

	t.Run("bind flag takes precedence over advertise and bind env vars", func(t *testing.T) {
		t.Setenv(config.EnvRaftAdvertise, "10.0.0.1:8080")
		t.Setenv(config.EnvRaftBind, "10.0.0.2:8080")
		cmd := newClusterRecoverCmd()
		require.NoError(t, cmd.Flags().Set("bind", "127.0.0.1:8080"))

		bindAddr := resolveClusterFlagOrEnv(cmd, "bind", config.EnvRaftAdvertise, config.EnvRaftBind)
		assert.Equal(t, "127.0.0.1:8080", bindAddr)
	})

	t.Run("advertise env var takes precedence over bind env var when bind flag omitted", func(t *testing.T) {
		t.Setenv(config.EnvRaftAdvertise, "10.0.0.1:8080")
		t.Setenv(config.EnvRaftBind, "10.0.0.2:8080")
		cmd := newClusterRecoverCmd()

		bindAddr := resolveClusterFlagOrEnv(cmd, "bind", config.EnvRaftAdvertise, config.EnvRaftBind)
		assert.Equal(t, "10.0.0.1:8080", bindAddr)
	})

	t.Run("bind env var used when advertise env var and bind flag omitted", func(t *testing.T) {
		t.Setenv(config.EnvRaftAdvertise, "")
		t.Setenv(config.EnvRaftBind, "10.0.0.2:8080")
		cmd := newClusterRecoverCmd()

		bindAddr := resolveClusterFlagOrEnv(cmd, "bind", config.EnvRaftAdvertise, config.EnvRaftBind)
		assert.Equal(t, "10.0.0.2:8080", bindAddr)
	})
}

func TestClusterRecoverCommand_DatabaseEnvVar(t *testing.T) {
	t.Run("GRANTORY_DATABASE env var used to reject postgres backend when flag omitted", func(t *testing.T) {
		t.Setenv(config.EnvDatabase, "postgres://user:pass@localhost:5432/grantory")
		cmd := newClusterRecoverCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"--node-id", "survivor-1", "--bind", "127.0.0.1:8081"})

		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "raft cluster recovery is not supported for postgresql backend")
	})

	t.Run("database flag overrides GRANTORY_DATABASE env var", func(t *testing.T) {
		t.Setenv(config.EnvDatabase, "postgres://user:pass@localhost:5432/grantory")
		cmd := newClusterRecoverCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		emptyDir := t.TempDir()
		cmd.SetArgs([]string{"--database", emptyDir, "--node-id", "survivor-1", "--bind", "127.0.0.1:8081"})

		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing recovery: no existing Raft state found in database directory")
	})
}

func TestClusterJoinCommand_HTTPAddressResolution(t *testing.T) {
	t.Run("resolves http-address configured as persistent flag on root command", func(t *testing.T) {
		var receivedPayload map[string]string
		var receivedAuth string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedAuth = r.Header.Get("Authorization")
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &receivedPayload)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","joined":"node-2","address":"127.0.0.1:8082"}`))
		}))
		defer server.Close()

		root := NewRootCommand()
		root.PersistentFlags().String("http-address", "", "HTTP address of the node")
		require.NoError(t, root.PersistentFlags().Set("http-address", "http://127.0.0.1:8080"))

		joinCmd, _, err := root.Find([]string{"cluster", "join"})
		require.NoError(t, err)
		clusterCmd := joinCmd.Parent()
		require.NoError(t, clusterCmd.PersistentFlags().Set("server-url", server.URL))
		require.NoError(t, clusterCmd.PersistentFlags().Set("cluster-secret", "test-secret"))
		require.NoError(t, joinCmd.Flags().Set("node-id", "node-2"))
		require.NoError(t, joinCmd.Flags().Set("address", "127.0.0.1:8082"))

		err = runClusterJoin(joinCmd, nil)
		require.NoError(t, err)
		assert.Equal(t, "Bearer test-secret", receivedAuth)
		assert.Equal(t, "node-2", receivedPayload["node_id"])
		assert.Equal(t, "127.0.0.1:8082", receivedPayload["address"])
		assert.Equal(t, "http://127.0.0.1:8080", receivedPayload["http_address"])
	})

	t.Run("resolves http-address configured via cmd.Flags()", func(t *testing.T) {
		var receivedPayload map[string]string
		var receivedAuth string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedAuth = r.Header.Get("Authorization")
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &receivedPayload)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","joined":"node-2","address":"127.0.0.1:8082"}`))
		}))
		defer server.Close()

		clusterCmd := newClusterCmd()
		joinCmd, _, err := clusterCmd.Find([]string{"join"})
		require.NoError(t, err)
		require.NoError(t, clusterCmd.PersistentFlags().Set("server-url", server.URL))
		require.NoError(t, clusterCmd.PersistentFlags().Set("cluster-secret", "test-secret"))
		require.NoError(t, joinCmd.Flags().Set("node-id", "node-2"))
		require.NoError(t, joinCmd.Flags().Set("address", "127.0.0.1:8082"))
		require.NoError(t, joinCmd.Flags().Set("http-address", "http://127.0.0.1:8090"))

		err = runClusterJoin(joinCmd, nil)
		require.NoError(t, err)
		assert.Equal(t, "Bearer test-secret", receivedAuth)
		assert.Equal(t, "node-2", receivedPayload["node_id"])
		assert.Equal(t, "127.0.0.1:8082", receivedPayload["address"])
		assert.Equal(t, "http://127.0.0.1:8090", receivedPayload["http_address"])
	})

	t.Run("rejects invalid http-address URL configured as persistent flag on root command", func(t *testing.T) {
		invalidURLs := []string{
			"invalid-url",
			"ftp://127.0.0.1:8080",
			"http://",
			"://bad-url",
		}
		for _, invalidURL := range invalidURLs {
			t.Run(invalidURL, func(t *testing.T) {
				root := NewRootCommand()
				root.PersistentFlags().String("http-address", "", "HTTP address of the node")
				require.NoError(t, root.PersistentFlags().Set("http-address", invalidURL))

				joinCmd, _, err := root.Find([]string{"cluster", "join"})
				require.NoError(t, err)
				clusterCmd := joinCmd.Parent()
				require.NoError(t, clusterCmd.PersistentFlags().Set("server-url", "http://127.0.0.1:8080"))
				require.NoError(t, joinCmd.Flags().Set("node-id", "node-2"))
				require.NoError(t, joinCmd.Flags().Set("address", "127.0.0.1:8082"))

				err = runClusterJoin(joinCmd, nil)
				require.Error(t, err)
				assert.Contains(t, err.Error(), fmt.Sprintf("invalid --http-address %q: must be a valid http:// or https:// URL", invalidURL))
			})
		}
	})

	t.Run("rejects unspecified ip in http-address configured as persistent flag on root command", func(t *testing.T) {
		unspecifiedIPs := []string{
			"http://0.0.0.0:8080",
			"http://[::]:8080",
		}
		for _, uip := range unspecifiedIPs {
			t.Run(uip, func(t *testing.T) {
				root := NewRootCommand()
				root.PersistentFlags().String("http-address", "", "HTTP address of the node")
				require.NoError(t, root.PersistentFlags().Set("http-address", uip))

				joinCmd, _, err := root.Find([]string{"cluster", "join"})
				require.NoError(t, err)
				clusterCmd := joinCmd.Parent()
				require.NoError(t, clusterCmd.PersistentFlags().Set("server-url", "http://127.0.0.1:8080"))
				require.NoError(t, joinCmd.Flags().Set("node-id", "node-2"))
				require.NoError(t, joinCmd.Flags().Set("address", "127.0.0.1:8082"))

				err = runClusterJoin(joinCmd, nil)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "http_address cannot have an unspecified IP host")
			})
		}
	})

	t.Run("rejects invalid http-address on cmd.Flags()", func(t *testing.T) {
		clusterCmd := newClusterCmd()
		joinCmd, _, err := clusterCmd.Find([]string{"join"})
		require.NoError(t, err)
		require.NoError(t, clusterCmd.PersistentFlags().Set("server-url", "http://127.0.0.1:8080"))
		require.NoError(t, joinCmd.Flags().Set("node-id", "node-2"))
		require.NoError(t, joinCmd.Flags().Set("address", "127.0.0.1:8082"))
		require.NoError(t, joinCmd.Flags().Set("http-address", "not-a-url"))

		err = runClusterJoin(joinCmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `invalid --http-address "not-a-url": must be a valid http:// or https:// URL`)
	})

	t.Run("rejects unspecified ip in http-address on cmd.Flags()", func(t *testing.T) {
		clusterCmd := newClusterCmd()
		joinCmd, _, err := clusterCmd.Find([]string{"join"})
		require.NoError(t, err)
		require.NoError(t, clusterCmd.PersistentFlags().Set("server-url", "http://127.0.0.1:8080"))
		require.NoError(t, joinCmd.Flags().Set("node-id", "node-2"))
		require.NoError(t, joinCmd.Flags().Set("address", "127.0.0.1:8082"))
		require.NoError(t, joinCmd.Flags().Set("http-address", "http://0.0.0.0:8080"))

		err = runClusterJoin(joinCmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "http_address cannot have an unspecified IP host")
	})
}
