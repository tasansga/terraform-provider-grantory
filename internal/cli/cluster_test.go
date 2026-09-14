package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	hashiraft "github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		var receivedMethod string
		var receivedPath string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedPath = r.URL.Path
			receivedHeader = r.Header.Get("X-Grantory-Cluster-Secret")
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
		assert.Equal(t, "super-secret", receivedHeader)
		assert.Contains(t, out.String(), "leadership transfer initiated")
		assert.Contains(t, out.String(), `"status":"ok"`)
	})

	t.Run("successful step-down with environment variables", func(t *testing.T) {
		var receivedHeader string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeader = r.Header.Get("X-Grantory-Cluster-Secret")
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
		assert.Equal(t, "env-cluster-secret", receivedHeader)
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
		var receivedMethod string
		var receivedPath string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedPath = r.URL.Path
			receivedHeader = r.Header.Get("X-Grantory-Cluster-Secret")
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
		assert.Equal(t, "status-secret", receivedHeader)
		assert.Contains(t, out.String(), "leader_id")
		assert.Contains(t, out.String(), "node-1")
	})

	t.Run("successful status with environment variables", func(t *testing.T) {
		var receivedHeader string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeader = r.Header.Get("X-Grantory-Cluster-Secret")
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
		assert.Equal(t, "env-status-secret", receivedHeader)
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
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"cluster", "remove", "--server-url", "http://127.0.0.1:8080"})

		err := root.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--node-id is required")
	})

	t.Run("successful remove with explicit flags and address", func(t *testing.T) {
		var receivedHeader string
		var receivedMethod string
		var receivedPath string
		var receivedPayload map[string]string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedPath = r.URL.Path
			receivedHeader = r.Header.Get("X-Grantory-Cluster-Secret")

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
		assert.Equal(t, "remove-secret", receivedHeader)
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
