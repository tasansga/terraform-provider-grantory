package raft

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
	nsstore "github.com/tasansga/terraform-provider-grantory/internal/store"
)

type inmemSnapshotSink struct {
	bytes.Buffer
}

func (s *inmemSnapshotSink) ID() string    { return "test-snap" }
func (s *inmemSnapshotSink) Cancel() error { return nil }
func (s *inmemSnapshotSink) Close() error  { return nil }

func TestSnapshotAndRestoreMultiTenant(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	// Write data to default and custom namespaces
	storeDef, err := srcNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	hostDef, err := storeDef.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)
	_, err = NewMutator(storeDef).ApplyCreateHost(ctx, storage.Host{ID: "host-def", CreatedAt: time.Now().UTC()})
	require.NoError(t, err)

	storeCustom, err := srcNSStore.StoreFor(ctx, "tenant_x")
	require.NoError(t, err)
	hostCustom, err := storeCustom.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)
	_, err = NewMutator(storeCustom).ApplyCreateHost(ctx, storage.Host{ID: "host-custom", CreatedAt: time.Now().UTC()})
	require.NoError(t, err)

	fsmSrc := NewFSM(ctx, srcNSStore)
	snap, err := fsmSrc.Snapshot()
	require.NoError(t, err)

	sink := &inmemSnapshotSink{}
	err = snap.Persist(sink)
	require.NoError(t, err)
	snap.Release()

	// Restore into fresh destination directory
	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)
	fsmDst := NewFSM(ctx, dstNSStore)

	err = fsmDst.Restore(io.NopCloser(bytes.NewReader(sink.Bytes())))
	require.NoError(t, err)

	// Verify restored data
	storeDefRestored, err := dstNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	_, err = storeDefRestored.GetHost(ctx, "host-def")
	require.NoError(t, err)
	_, err = storeDefRestored.GetHost(ctx, hostDef.ID)
	require.NoError(t, err)

	storeCustomRestored, err := dstNSStore.StoreFor(ctx, "tenant_x")
	require.NoError(t, err)
	_, err = storeCustomRestored.GetHost(ctx, "host-custom")
	require.NoError(t, err)
	_, err = storeCustomRestored.GetHost(ctx, hostCustom.ID)
	require.NoError(t, err)
}

func TestSnapshotAndRestoreAllEntities(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	type entityGroup struct {
		hostID      string
		schemaDefID string
		reqID       string
		regID       string
	}
	namespaces := []string{nsstore.DefaultNamespace, "tenant_alpha", "tenant_beta"}
	created := make(map[string]entityGroup)

	for _, ns := range namespaces {
		store, err := srcNSStore.StoreFor(ctx, ns)
		require.NoError(t, err)

		// 1. Host
		host, err := store.CreateHost(ctx, storage.Host{
			ID:        "host-" + ns,
			UniqueKey: "uk-" + ns,
			PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...",
			Labels:    map[string]string{"env": "prod", "ns": ns},
		})
		require.NoError(t, err)

		// 2. Schema definition
		schemaRaw := json.RawMessage(`{"type":"object","properties":{"val":{"type":"string"}}}`)
		schemaDef, err := store.CreateSchemaDefinition(ctx, storage.SchemaDefinition{
			UniqueKey: "schema-uk-" + ns,
			Schema:    schemaRaw,
			Labels:    map[string]string{"version": "v1"},
		})
		require.NoError(t, err)

		// 3. Request
		reqPayload := map[string]any{"val": "req-" + ns}
		req, err := store.CreateRequest(ctx, storage.Request{
			HostID:                    host.ID,
			RequestSchemaDefinitionID: schemaDef.ID,
			UniqueKey:                 "req-uk-" + ns,
			Payload:                   reqPayload,
			Mutable:                   true,
			Version:                   1,
			Labels:                    map[string]string{"req_label": "yes"},
		})
		require.NoError(t, err)

		// 4. Grant
		grantPayload := map[string]any{"granted": true}
		_, err = store.CreateGrant(ctx, storage.Grant{
			RequestID:      req.ID,
			Payload:        grantPayload,
			RequestVersion: 1,
		})
		require.NoError(t, err)

		// 5. Register
		regPayload := map[string]any{"registered": true}
		reg, err := store.CreateRegister(ctx, storage.Register{
			HostID:             host.ID,
			SchemaDefinitionID: schemaDef.ID,
			UniqueKey:          "reg-uk-" + ns,
			Payload:            regPayload,
			Mutable:            false,
			Labels:             map[string]string{"reg_label": "yes"},
		})
		require.NoError(t, err)

		created[ns] = entityGroup{
			hostID:      host.ID,
			schemaDefID: schemaDef.ID,
			reqID:       req.ID,
			regID:       reg.ID,
		}
	}

	// Snapshot
	fsmSrc := NewFSM(ctx, srcNSStore)
	snap, err := fsmSrc.Snapshot()
	require.NoError(t, err)

	sink := &inmemSnapshotSink{}
	err = snap.Persist(sink)
	require.NoError(t, err)
	snap.Release()

	// Restore into fresh directory
	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)
	fsmDst := NewFSM(ctx, dstNSStore)

	err = fsmDst.Restore(io.NopCloser(bytes.NewReader(sink.Bytes())))
	require.NoError(t, err)

	// Verify all entities in all namespaces
	for _, ns := range namespaces {
		store, err := dstNSStore.StoreFor(ctx, ns)
		require.NoError(t, err)

		grp := created[ns]

		// Host
		h, err := store.GetHost(ctx, grp.hostID)
		require.NoError(t, err)
		assert.Equal(t, "uk-"+ns, h.UniqueKey)
		assert.Equal(t, "prod", h.Labels["env"])

		// Schema Definition
		sDef, err := store.GetSchemaDefinition(ctx, grp.schemaDefID)
		require.NoError(t, err)
		assert.Equal(t, "schema-uk-"+ns, sDef.UniqueKey)

		// Request
		r, err := store.GetRequest(ctx, grp.reqID)
		require.NoError(t, err)
		assert.Equal(t, "req-uk-"+ns, r.UniqueKey)
		assert.Equal(t, "req-"+ns, r.Payload["val"])

		// Grant
		g, found, err := store.GetGrantForRequest(ctx, grp.reqID)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, true, g.Payload["granted"])

		// Register
		reg, err := store.GetRegister(ctx, grp.regID)
		require.NoError(t, err)
		assert.Equal(t, "reg-uk-"+ns, reg.UniqueKey)
		assert.Equal(t, true, reg.Payload["registered"])
	}
}

func TestSnapshotEmptyNamespaceStore(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	fsmSrc := NewFSM(ctx, srcNSStore)
	snap, err := fsmSrc.Snapshot()
	require.NoError(t, err)

	sink := &inmemSnapshotSink{}
	err = snap.Persist(sink)
	require.NoError(t, err)
	snap.Release()

	// Restore into destination
	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)
	fsmDst := NewFSM(ctx, dstNSStore)

	err = fsmDst.Restore(io.NopCloser(bytes.NewReader(sink.Bytes())))
	require.NoError(t, err)
}

func TestSnapshotReleaseCleanup(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := nsstore.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	store, err := nsStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	_, err = store.CreateHost(ctx, storage.Host{ID: "host-cleanup"})
	require.NoError(t, err)

	fsm := NewFSM(ctx, nsStore)
	snap, err := fsm.Snapshot()
	require.NoError(t, err)

	fsmSnap, ok := snap.(*FSMSnapshot)
	require.True(t, ok)
	require.NotEmpty(t, fsmSnap.tempDir)

	expectedParent := filepath.Join(nsStore.DataDir(), RaftDirName, StagingDirName)
	assert.Equal(t, expectedParent, filepath.Dir(fsmSnap.tempDir), "snapshot temp directory must be inside snapshot staging dir")

	// Verify temp directory exists
	_, err = os.Stat(fsmSnap.tempDir)
	require.NoError(t, err)

	// Release cleans up temp directory
	snap.Release()
	_, err = os.Stat(fsmSnap.tempDir)
	require.True(t, os.IsNotExist(err))

	// Calling Release again is safe
	snap.Release()
}

func TestSnapshotStagingDirectory(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := nsstore.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	store, err := nsStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	_, err = store.CreateHost(ctx, storage.Host{ID: "host-staging"})
	require.NoError(t, err)

	snap, err := NewFSMSnapshotWithHTTPAddrs(ctx, nsStore, nil)
	require.NoError(t, err)
	defer snap.Release()

	expectedParent := filepath.Join(nsStore.DataDir(), RaftDirName, StagingDirName)
	assert.Equal(t, expectedParent, filepath.Dir(snap.tempDir), "snap.tempDir parent directory must match snapshot staging directory on storage volume")
	assert.NotEqual(t, filepath.Clean(os.TempDir()), filepath.Clean(filepath.Dir(snap.tempDir)), "snap.tempDir must not be created directly in os.TempDir()")
	assert.NotEqual(t, filepath.Join(nsStore.DataDir(), RaftDirName, SnapshotsDirName), filepath.Dir(snap.tempDir), "snap.tempDir must not pollute snapshots directory")
	assert.True(t, strings.HasPrefix(filepath.Base(snap.tempDir), "snap-stage-"), "snap.tempDir basename must start with snap-stage-")

	// Verify temp directory exists before Release and is removed after Release
	_, err = os.Stat(snap.tempDir)
	require.NoError(t, err)

	snap.Release()
	_, err = os.Stat(snap.tempDir)
	assert.True(t, os.IsNotExist(err), "snap.tempDir should be cleaned up on Release()")

	// Snapshot parent directory should remain intact on the storage volume
	stat, err := os.Stat(expectedParent)
	require.NoError(t, err)
	assert.True(t, stat.IsDir())
}

func TestSnapshotNilAndErrorHandling(t *testing.T) {
	ctx := context.Background()

	// Snapshot on nil FSM
	var fsmNil *FSM
	_, err := fsmNil.Snapshot()
	require.Error(t, err)

	// Restore on nil FSM
	err = fsmNil.Restore(io.NopCloser(strings.NewReader("")))
	require.Error(t, err)

	// Snapshot on FSM with nil NamespaceStore
	fsmNoStore := NewFSM(ctx, nil)
	_, err = fsmNoStore.Snapshot()
	require.Error(t, err)

	err = fsmNoStore.Restore(io.NopCloser(strings.NewReader("")))
	require.Error(t, err)

	// Restore with nil reader
	dir := t.TempDir()
	nsStore, err := nsstore.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)
	fsm := NewFSM(ctx, nsStore)
	err = fsm.Restore(nil)
	require.Error(t, err)

	// Persist with nil sink
	snap, err := fsm.Snapshot()
	require.NoError(t, err)
	defer snap.Release()
	err = snap.Persist(nil)
	require.Error(t, err)

	// Persist on nil FSMSnapshot
	var snapNil *FSMSnapshot
	err = snapNil.Persist(&inmemSnapshotSink{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fsm snapshot is nil")
}

func TestRestoreInvalidStream(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := nsstore.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)
	fsm := NewFSM(ctx, nsStore)

	// Corrupt gzip stream
	err = fsm.Restore(io.NopCloser(strings.NewReader("not-a-valid-gzip-stream")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gzip")
}

func TestRestorePathTraversalRejected(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := nsstore.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)
	fsm := NewFSM(ctx, nsStore)

	// Construct tar.gz containing malicious path traversal
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: "../../etc/shadow.db",
		Mode: 0o644,
		Size: int64(len("malicious")),
	}
	require.NoError(t, tw.WriteHeader(hdr))
	_, err = tw.Write([]byte("malicious"))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	err = fsm.Restore(io.NopCloser(&buf))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "directory traversal detected")
}

func TestCheckpointAllStores(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := nsstore.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	// Checkpoint empty store
	err = CheckpointAllStores(nsStore)
	require.NoError(t, err)

	// Checkpoint nil store
	err = CheckpointAllStores(nil)
	require.NoError(t, err)

	// Populate stores and checkpoint
	store, err := nsStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	_, err = store.CreateHost(ctx, storage.Host{ID: "host-chk"})
	require.NoError(t, err)

	err = CheckpointAllStores(nsStore)
	require.NoError(t, err)
}

func TestSnapshotCreation_CheckpointContextTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Pre-cancel context to test checkpoint abort

	dir := t.TempDir()
	nsStore, err := nsstore.NewNamespaceStore(context.Background(), dir)
	require.NoError(t, err)

	store, err := nsStore.StoreFor(context.Background(), nsstore.DefaultNamespace)
	require.NoError(t, err)
	_, err = store.CreateHost(context.Background(), storage.Host{ID: "host-chk-cancel"})
	require.NoError(t, err)

	snap, err := NewFSMSnapshotWithHTTPAddrs(ctx, nsStore, nil)
	require.Error(t, err)
	assert.Nil(t, snap)
	assert.Contains(t, err.Error(), "checkpoint stores")

	// Direct checkpoint with canceled context should also fail
	err = CheckpointAllStoresContext(ctx, nsStore)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wal checkpoint namespace")
}

func TestSnapshotCreation_SuccessWithCheckpointTimeout(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := nsstore.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	store, err := nsStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	_, err = store.CreateHost(ctx, storage.Host{ID: "host-snap-ok"})
	require.NoError(t, err)

	snap, err := NewFSMSnapshotWithHTTPAddrs(ctx, nsStore, map[string]string{
		"node-1": "http://127.0.0.1:8080",
	})
	require.NoError(t, err)
	require.NotNil(t, snap)
	defer snap.Release()
}

func TestRestorePurgesOrphanedDatabases(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	// Snapshot source only has default namespace
	storeDef, err := srcNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	hostSnap, err := storeDef.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)

	fsmSrc := NewFSM(ctx, srcNSStore)
	snap, err := fsmSrc.Snapshot()
	require.NoError(t, err)

	sink := &inmemSnapshotSink{}
	require.NoError(t, snap.Persist(sink))
	snap.Release()

	// Destination directory setup
	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)

	// In destination: create default namespace with old data AND an extra namespace
	dstDef, err := dstNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	hostOld, err := dstDef.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)

	dstOrphan, err := dstNSStore.StoreFor(ctx, "tenant_orphan")
	require.NoError(t, err)
	_, err = dstOrphan.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)

	// Write stray companion and raft files directly into destination
	staleDBPath := nsstore.NamespaceDBPath(dstDir, "stale_raw")
	require.NoError(t, os.WriteFile(staleDBPath, []byte("fake-db"), 0o644))
	require.NoError(t, os.WriteFile(staleDBPath+"-wal", []byte("fake-wal"), 0o644))
	require.NoError(t, os.WriteFile(staleDBPath+"-shm", []byte("fake-shm"), 0o644))

	// raft.db must be preserved!
	raftDBPath := filepath.Join(dstDir, "raft.db")
	require.NoError(t, os.WriteFile(raftDBPath, []byte("raft-metadata"), 0o644))

	// Now perform restore
	fsmDst := NewFSM(ctx, dstNSStore)
	err = fsmDst.Restore(io.NopCloser(bytes.NewReader(sink.Bytes())))
	require.NoError(t, err)

	// Verify restored data in default namespace
	dstDefRestored, err := dstNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	h, err := dstDefRestored.GetHost(ctx, hostSnap.ID)
	require.NoError(t, err)
	assert.Equal(t, hostSnap.ID, h.ID)
	_, err = dstDefRestored.GetHost(ctx, hostOld.ID)
	require.Error(t, err)

	// Verify orphaned databases and companion files were purged
	orphanDBPath := nsstore.NamespaceDBPath(dstDir, "tenant_orphan")
	_, err = os.Stat(orphanDBPath)
	assert.True(t, os.IsNotExist(err), "tenant_orphan.db should be purged")

	_, err = os.Stat(staleDBPath)
	assert.True(t, os.IsNotExist(err), "stale_raw.db should be purged")
	_, err = os.Stat(staleDBPath + "-wal")
	assert.True(t, os.IsNotExist(err), "stale_raw.db-wal should be purged")
	_, err = os.Stat(staleDBPath + "-shm")
	assert.True(t, os.IsNotExist(err), "stale_raw.db-shm should be purged")

	// Verify raft.db was preserved
	raftStat, err := os.Stat(raftDBPath)
	require.NoError(t, err, "raft.db must NOT be deleted")
	assert.False(t, raftStat.IsDir())
	content, err := os.ReadFile(raftDBPath)
	require.NoError(t, err)
	assert.Equal(t, "raft-metadata", string(content))
}

func TestRestoreAtomicFailureKeepsTargetIntact(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := nsstore.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	// Create initial state
	store, err := nsStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	hostIntact, err := store.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)

	// Close stores so file locks aren't holding anything
	require.NoError(t, nsStore.Reset())

	// Create an invalid/corrupt archive stream (corrupt tar entry midway)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	hdr := &tar.Header{
		Name: "corrupt.db",
		Mode: 0o644,
		Size: 1024, // Claims 1024 bytes
	}
	require.NoError(t, tw.WriteHeader(hdr))
	_, _ = tw.Write([]byte("short")) // Only writes 5 bytes, then stream truncates
	_ = tw.Close()
	_ = gw.Close()

	fsm := NewFSM(ctx, nsStore)
	err = fsm.Restore(io.NopCloser(&buf))
	require.Error(t, err, "restore should fail on truncated archive")

	// Verify no staging dir was left behind in dir
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range entries {
		assert.False(t, strings.HasPrefix(entry.Name(), "grantory-restore-"), "staging directory should be cleaned up")
	}

	// Verify original database is still intact
	storeAfter, err := nsStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	h, err := storeAfter.GetHost(ctx, hostIntact.ID)
	require.NoError(t, err)
	assert.Equal(t, hostIntact.ID, h.ID)
}

func TestRestoreSkipsNonRegularFilesAndRaftDB(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	store, err := srcNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	hostValid, err := store.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)

	fsmSrc := NewFSM(ctx, srcNSStore)
	snap, err := fsmSrc.Snapshot()
	require.NoError(t, err)
	sink := &inmemSnapshotSink{}
	require.NoError(t, snap.Persist(sink))
	snap.Release()

	// Read valid archive bytes to extract the default db
	gzr, err := gzip.NewReader(bytes.NewReader(sink.Bytes()))
	require.NoError(t, err)
	tr := tar.NewReader(gzr)
	hdr, err := tr.Next()
	require.NoError(t, err)
	dbBytes, err := io.ReadAll(tr)
	require.NoError(t, err)
	_ = gzr.Close()

	// Craft a custom archive containing:
	// 1. Directory entry (TypeDir)
	// 2. raft.db entry (TypeReg)
	// 3. valid _def.db entry (TypeReg)
	var customBuf bytes.Buffer
	gw := gzip.NewWriter(&customBuf)
	tw := tar.NewWriter(gw)

	// Dir entry
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "some_folder/",
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	}))

	// raft.db entry
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "raft.db",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len("malicious-raft-db")),
	}))
	_, err = tw.Write([]byte("malicious-raft-db"))
	require.NoError(t, err)

	// Valid db entry
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     hdr.Name,
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(dbBytes)),
	}))
	_, err = tw.Write(dbBytes)
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	// Restore into destination
	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)
	fsmDst := NewFSM(ctx, dstNSStore)

	err = fsmDst.Restore(io.NopCloser(&customBuf))
	require.NoError(t, err)

	// Verify raft.db was NOT created
	_, err = os.Stat(filepath.Join(dstDir, "raft.db"))
	assert.True(t, os.IsNotExist(err), "raft.db from snapshot should be ignored")

	// Verify valid db was restored
	dstStore, err := dstNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	h, err := dstStore.GetHost(ctx, hostValid.ID)
	require.NoError(t, err)
	assert.Equal(t, hostValid.ID, h.ID)
}

func TestRestoreSnapshotConcurrentReadsBlocked(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	storeDef, err := srcNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	host, err := storeDef.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)

	fsmSrc := NewFSM(ctx, srcNSStore)
	snap, err := fsmSrc.Snapshot()
	require.NoError(t, err)

	sink := &inmemSnapshotSink{}
	require.NoError(t, snap.Persist(sink))
	snap.Release()

	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)
	fsmDst := NewFSM(ctx, dstNSStore)

	// Spin up goroutine doing concurrent StoreFor calls
	readDone := make(chan struct{})
	var readErrors []error
	go func() {
		defer close(readDone)
		for i := 0; i < 20; i++ {
			st, err := dstNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
			if err != nil {
				readErrors = append(readErrors, err)
			} else if st != nil {
				_, _ = st.GetHost(ctx, host.ID)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	// Perform restore concurrently
	err = fsmDst.Restore(io.NopCloser(bytes.NewReader(sink.Bytes())))
	require.NoError(t, err)

	<-readDone
	assert.Empty(t, readErrors, "concurrent reads during restore must not encounter store errors")

	// Final verification that restored host is queryable
	finalStore, err := dstNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	gotHost, err := finalStore.GetHost(ctx, host.ID)
	require.NoError(t, err)
	assert.Equal(t, host.ID, gotHost.ID)
}

func TestSnapshotAndRestoreURLEscapedNamespace(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	ns := "team:billing"
	storeEsc, err := srcNSStore.StoreFor(ctx, ns)
	require.NoError(t, err)

	host, err := storeEsc.CreateHost(ctx, storage.Host{
		ID:        "host-team-billing",
		UniqueKey: "uk-team-billing",
	})
	require.NoError(t, err)

	fsmSrc := NewFSM(ctx, srcNSStore)
	snap, err := fsmSrc.Snapshot()
	require.NoError(t, err)

	sink := &inmemSnapshotSink{}
	err = snap.Persist(sink)
	require.NoError(t, err)
	snap.Release()

	// Verify that the snapshot tar archive contains the escaped filename team%3Abilling.db
	// and does NOT contain unescaped team:billing.db or duplicates
	gzr, err := gzip.NewReader(bytes.NewReader(sink.Bytes()))
	require.NoError(t, err)
	tr := tar.NewReader(gzr)
	var names []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		names = append(names, hdr.Name)
	}
	_ = gzr.Close()

	expectedName := filepath.Base(nsstore.NamespaceDBPath(srcDir, ns))
	assert.Contains(t, names, expectedName)
	assert.Equal(t, 1, countOccurrences(names, expectedName), "must not duplicate snapshot files")

	// Restore into fresh destination directory
	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)
	fsmDst := NewFSM(ctx, dstNSStore)

	err = fsmDst.Restore(io.NopCloser(bytes.NewReader(sink.Bytes())))
	require.NoError(t, err)

	// Verify restored data can be read via StoreFor with the escaped namespace
	storeRestored, err := dstNSStore.StoreFor(ctx, ns)
	require.NoError(t, err)

	gotHost, err := storeRestored.GetHost(ctx, host.ID)
	require.NoError(t, err)
	assert.Equal(t, host.ID, gotHost.ID)
}

func countOccurrences(slice []string, val string) int {
	cnt := 0
	for _, s := range slice {
		if s == val {
			cnt++
		}
	}
	return cnt
}

func TestSnapshotVacuumFailureRejectsFallback(t *testing.T) {
	t.Run("inactive corrupt db fails snapshot without copyFile fallback", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		nsStore, err := nsstore.NewNamespaceStore(ctx, dir)
		require.NoError(t, err)

		// Create a valid default store
		storeDef, err := nsStore.StoreFor(ctx, nsstore.DefaultNamespace)
		require.NoError(t, err)
		_, err = storeDef.CreateHost(ctx, storage.Host{ID: "host-1"})
		require.NoError(t, err)

		// Place a corrupt inactive .db file directly into dir
		corruptPath := filepath.Join(dir, "inactive_corrupt.db")
		require.NoError(t, os.WriteFile(corruptPath, []byte("NOT-A-SQLITE-FILE"), 0o644))

		// Snapshot must fail because VACUUM INTO fails on inactive_corrupt.db
		snap, err := NewFSMSnapshot(ctx, nsStore)
		require.Error(t, err, "snapshot must fail when VACUUM INTO fails on an inactive db")
		assert.Nil(t, snap)
		assert.Contains(t, err.Error(), "vacuum")
	})

	t.Run("active store vacuum failure returns error immediately", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		nsStore, err := nsstore.NewNamespaceStore(ctx, dir)
		require.NoError(t, err)

		storeDef, err := nsStore.StoreFor(ctx, nsstore.DefaultNamespace)
		require.NoError(t, err)
		_, err = storeDef.CreateHost(ctx, storage.Host{ID: "host-1"})
		require.NoError(t, err)

		db := storeDef.DB()
		require.NotNil(t, db)
		_, err = db.Exec("PRAGMA query_only = ON")
		require.NoError(t, err)

		snap, err := NewFSMSnapshot(ctx, nsStore)
		require.Error(t, err, "snapshot must fail when VACUUM INTO fails on an active store")
		assert.Nil(t, snap)
		assert.Contains(t, err.Error(), "vacuum")
	})
}

func TestSnapshotInactiveURLEscapedNamespace(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()

	// Create an inactive SQLite file directly in dataDir with URL-escaped name
	escapedDBPath := filepath.Join(dataDir, "team%3Abilling.db")
	require.True(t, strings.HasSuffix(escapedDBPath, "team%3Abilling.db"))

	rawDB, err := sql.Open("sqlite3", escapedDBPath)
	require.NoError(t, err)
	_, err = rawDB.Exec("CREATE TABLE test_table (id TEXT PRIMARY KEY, value TEXT); INSERT INTO test_table VALUES ('1', 'hello');")
	require.NoError(t, err)
	require.NoError(t, rawDB.Close())

	// Create nsStore for dataDir without calling StoreFor("team:billing"), so it remains inactive
	nsStore, err := nsstore.NewNamespaceStore(ctx, dataDir)
	require.NoError(t, err)

	// Call NewFSMSnapshot which must snapshot inactive DB files via vacuumIntoFile
	snap, err := NewFSMSnapshot(ctx, nsStore)
	require.NoError(t, err, "vacuumIntoFile must succeed on inactive db with URL-escaped filename")
	require.NotNil(t, snap)
	defer snap.Release()

	// Verify the snapshot contains team%3Abilling.db
	sink := &inmemSnapshotSink{}
	require.NoError(t, snap.Persist(sink))

	gzr, err := gzip.NewReader(bytes.NewReader(sink.Bytes()))
	require.NoError(t, err)
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)
	var found bool
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if hdr.Name == "team%3Abilling.db" {
			found = true
		}
	}
	assert.True(t, found, "team%3Abilling.db must be present in snapshot")
}

type mockTestRegistrar struct {
	mu    sync.Mutex
	addrs map[string]string
}

func (m *mockTestRegistrar) RegisterHTTPAddr(raftAddrOrID, httpAddr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addrs == nil {
		m.addrs = make(map[string]string)
	}
	m.addrs[raftAddrOrID] = httpAddr
}

func (m *mockTestRegistrar) DeregisterHTTPAddr(raftAddrOrID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addrs != nil {
		delete(m.addrs, raftAddrOrID)
	}
}

func (m *mockTestRegistrar) HTTPAddrs() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addrs == nil {
		return nil
	}
	cp := make(map[string]string, len(m.addrs))
	for k, v := range m.addrs {
		cp[k] = v
	}
	return cp
}

func (m *mockTestRegistrar) ResetHTTPAddrs(addrs map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addrs = make(map[string]string, len(addrs))
	for k, v := range addrs {
		m.addrs[k] = v
	}
}

func TestSnapshotAndRestoreWithHTTPAddrs(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	storeDef, err := srcNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	hostDef, err := storeDef.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)

	fsmSrc := NewFSM(ctx, srcNSStore)
	srcReg := &mockTestRegistrar{
		addrs: map[string]string{
			"node-1":        "http://10.0.0.1:8080",
			"10.0.0.1:9090": "http://10.0.0.1:8080",
			"node-2":        "http://10.0.0.2:8080",
			"10.0.0.2:9090": "http://10.0.0.2:8080",
		},
	}
	fsmSrc.SetRegistrar(srcReg)

	snap, err := fsmSrc.Snapshot()
	require.NoError(t, err)
	require.NotNil(t, snap)

	sink := &inmemSnapshotSink{}
	err = snap.Persist(sink)
	require.NoError(t, err)
	snap.Release()

	// Verify tar archive contains cluster_http_addrs.json
	gzr, err := gzip.NewReader(bytes.NewReader(sink.Bytes()))
	require.NoError(t, err)
	tr := tar.NewReader(gzr)
	var foundAddrsFile bool
	var extractedAddrs map[string]string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if hdr.Name == "cluster_http_addrs.json" {
			foundAddrsFile = true
			data, err := io.ReadAll(tr)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(data, &extractedAddrs))
		}
	}
	require.True(t, foundAddrsFile, "cluster_http_addrs.json must be present in snapshot tar")
	assert.Equal(t, srcReg.addrs, extractedAddrs)

	// Restore into fresh destination directory with fresh registrar
	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)
	fsmDst := NewFSM(ctx, dstNSStore)
	dstReg := &mockTestRegistrar{}
	fsmDst.SetRegistrar(dstReg)

	err = fsmDst.Restore(io.NopCloser(bytes.NewReader(sink.Bytes())))
	require.NoError(t, err)

	// Verify restored data in DB
	storeDefRestored, err := dstNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	_, err = storeDefRestored.GetHost(ctx, hostDef.ID)
	require.NoError(t, err)

	// Verify HTTP addresses restored into dstReg
	assert.Equal(t, srcReg.addrs, dstReg.HTTPAddrs())

	// Verify cluster_http_addrs.json was NOT leaked/copied into dstDir
	_, err = os.Stat(filepath.Join(dstDir, "cluster_http_addrs.json"))
	assert.True(t, os.IsNotExist(err), "cluster_http_addrs.json must not be copied into tenant sqlite dir")
}

func TestRaftNodeHTTPAddrs(t *testing.T) {
	node := &RaftNode{
		httpAddrs: map[string]string{
			"node-1": "http://10.0.0.1:8080",
			"node-2": "http://10.0.0.2:8080",
		},
	}
	addrs := node.HTTPAddrs()
	assert.Equal(t, map[string]string{
		"node-1": "http://10.0.0.1:8080",
		"node-2": "http://10.0.0.2:8080",
	}, addrs)

	// Verify mutation of returned copy does not affect internal node state
	addrs["node-3"] = "http://10.0.0.3:8080"
	assert.Empty(t, node.HTTPAddrFor("node-3"))
}

func TestSnapshotAndRestoreWithoutHTTPAddrs(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	storeDef, err := srcNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	hostDef, err := storeDef.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)

	snap, err := NewFSMSnapshotWithHTTPAddrs(ctx, srcNSStore, nil)
	require.NoError(t, err)
	require.NotNil(t, snap)

	sink := &inmemSnapshotSink{}
	err = snap.Persist(sink)
	require.NoError(t, err)
	snap.Release()

	// Verify tar archive contains cluster_http_addrs.json with empty map
	gzr, err := gzip.NewReader(bytes.NewReader(sink.Bytes()))
	require.NoError(t, err)
	tr := tar.NewReader(gzr)
	var foundAddrsFile bool
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if hdr.Name == "cluster_http_addrs.json" {
			foundAddrsFile = true
			data, err := io.ReadAll(tr)
			require.NoError(t, err)
			var addrs map[string]string
			require.NoError(t, json.Unmarshal(data, &addrs))
			assert.Empty(t, addrs)
		}
	}
	require.True(t, foundAddrsFile, "cluster_http_addrs.json must be present in snapshot tar even when empty")

	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)

	dstReg := &mockTestRegistrar{
		addrs: map[string]string{
			"stale-node": "http://10.0.0.99:8080",
		},
	}
	err = RestoreSnapshotWithRegistrar(io.NopCloser(bytes.NewReader(sink.Bytes())), dstNSStore, dstReg)
	require.NoError(t, err)

	storeDefRestored, err := dstNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	_, err = storeDefRestored.GetHost(ctx, hostDef.ID)
	require.NoError(t, err)
	assert.Empty(t, dstReg.HTTPAddrs(), "empty cluster_http_addrs.json must flush pre-existing registrar entries")
}

func TestSnapshotRestore_FlushesStaleHTTPAddrsOnEmptySnapshot(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	// Source has no HTTP addresses registered
	fsmSrc := NewFSM(ctx, srcNSStore)
	srcReg := &mockTestRegistrar{addrs: map[string]string{}}
	fsmSrc.SetRegistrar(srcReg)

	snap, err := fsmSrc.Snapshot()
	require.NoError(t, err)
	require.NotNil(t, snap)

	sink := &inmemSnapshotSink{}
	err = snap.Persist(sink)
	require.NoError(t, err)
	snap.Release()

	// Destination registrar has pre-existing entries
	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)
	fsmDst := NewFSM(ctx, dstNSStore)
	dstReg := &mockTestRegistrar{
		addrs: map[string]string{
			"node-stale-1": "http://10.0.0.1:8080",
			"node-stale-2": "http://10.0.0.2:8080",
		},
	}
	fsmDst.SetRegistrar(dstReg)

	err = fsmDst.Restore(io.NopCloser(bytes.NewReader(sink.Bytes())))
	require.NoError(t, err)

	assert.Empty(t, dstReg.HTTPAddrs(), "restoring snapshot with zero HTTP addresses must flush pre-existing registrar entries")
}

func TestSnapshotRestore_OmittedHTTPAddrsFlushesStaleRegistrar(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	storeDef, err := srcNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	host, err := storeDef.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)

	fsmSrc := NewFSM(ctx, srcNSStore)
	snap, err := fsmSrc.Snapshot()
	require.NoError(t, err)

	sink := &inmemSnapshotSink{}
	require.NoError(t, snap.Persist(sink))
	snap.Release()

	// Build an archive that strips out cluster_http_addrs.json to simulate an older snapshot
	gzr, err := gzip.NewReader(bytes.NewReader(sink.Bytes()))
	require.NoError(t, err)
	tr := tar.NewReader(gzr)

	var strippedBuf bytes.Buffer
	gw := gzip.NewWriter(&strippedBuf)
	tw := tar.NewWriter(gw)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if hdr.Name == "cluster_http_addrs.json" {
			continue // omit cluster_http_addrs.json
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err = io.Copy(tw, tr)
		require.NoError(t, err)
	}
	require.NoError(t, gzr.Close())
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	// Destination registrar has pre-existing entries
	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)

	dstReg := &mockTestRegistrar{
		addrs: map[string]string{
			"stale-node": "http://10.0.0.99:8080",
		},
	}

	err = RestoreSnapshotWithRegistrar(io.NopCloser(&strippedBuf), dstNSStore, dstReg)
	require.NoError(t, err)

	storeDefRestored, err := dstNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	_, err = storeDefRestored.GetHost(ctx, host.ID)
	require.NoError(t, err)

	assert.Empty(t, dstReg.HTTPAddrs(), "omitted cluster_http_addrs.json must call ResetHTTPAddrs(nil) and flush pre-existing entries")
}

func TestSnapshotRestorePurgesStaleHTTPAddrs(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	fsmSrc := NewFSM(ctx, srcNSStore)
	srcReg := &mockTestRegistrar{
		addrs: map[string]string{
			"node-1": "http://10.0.0.1:8080",
			"node-2": "http://10.0.0.2:8080",
		},
	}
	fsmSrc.SetRegistrar(srcReg)

	snap, err := fsmSrc.Snapshot()
	require.NoError(t, err)
	require.NotNil(t, snap)

	sink := &inmemSnapshotSink{}
	err = snap.Persist(sink)
	require.NoError(t, err)
	snap.Release()

	// Destination registrar contains a stale entry for node-99 (which was removed before snapshot)
	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)
	fsmDst := NewFSM(ctx, dstNSStore)
	dstReg := &mockTestRegistrar{
		addrs: map[string]string{
			"node-99": "http://10.0.0.99:8080",
		},
	}
	fsmDst.SetRegistrar(dstReg)

	err = fsmDst.Restore(io.NopCloser(bytes.NewReader(sink.Bytes())))
	require.NoError(t, err)

	// Stale node-99 must be purged, only node-1 and node-2 should exist in dstReg
	expected := map[string]string{
		"node-1": "http://10.0.0.1:8080",
		"node-2": "http://10.0.0.2:8080",
	}
	assert.Equal(t, expected, dstReg.HTTPAddrs(), "stale HTTP addresses must be purged during snapshot restore")
}

func TestRaftNodeResetHTTPAddrs(t *testing.T) {
	node := &RaftNode{
		httpAddrs: map[string]string{
			"stale-node": "http://10.0.0.99:8080",
		},
		addrByServerID: map[string]string{
			"node-1": "10.0.0.1:9090",
		},
		serverIDByAddr: map[string]string{
			"10.0.0.2:9090": "node-2",
		},
	}

	// Reset with new addresses
	newAddrs := map[string]string{
		"node-1":        "http://10.0.0.1:8080",
		"10.0.0.2:9090": "http://10.0.0.2:8080",
	}
	node.ResetHTTPAddrs(newAddrs)

	// Verify stale address is purged
	assert.Empty(t, node.HTTPAddrFor("stale-node"))

	// Verify reciprocal mappings were realigned
	assert.Equal(t, "http://10.0.0.1:8080", node.HTTPAddrFor("node-1"))
	assert.Equal(t, "http://10.0.0.1:8080", node.HTTPAddrFor("10.0.0.1:9090"), "reciprocal addr for node-1 should be populated")

	assert.Equal(t, "http://10.0.0.2:8080", node.HTTPAddrFor("10.0.0.2:9090"))
	assert.Equal(t, "http://10.0.0.2:8080", node.HTTPAddrFor("node-2"), "reciprocal serverID for 10.0.0.2:9090 should be populated")

	// Reset with nil clears map
	node.ResetHTTPAddrs(nil)
	assert.Empty(t, node.HTTPAddrs())
}

func TestRestoreSnapshot_PreservesStaticHTTPAddrs(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := nsstore.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:18091",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 1,
		RaftPeers: []string{
			"node-peer=127.0.0.1:18092@http://127.0.0.1:8092",
		},
		RaftPeerHTTPAddrs: []string{
			"node-extra=http://127.0.0.1:8093",
		},
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	// Verify static addresses are registered on boot
	assert.Equal(t, "http://127.0.0.1:8092", node.HTTPAddrFor("node-peer"))
	assert.Equal(t, "http://127.0.0.1:8092", node.HTTPAddrFor("127.0.0.1:18092"))
	assert.Equal(t, "http://127.0.0.1:8093", node.HTTPAddrFor("node-extra"))

	// Build snapshot archive with empty cluster_http_addrs.json ("{}")
	var bufEmptyMap bytes.Buffer
	gw := gzip.NewWriter(&bufEmptyMap)
	tw := tar.NewWriter(gw)
	data := []byte("{}")
	hdr := &tar.Header{
		Name:     "cluster_http_addrs.json",
		Mode:     0o644,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
	}
	require.NoError(t, tw.WriteHeader(hdr))
	_, err = tw.Write(data)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	// Restore snapshot with empty map: static addresses must remain preserved
	err = RestoreSnapshotWithRegistrar(io.NopCloser(&bufEmptyMap), nsStore, node)
	require.NoError(t, err)

	assert.Equal(t, "http://127.0.0.1:8092", node.HTTPAddrFor("node-peer"))
	assert.Equal(t, "http://127.0.0.1:8092", node.HTTPAddrFor("127.0.0.1:18092"))
	assert.Equal(t, "http://127.0.0.1:8093", node.HTTPAddrFor("node-extra"))

	// Build snapshot archive omitting cluster_http_addrs.json entirely (invokes ResetHTTPAddrs(nil))
	var bufOmitted bytes.Buffer
	gw = gzip.NewWriter(&bufOmitted)
	tw = tar.NewWriter(gw)
	// Empty tar archive
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	err = RestoreSnapshotWithRegistrar(io.NopCloser(&bufOmitted), nsStore, node)
	require.NoError(t, err)

	assert.Equal(t, "http://127.0.0.1:8092", node.HTTPAddrFor("node-peer"))
	assert.Equal(t, "http://127.0.0.1:8092", node.HTTPAddrFor("127.0.0.1:18092"))
	assert.Equal(t, "http://127.0.0.1:8093", node.HTTPAddrFor("node-extra"))

	// Direct ResetHTTPAddrs(nil) call also preserves static endpoints
	node.ResetHTTPAddrs(nil)
	assert.Equal(t, "http://127.0.0.1:8092", node.HTTPAddrFor("node-peer"))
	assert.Equal(t, "http://127.0.0.1:8092", node.HTTPAddrFor("127.0.0.1:18092"))
	assert.Equal(t, "http://127.0.0.1:8093", node.HTTPAddrFor("node-extra"))
}

func TestRestoreSnapshot_ExceedsDBSizeLimit(t *testing.T) {
	ctx := context.Background()
	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name:     "default.db",
		Mode:     0o644,
		Size:     maxSnapshotDBBytes + 1024,
		Typeflag: tar.TypeReg,
	}
	require.NoError(t, tw.WriteHeader(hdr))
	require.NoError(t, gw.Close())

	err = RestoreSnapshot(io.NopCloser(bytes.NewReader(buf.Bytes())), dstNSStore)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed size of 1073741824 bytes")
}

func TestRestoreSnapshot_ExceedsMetadataSizeLimit(t *testing.T) {
	ctx := context.Background()

	t.Run("header size exceeds limit", func(t *testing.T) {
		dstDir := t.TempDir()
		dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
		require.NoError(t, err)

		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)

		hdr := &tar.Header{
			Name:     "cluster_http_addrs.json",
			Mode:     0o644,
			Size:     maxSnapshotMetadataBytes + 1,
			Typeflag: tar.TypeReg,
		}
		require.NoError(t, tw.WriteHeader(hdr))
		require.NoError(t, gw.Close())

		err = RestoreSnapshotWithRegistrar(io.NopCloser(bytes.NewReader(buf.Bytes())), dstNSStore, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cluster_http_addrs.json exceeds maximum allowed size of 10485760 bytes")
	})
}

func TestSnapshotVACUUMTimeout_Constant(t *testing.T) {
	assert.Equal(t, 5*time.Minute, defaultSnapshotVACUUMTimeout)
}

func TestSnapshotTimeout_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel context

	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(context.Background(), srcDir)
	require.NoError(t, err)

	storeDef, err := srcNSStore.StoreFor(context.Background(), nsstore.DefaultNamespace)
	require.NoError(t, err)
	_, err = storeDef.CreateHost(context.Background(), storage.Host{})
	require.NoError(t, err)

	_, err = NewFSMSnapshot(ctx, srcNSStore)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context canceled"), "expected context canceled error, got: %v", err)
}

func TestVacuumIntoFile_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel context

	srcDir := t.TempDir()
	srcDB := filepath.Join(srcDir, "test.db")
	db, err := sql.Open("sqlite3", srcDB)
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE test (id TEXT PRIMARY KEY);")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	dstDB := filepath.Join(srcDir, "backup.db")
	err = vacuumIntoFile(ctx, srcDB, dstDB)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context canceled"), "expected context canceled error, got: %v", err)
}

func TestRestoreSnapshot_CommitDBCopyFallbackFailure(t *testing.T) {
	ctx := context.Background()

	// 1. Create a snapshot tar containing a valid default.db
	srcDir := t.TempDir()
	srcDB := filepath.Join(srcDir, "default.db")
	db, err := sql.Open("sqlite3", srcDB)
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE t (id TEXT PRIMARY KEY);")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	dbBytes, err := os.ReadFile(srcDB)
	require.NoError(t, err)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name:     "default.db",
		Mode:     0o644,
		Size:     int64(len(dbBytes)),
		Typeflag: tar.TypeReg,
	}
	require.NoError(t, tw.WriteHeader(hdr))
	_, err = tw.Write(dbBytes)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	// 2. Prepare target directory where default.db is an existing directory,
	// causing both os.Rename(stagedPath, destPath) and copyFile(stagedPath, destPath) to fail.
	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)

	err = os.Mkdir(filepath.Join(dstDir, "default.db"), 0o755)
	require.NoError(t, err)

	// 3. Attempt RestoreSnapshot and verify error formatting and wrapping
	err = RestoreSnapshot(io.NopCloser(bytes.NewReader(buf.Bytes())), dstNSStore)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "commit db file default.db: copy fallback failed:")
	assert.Contains(t, err.Error(), "(rename failed:")

	// Verify that the root copyErr is properly wrapped
	var pathErr *os.PathError
	assert.True(t, errors.As(err, &pathErr), "expected wrapped PathError, got: %v", err)
}

func TestRestoreSnapshot_InvalidSQLiteHeaderMagic(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := nsstore.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	// Create initial database with a host so we can verify target directory remains intact
	store, err := nsStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	hostIntact, err := store.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)

	// Close stores to release locks
	require.NoError(t, nsStore.Reset())

	// Test 1: File is too short (< 16 bytes)
	t.Run("file shorter than 16 bytes", func(t *testing.T) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)

		shortContent := []byte("short-bad")
		hdr := &tar.Header{
			Name:     "corrupt.db",
			Mode:     0o644,
			Size:     int64(len(shortContent)),
			Typeflag: tar.TypeReg,
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err = tw.Write(shortContent)
		require.NoError(t, err)
		require.NoError(t, tw.Close())
		require.NoError(t, gw.Close())

		fsm := NewFSM(ctx, nsStore)
		err = fsm.Restore(io.NopCloser(bytes.NewReader(buf.Bytes())))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "snapshot database file corrupt.db is not a valid SQLite database (invalid header magic)")

		// Verify original database still intact
		storeAfter, err := nsStore.StoreFor(ctx, nsstore.DefaultNamespace)
		require.NoError(t, err)
		h, err := storeAfter.GetHost(ctx, hostIntact.ID)
		require.NoError(t, err)
		assert.Equal(t, hostIntact.ID, h.ID)
	})

	// Test 2: File is >= 16 bytes but does not start with SQLite format 3\x00
	t.Run("file has invalid 16-byte header", func(t *testing.T) {
		require.NoError(t, nsStore.Reset())

		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)

		invalidMagicContent := []byte("THIS_IS_NOT_SQLITE_HEADER_12345")
		hdr := &tar.Header{
			Name:     "tenant_bad.db",
			Mode:     0o644,
			Size:     int64(len(invalidMagicContent)),
			Typeflag: tar.TypeReg,
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err = tw.Write(invalidMagicContent)
		require.NoError(t, err)
		require.NoError(t, tw.Close())
		require.NoError(t, gw.Close())

		fsm := NewFSM(ctx, nsStore)
		err = fsm.Restore(io.NopCloser(bytes.NewReader(buf.Bytes())))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "snapshot database file tenant_bad.db is not a valid SQLite database (invalid header magic)")

		// Verify tenant_bad.db was NOT committed to the data directory
		_, err = os.Stat(filepath.Join(dir, "tenant_bad.db"))
		assert.True(t, os.IsNotExist(err), "invalid database file must not be committed to data directory")

		// Verify original database still intact
		storeAfter, err := nsStore.StoreFor(ctx, nsstore.DefaultNamespace)
		require.NoError(t, err)
		h, err := storeAfter.GetHost(ctx, hostIntact.ID)
		require.NoError(t, err)
		assert.Equal(t, hostIntact.ID, h.ID)
	})
}

func TestNewRaftNode_CleansStaleStagingDirectories(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := nsstore.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	// Pre-create stale staging directories and a non-staging directory
	stagingDir := filepath.Join(dir, RaftDirName, StagingDirName)
	stale1 := filepath.Join(stagingDir, "snap-stage-11111")
	stale2 := filepath.Join(stagingDir, "snap-stage-22222")
	staleRestoreStaging := filepath.Join(stagingDir, "grantory-restore-33333")
	staleRestoreDataDir := filepath.Join(dir, "grantory-restore-44444")
	keepDir := filepath.Join(stagingDir, "custom-keep")
	keepDataDir := filepath.Join(dir, "custom-keep-data")
	require.NoError(t, os.MkdirAll(stale1, 0o755))
	require.NoError(t, os.MkdirAll(stale2, 0o755))
	require.NoError(t, os.MkdirAll(staleRestoreStaging, 0o755))
	require.NoError(t, os.MkdirAll(staleRestoreDataDir, 0o755))
	require.NoError(t, os.MkdirAll(keepDir, 0o755))
	require.NoError(t, os.MkdirAll(keepDataDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(stale1, "dummy.db"), []byte("stale"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(staleRestoreStaging, "dummy.db"), []byte("stale"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(staleRestoreDataDir, "dummy.db"), []byte("stale"), 0o644))

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftBootstrapExpect: 1,
		Database:            dir,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	// Verify stale snap-stage and grantory-restore directories were cleaned up on startup
	_, err = os.Stat(stale1)
	assert.True(t, os.IsNotExist(err), "stale staging directory snap-stage-11111 must be removed on startup")
	_, err = os.Stat(stale2)
	assert.True(t, os.IsNotExist(err), "stale staging directory snap-stage-22222 must be removed on startup")
	_, err = os.Stat(staleRestoreStaging)
	assert.True(t, os.IsNotExist(err), "stale restore staging directory grantory-restore-33333 must be removed on startup")
	_, err = os.Stat(staleRestoreDataDir)
	assert.True(t, os.IsNotExist(err), "stale restore data directory grantory-restore-44444 must be removed on startup")

	// Verify non-staging directory was preserved
	_, err = os.Stat(keepDir)
	assert.NoError(t, err, "non snap-stage directory must be preserved")
	_, err = os.Stat(keepDataDir)
	assert.NoError(t, err, "non restore directory in dataDir must be preserved")
}

type inspectRestoreRegistrar struct {
	mockTestRegistrar
	onReset func()
}

func (r *inspectRestoreRegistrar) ResetHTTPAddrs(addrs map[string]string) {
	r.mockTestRegistrar.ResetHTTPAddrs(addrs)
	if r.onReset != nil {
		r.onReset()
	}
}

func TestRestoreSnapshotWithRegistrar_UsesStagingBase(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	storeDef, err := srcNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	_, err = storeDef.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)

	snap, err := NewFSMSnapshotWithHTTPAddrs(ctx, srcNSStore, map[string]string{
		"node-1": "http://10.0.0.1:8080",
	})
	require.NoError(t, err)
	sink := &inmemSnapshotSink{}
	require.NoError(t, snap.Persist(sink))
	snap.Release()

	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)

	stagingBase := filepath.Join(dstDir, RaftDirName, StagingDirName)
	var stagingFoundDuringRestore bool

	inspectReg := &inspectRestoreRegistrar{
		onReset: func() {
			entries, err := os.ReadDir(stagingBase)
			if err == nil {
				for _, entry := range entries {
					if entry.IsDir() && strings.HasPrefix(entry.Name(), "grantory-restore-") {
						stagingFoundDuringRestore = true
						break
					}
				}
			}
			// Verify target directory root does NOT have grantory-restore-*
			rootEntries, err := os.ReadDir(dstDir)
			if err == nil {
				for _, entry := range rootEntries {
					assert.False(t, strings.HasPrefix(entry.Name(), "grantory-restore-"), "staging dir must not be in targetDir root")
				}
			}
		},
	}

	err = RestoreSnapshotWithRegistrar(io.NopCloser(bytes.NewReader(sink.Bytes())), dstNSStore, inspectReg)
	require.NoError(t, err)
	assert.True(t, stagingFoundDuringRestore, "grantory-restore-* staging directory must be located inside stagingBase (<targetDir>/raft/staging)")

	// After restore finishes, staging directory should be removed
	entries, err := os.ReadDir(stagingBase)
	require.NoError(t, err)
	for _, entry := range entries {
		assert.False(t, strings.HasPrefix(entry.Name(), "grantory-restore-"), "staging directory must be cleaned up after restore")
	}
}

func TestRestoreSnapshotWithRegistrar_StaleWALRemovalError(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	srcNSStore, err := nsstore.NewNamespaceStore(ctx, srcDir)
	require.NoError(t, err)

	storeDef, err := srcNSStore.StoreFor(ctx, nsstore.DefaultNamespace)
	require.NoError(t, err)
	_, err = storeDef.CreateHost(ctx, storage.Host{})
	require.NoError(t, err)

	snap, err := NewFSMSnapshotWithHTTPAddrs(ctx, srcNSStore, map[string]string{
		"node-1": "http://10.0.0.1:8080",
	})
	require.NoError(t, err)
	sink := &inmemSnapshotSink{}
	require.NoError(t, snap.Persist(sink))
	snap.Release()

	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)

	// Create a non-empty directory at the WAL file path to ensure os.Remove fails
	walPath := filepath.Join(dstDir, nsstore.DefaultNamespace+".db-wal")
	require.NoError(t, os.MkdirAll(walPath, 0o755))
	nestedFile := filepath.Join(walPath, "stale-lock")
	require.NoError(t, os.WriteFile(nestedFile, []byte("unremovable"), 0o644))

	err = RestoreSnapshotWithRegistrar(io.NopCloser(bytes.NewReader(sink.Bytes())), dstNSStore, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove stale wal/shm file")
	assert.Contains(t, err.Error(), nsstore.DefaultNamespace+".db-wal")

	// Also verify the same for -shm
	require.NoError(t, os.RemoveAll(walPath))
	shmPath := filepath.Join(dstDir, nsstore.DefaultNamespace+".db-shm")
	require.NoError(t, os.MkdirAll(shmPath, 0o755))
	nestedFileShm := filepath.Join(shmPath, "stale-lock")
	require.NoError(t, os.WriteFile(nestedFileShm, []byte("unremovable"), 0o644))

	err = RestoreSnapshotWithRegistrar(io.NopCloser(bytes.NewReader(sink.Bytes())), dstNSStore, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove stale wal/shm file")
	assert.Contains(t, err.Error(), nsstore.DefaultNamespace+".db-shm")

	require.NoError(t, os.RemoveAll(shmPath))
}

func TestRestoreSnapshotCorruptDBDoesNotMutateRegistrar(t *testing.T) {
	ctx := context.Background()

	// 1. Construct a snapshot tar.gz containing cluster_http_addrs.json followed by a corrupt SQLite database
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	// Entry 1: cluster_http_addrs.json
	addrsJSON, err := json.Marshal(map[string]string{
		"node-1": "http://10.0.0.1:8080",
		"node-2": "http://10.0.0.2:8080",
	})
	require.NoError(t, err)

	hdrAddrs := &tar.Header{
		Name:     "cluster_http_addrs.json",
		Mode:     0o644,
		Size:     int64(len(addrsJSON)),
		Typeflag: tar.TypeReg,
	}
	require.NoError(t, tw.WriteHeader(hdrAddrs))
	_, err = tw.Write(addrsJSON)
	require.NoError(t, err)

	// Entry 2: corrupt default.db (invalid SQLite header magic)
	corruptDB := []byte("this is corrupted and has no sqlite header magic")
	hdrDB := &tar.Header{
		Name:     "default.db",
		Mode:     0o644,
		Size:     int64(len(corruptDB)),
		Typeflag: tar.TypeReg,
	}
	require.NoError(t, tw.WriteHeader(hdrDB))
	_, err = tw.Write(corruptDB)
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, gzw.Close())

	// 2. Prepare destination store and registrar with pre-existing addresses
	dstDir := t.TempDir()
	dstNSStore, err := nsstore.NewNamespaceStore(ctx, dstDir)
	require.NoError(t, err)

	initialAddrs := map[string]string{
		"pre-existing-node": "http://existing.local:8080",
	}
	mockReg := &mockTestRegistrar{
		addrs: map[string]string{
			"pre-existing-node": "http://existing.local:8080",
		},
	}

	// 3. Attempt restore
	err = RestoreSnapshotWithRegistrar(io.NopCloser(bytes.NewReader(buf.Bytes())), dstNSStore, mockReg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid header magic")

	// 4. Verify registrar routing table was NOT mutated
	assert.Equal(t, initialAddrs, mockReg.HTTPAddrs(), "registrar routing table must not be mutated when snapshot restore fails on corrupted DB")
}
