package raft

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	hashiraft "github.com/hashicorp/raft"
	_ "github.com/mattn/go-sqlite3"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
	"github.com/tasansga/terraform-provider-grantory/internal/store"
)

const (
	maxSnapshotDBBytes           int64         = 1 << 30
	maxSnapshotMetadataBytes     int64         = 10 << 20
	defaultSnapshotVACUUMTimeout time.Duration = 5 * time.Minute
	sqliteHeaderMagic                          = "SQLite format 3\x00"
	clusterHTTPAddrsFileName                   = "cluster_http_addrs.json"
)

var _ hashiraft.FSMSnapshot = (*FSMSnapshot)(nil)

// FSMSnapshot implements hashicorp/raft.FSMSnapshot for multi-database SQLite stores.
type FSMSnapshot struct {
	tempDir string
	nsStore *store.NamespaceStore
}

// NewFSMSnapshotWithHTTPAddrs checkpoints all active stores in nsStore, creates an isolated
// point-in-time copy of tenant SQLite databases, and serializes httpAddrs to cluster_http_addrs.json.
func NewFSMSnapshotWithHTTPAddrs(ctx context.Context, nsStore *store.NamespaceStore, httpAddrs map[string]string) (*FSMSnapshot, error) {
	if nsStore == nil {
		return nil, errors.New("namespace store not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	dataDir := nsStore.DataDir()
	if dataDir == "" {
		return nil, errors.New("namespace store has empty data directory")
	}
	if storage.IsPostgresDSN(dataDir) {
		return nil, errors.New("raft snapshot not supported for PostgreSQL backend")
	}

	// 1. Flush SQLite WAL journals across all active stores.
	checkpointCtx, checkpointCancel := context.WithTimeout(ctx, defaultSnapshotVACUUMTimeout)
	defer checkpointCancel()
	if err := CheckpointAllStoresContext(checkpointCtx, nsStore); err != nil {
		return nil, fmt.Errorf("checkpoint stores: %w", err)
	}

	// 2. Create isolated temp directory for point-in-time snapshot.
	stageDir := filepath.Join(dataDir, RaftDirName, StagingDirName)
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return nil, fmt.Errorf("create snapshot staging directory: %w", err)
	}
	tempDir, err := os.MkdirTemp(stageDir, "snap-stage-*")
	if err != nil {
		return nil, fmt.Errorf("create snapshot temp dir: %w", err)
	}

	// 3. Atomically snapshot active databases via VACUUM INTO.
	vacuumCtx, cancel := context.WithTimeout(ctx, defaultSnapshotVACUUMTimeout)
	defer cancel()

	activeStores := nsStore.ActiveStores()
	vacuumed := make(map[string]bool)

	for ns, st := range activeStores {
		if st == nil {
			continue
		}
		db := st.DB()
		if db == nil {
			continue
		}
		baseName := filepath.Base(store.NamespaceDBPath(dataDir, ns))
		dst := filepath.Join(tempDir, baseName)
		if _, err := db.ExecContext(vacuumCtx, "VACUUM INTO ?", dst); err != nil {
			_ = os.RemoveAll(tempDir)
			return nil, fmt.Errorf("snapshot namespace %q: vacuum error: %w", ns, err)
		}
		vacuumed[baseName] = true
	}

	// 4. Discover any remaining inactive .db files in dataDir and snapshot them.
	files, err := discoverDBFiles(dataDir)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("discover db files: %w", err)
	}

	for _, src := range files {
		baseName := filepath.Base(src)
		if vacuumed[baseName] {
			continue
		}
		dst := filepath.Join(tempDir, baseName)
		if err := vacuumIntoFile(vacuumCtx, src, dst); err != nil {
			_ = os.RemoveAll(tempDir)
			return nil, fmt.Errorf("snapshot inactive db file %s: vacuum error: %w", src, err)
		}
		vacuumed[baseName] = true
	}

	// 5. Serialize HTTP address mappings. Always write cluster_http_addrs.json
	// (even if httpAddrs is empty or nil, write {}) so restoring nodes reliably flush stale entries.
	toSerialize := httpAddrs
	if toSerialize == nil {
		toSerialize = make(map[string]string)
	}
	data, err := json.Marshal(toSerialize)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("marshal http addrs: %w", err)
	}
	addrsPath := filepath.Join(tempDir, clusterHTTPAddrsFileName)
	if err := os.WriteFile(addrsPath, data, 0o644); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("write http addrs snapshot: %w", err)
	}

	return &FSMSnapshot{
		tempDir: tempDir,
		nsStore: nsStore,
	}, nil
}

// NewFSMSnapshot checkpoints all active stores in nsStore and creates an isolated point-in-time
// copy of all tenant SQLite databases into a temporary directory for safe persistence.
// It executes VACUUM INTO ? on active database connections to guarantee an atomic, uncorrupted
// snapshot with flushed WAL journals.
func NewFSMSnapshot(ctx context.Context, nsStore *store.NamespaceStore) (*FSMSnapshot, error) {
	return NewFSMSnapshotWithHTTPAddrs(ctx, nsStore, nil)
}

// CheckpointAllStores executes PRAGMA wal_checkpoint(TRUNCATE) on all active stores in nsStore.
func CheckpointAllStores(nsStore *store.NamespaceStore) error {
	return CheckpointAllStoresContext(context.Background(), nsStore)
}

// CheckpointAllStoresContext executes PRAGMA wal_checkpoint(TRUNCATE) with context on all active stores.
func CheckpointAllStoresContext(ctx context.Context, nsStore *store.NamespaceStore) error {
	if nsStore == nil {
		return nil
	}

	for ns, store := range nsStore.ActiveStores() {
		if store == nil {
			continue
		}
		db := store.DB()
		if db == nil {
			continue
		}
		if _, err := db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			return fmt.Errorf("wal checkpoint namespace %q: %w", ns, err)
		}
	}
	return nil
}

// Persist writes the snapshot state to the given raft.SnapshotSink as a .tar.gz archive.
func (s *FSMSnapshot) Persist(sink hashiraft.SnapshotSink) error {
	if s == nil {
		return errors.New("fsm snapshot is nil")
	}
	if sink == nil {
		return errors.New("snapshot sink is nil")
	}

	gw := gzip.NewWriter(sink)
	tw := tar.NewWriter(gw)

	entries, err := os.ReadDir(s.tempDir)
	if err != nil {
		_ = tw.Close()
		_ = gw.Close()
		return fmt.Errorf("read snapshot temp dir: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".db") && entry.Name() != clusterHTTPAddrsFileName) {
			continue
		}

		filePath := filepath.Join(s.tempDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			_ = tw.Close()
			_ = gw.Close()
			return fmt.Errorf("stat db file %s: %w", entry.Name(), err)
		}

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			_ = tw.Close()
			_ = gw.Close()
			return fmt.Errorf("create tar header for %s: %w", entry.Name(), err)
		}
		hdr.Name = entry.Name()

		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gw.Close()
			return fmt.Errorf("write tar header for %s: %w", entry.Name(), err)
		}

		f, err := os.Open(filePath)
		if err != nil {
			_ = tw.Close()
			_ = gw.Close()
			return fmt.Errorf("open file %s: %w", entry.Name(), err)
		}

		if _, err := io.Copy(tw, f); err != nil {
			_ = f.Close()
			_ = tw.Close()
			_ = gw.Close()
			return fmt.Errorf("write file data for %s: %w", entry.Name(), err)
		}
		_ = f.Close()
	}

	if err := tw.Close(); err != nil {
		_ = gw.Close()
		return fmt.Errorf("close tar writer: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}

	return nil
}

// Release removes any temporary files created during the snapshot lifecycle.
func (s *FSMSnapshot) Release() {
	if s == nil {
		return
	}
	if s.tempDir != "" {
		_ = os.RemoveAll(s.tempDir)
		s.tempDir = ""
	}
}

// RestoreSnapshotWithRegistrar restores all namespace SQLite databases from a .tar.gz stream into nsStore,
// and registers any HTTP addresses found in cluster_http_addrs.json with registrar.
func RestoreSnapshotWithRegistrar(rc io.ReadCloser, nsStore *store.NamespaceStore, registrar HTTPAddrRegistrar) error {
	if rc == nil {
		return errors.New("snapshot reader is nil")
	}
	defer func() { _ = rc.Close() }()

	if nsStore == nil {
		return errors.New("namespace store not initialized")
	}

	targetDir := nsStore.DataDir()
	if targetDir == "" {
		return errors.New("namespace store has empty data directory")
	}
	if storage.IsPostgresDSN(targetDir) {
		return errors.New("raft restore not supported for PostgreSQL backend")
	}

	// 1. Acquire restore lock on NamespaceStore to prevent concurrent HTTP requests
	// from accessing or creating databases while restore is in flight, then close active stores.
	unlock := nsStore.BeginRestore()
	defer unlock()

	if err := nsStore.ResetLocked(); err != nil {
		return fmt.Errorf("close active namespace stores: %w", err)
	}

	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return fmt.Errorf("create database directory: %w", err)
	}

	// 2. Unpack entries into an isolated temporary staging directory first.
	stagingBase := filepath.Join(targetDir, RaftDirName, StagingDirName)
	if err := os.MkdirAll(stagingBase, 0o755); err != nil {
		stagingBase = targetDir
	}
	stagingDir, err := os.MkdirTemp(stagingBase, "grantory-restore-*")
	if err != nil {
		return fmt.Errorf("create restore staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stagingDir) }()

	gzr, err := gzip.NewReader(rc)
	if err != nil {
		return fmt.Errorf("open gzip reader: %w", err)
	}
	defer func() { _ = gzr.Close() }()

	restoredDBs := make(map[string]bool)
	var encounteredAddrs bool
	var pendingHTTPAddrs map[string]string

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		if hdr == nil {
			continue
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		cleanName := filepath.Clean(hdr.Name)
		if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) {
			return fmt.Errorf("invalid archive path %q: directory traversal detected", hdr.Name)
		}

		baseName := filepath.Base(cleanName)
		if baseName == clusterHTTPAddrsFileName {
			encounteredAddrs = true
			if hdr.Size > maxSnapshotMetadataBytes {
				return fmt.Errorf("%s exceeds maximum allowed size of %d bytes", clusterHTTPAddrsFileName, maxSnapshotMetadataBytes)
			}
			data, err := io.ReadAll(io.LimitReader(tr, maxSnapshotMetadataBytes+1))
			if err != nil {
				return fmt.Errorf("read %s from snapshot: %w", clusterHTTPAddrsFileName, err)
			}
			if int64(len(data)) > maxSnapshotMetadataBytes {
				return fmt.Errorf("%s exceeds maximum allowed size of %d bytes", clusterHTTPAddrsFileName, maxSnapshotMetadataBytes)
			}
			var addrs map[string]string
			if err := json.Unmarshal(data, &addrs); err != nil {
				return fmt.Errorf("unmarshal %s: %w", clusterHTTPAddrsFileName, err)
			}
			pendingHTTPAddrs = addrs
			continue
		}

		if !strings.HasSuffix(baseName, ".db") {
			continue
		}
		if baseName == RaftDBFileName {
			continue
		}

		if hdr.Size > maxSnapshotDBBytes {
			return fmt.Errorf("snapshot database file %s exceeds maximum allowed size of %d bytes", baseName, maxSnapshotDBBytes)
		}

		stagedPath := filepath.Join(stagingDir, baseName)
		f, err := os.OpenFile(stagedPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return fmt.Errorf("create staging extraction file %s: %w", stagedPath, err)
		}

		written, err := io.Copy(f, io.LimitReader(tr, maxSnapshotDBBytes+1))
		if err != nil {
			_ = f.Close()
			return fmt.Errorf("extract db file %s: %w", baseName, err)
		}
		if written > maxSnapshotDBBytes {
			_ = f.Close()
			return fmt.Errorf("snapshot database file %s exceeds maximum allowed size of %d bytes", baseName, maxSnapshotDBBytes)
		}

		if err := f.Sync(); err != nil {
			_ = f.Close()
			return fmt.Errorf("sync db file %s: %w", baseName, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close db file %s: %w", baseName, err)
		}

		magicBuf := make([]byte, 16)
		sf, err := os.Open(stagedPath)
		if err != nil {
			return fmt.Errorf("open staged db file %s for verification: %w", baseName, err)
		}
		_, err = io.ReadFull(sf, magicBuf)
		_ = sf.Close()
		if err != nil || string(magicBuf) != sqliteHeaderMagic {
			return fmt.Errorf("snapshot database file %s is not a valid SQLite database (invalid header magic)", baseName)
		}

		restoredDBs[baseName] = true
	}

	// 3. Commit verified databases from staging directory to targetDir
	for baseName := range restoredDBs {
		stagedPath := filepath.Join(stagingDir, baseName)
		destPath := filepath.Join(targetDir, baseName)

		// Remove any existing WAL / SHM files for this database
		for _, ext := range []string{"-wal", "-shm"} {
			if err := os.Remove(destPath + ext); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove stale wal/shm file %s: %w", destPath+ext, err)
			}
		}

		if err := os.Rename(stagedPath, destPath); err != nil {
			if copyErr := copyFile(stagedPath, destPath); copyErr != nil {
				return fmt.Errorf("commit db file %s: copy fallback failed: %w (rename failed: %v)", baseName, copyErr, err)
			}
			_ = os.Remove(stagedPath)
		}
	}

	// 4. Purge orphaned / stale databases not present in restored snapshot
	purgeOrphaned := func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			var baseDB string
			switch {
			case strings.HasSuffix(name, ".db"):
				baseDB = name
			case strings.HasSuffix(name, ".db-wal"):
				baseDB = strings.TrimSuffix(name, "-wal")
			case strings.HasSuffix(name, ".db-shm"):
				baseDB = strings.TrimSuffix(name, "-shm")
			default:
				continue
			}

			if baseDB == RaftDBFileName {
				continue
			}
			if !restoredDBs[baseDB] {
				_ = os.Remove(filepath.Join(dir, name))
			}
		}
	}

	purgeOrphaned(targetDir)

	// 5. Apply buffered routing table to registrar now that all database files are committed
	if encounteredAddrs {
		if resetter, ok := registrar.(interface{ ResetHTTPAddrs(map[string]string) }); ok && resetter != nil {
			resetter.ResetHTTPAddrs(pendingHTTPAddrs)
		} else if registrar != nil {
			for k, v := range pendingHTTPAddrs {
				registrar.RegisterHTTPAddr(k, v)
			}
		}
	} else if registrar != nil {
		if resetter, ok := registrar.(interface{ ResetHTTPAddrs(map[string]string) }); ok && resetter != nil {
			resetter.ResetHTTPAddrs(nil)
		}
	}

	return nil
}

// RestoreSnapshot restores all namespace SQLite databases from a .tar.gz stream into nsStore.
func RestoreSnapshot(rc io.ReadCloser, nsStore *store.NamespaceStore) error {
	return RestoreSnapshotWithRegistrar(rc, nsStore, nil)
}

func discoverDBFiles(dataDir string) ([]string, error) {
	seen := make(map[string]bool)
	var files []string

	addFile := func(path string) {
		base := filepath.Base(path)
		if strings.HasSuffix(base, ".db") && base != RaftDBFileName && !seen[base] {
			seen[base] = true
			files = append(files, path)
		}
	}

	// Scan dataDir directly for database files. Active stores are already
	// vacuumed earlier in NewFSMSnapshotWithHTTPAddrs.
	entries, err := os.ReadDir(dataDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			addFile(filepath.Join(dataDir, entry.Name()))
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	sort.Strings(files)
	return files, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func vacuumIntoFile(ctx context.Context, src, dst string) error {
	db, err := sql.Open("sqlite3", src)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
		return err
	}

	_, err = db.ExecContext(ctx, "VACUUM INTO ?", dst)
	return err
}
