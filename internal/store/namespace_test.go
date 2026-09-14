package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

func TestNamespaceStoreNewWithCancelledContextDoesNotFailStoreFor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Immediately cancel the creation context

	dataDir := t.TempDir()
	nsStore, err := NewNamespaceStore(ctx, dataDir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	// StoreFor with a valid, healthy context should succeed and migrate the DB schema without context canceled
	st, err := nsStore.StoreFor(context.Background(), "test-tenant")
	require.NoError(t, err, "StoreFor must succeed and migrate even if NewNamespaceStore received a cancelled context")
	assert.NotNil(t, st)
}

func TestNamespaceStoreNilReceiver(t *testing.T) {
	t.Parallel()

	var nsStore *NamespaceStore
	st, err := nsStore.StoreFor(context.Background(), "test-tenant")
	require.Error(t, err)
	assert.Nil(t, st)
	assert.Contains(t, err.Error(), "namespace store is nil")
}

func TestNamespaceStore_ConcurrentStoreFor_SingleInit(t *testing.T) {
	dataDir := t.TempDir()
	nsStore, err := NewNamespaceStore(context.Background(), dataDir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	const concurrency = 20
	var wg sync.WaitGroup
	startCh := make(chan struct{})

	stores := make([]storage.Store, concurrency)
	errs := make([]error, concurrency)

	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			<-startCh
			s, err := nsStore.StoreFor(context.Background(), "concurrent-tenant")
			stores[idx] = s
			errs[idx] = err
		}(i)
	}

	close(startCh)
	wg.Wait()

	for i := 0; i < concurrency; i++ {
		require.NoError(t, errs[i], "StoreFor should not fail under concurrent access")
		require.NotNil(t, stores[i])
		assert.Same(t, stores[0], stores[i], "all concurrent StoreFor calls must receive the same store instance")
	}
}

func TestNamespaceStore_StoreFor_PreCancelledContextReturnsImmediately(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	nsStore, err := NewNamespaceStore(context.Background(), dataDir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel context before calling StoreFor

	st, err := nsStore.StoreFor(ctx, "cancelled-tenant")
	require.ErrorIs(t, err, context.Canceled, "StoreFor must return context.Canceled immediately with pre-canceled context")
	assert.Nil(t, st)

	// Verify that a subsequent call with a healthy context succeeds
	st, err = nsStore.StoreFor(context.Background(), "cancelled-tenant")
	require.NoError(t, err)
	require.NotNil(t, st)

	host, err := st.CreateHost(context.Background(), storage.Host{})
	require.NoError(t, err)
	assert.NotEmpty(t, host.ID)
}

func TestNamespaceStore_StoreFor_ContextCancellationDuringInitialization(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	nsStore, err := NewNamespaceStore(context.Background(), dataDir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	const namespace = "slow-tenant"
	dbPath := NamespaceDBPath(dataDir, namespace)

	// Open a raw SQLite connection, set WAL mode, and hold an exclusive lock to simulate slow initialization
	rawDB, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	defer func() { _ = rawDB.Close() }()

	_, err = rawDB.Exec("PRAGMA journal_mode = WAL")
	require.NoError(t, err)

	tx, err := rawDB.BeginTx(context.Background(), nil)
	require.NoError(t, err)
	_, err = tx.Exec("CREATE TABLE lock_holder (id int)")
	require.NoError(t, err)

	// Caller 1 has a short timeout (100ms)
	timeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelTimeout()

	start := time.Now()
	st1, err1 := nsStore.StoreFor(timeoutCtx, namespace)
	elapsed := time.Since(start)

	// Caller 1 should exit immediately upon timeout (~100ms), without waiting for the 5s sqlite busy timeout
	require.ErrorIs(t, err1, context.DeadlineExceeded, "StoreFor must return context.DeadlineExceeded when context times out during init")
	assert.Nil(t, st1)
	assert.Less(t, elapsed, 2*time.Second, "caller must return immediately on context timeout without blocking for initialization")

	// Caller 2 has a context that is canceled manually after 50ms while init is still blocked
	cancelCtx, cancelFunc := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancelFunc()
	}()

	startCancel := time.Now()
	st2, err2 := nsStore.StoreFor(cancelCtx, namespace)
	elapsedCancel := time.Since(startCancel)

	require.ErrorIs(t, err2, context.Canceled, "StoreFor must return context.Canceled when context is canceled during init")
	assert.Nil(t, st2)
	assert.Less(t, elapsedCancel, 2*time.Second, "caller must return immediately on context cancel without blocking for initialization")

	// Release the lock so background/future initialization can proceed
	require.NoError(t, tx.Rollback())

	// A healthy caller with background context must now succeed
	var st3 storage.Store
	var err3 error
	require.Eventually(t, func() bool {
		st3, err3 = nsStore.StoreFor(context.Background(), namespace)
		return err3 == nil && st3 != nil
	}, 5*time.Second, 50*time.Millisecond, "StoreFor must eventually succeed once initialization lock is released")

	host, err := st3.CreateHost(context.Background(), storage.Host{})
	require.NoError(t, err)
	assert.NotEmpty(t, host.ID)
}

func TestValidateNamespaceName_ReservedRaft(t *testing.T) {
	t.Parallel()

	reservedCases := []string{"raft", "RAFT", "Raft", "rAfT"}
	for _, ns := range reservedCases {
		err := ValidateNamespaceName(ns)
		require.Error(t, err, "namespace %q should be rejected", ns)
		assert.True(t, errors.Is(err, ErrInvalidNamespace), "must wrap ErrInvalidNamespace")
		assert.Contains(t, err.Error(), "namespace 'raft' is reserved")
	}

	validCases := []string{"default", "rafting", "kraft", "draft", DefaultNamespace, "tenant-1"}
	for _, ns := range validCases {
		err := ValidateNamespaceName(ns)
		require.NoError(t, err, "namespace %q should be valid", ns)
	}
}

func TestValidateNamespaceName_ErrInvalidNamespace(t *testing.T) {
	t.Parallel()

	invalidCases := []struct {
		name      string
		namespace string
		errMsg    string
	}{
		{"empty", "", "namespace is required"},
		{"too short", "abc", "must be at least 4 characters"},
		{"invalid characters", "tenant with spaces", "contains invalid characters"},
		{"invalid symbol", "tenant@org", "contains invalid characters"},
		{"reserved raft", "raft", "namespace 'raft' is reserved"},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNamespaceName(tc.namespace)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidNamespace), "error must wrap ErrInvalidNamespace")
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

func TestNamespaceStore_Close_NilReceiver(t *testing.T) {
	t.Parallel()

	var nsStore *NamespaceStore
	require.NoError(t, nsStore.Close())
}

func TestNamespaceStore_Close_CoordinatesWithRestoreLock(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	nsStore, err := NewNamespaceStore(context.Background(), dataDir)
	require.NoError(t, err)

	// Create an active store
	st, err := nsStore.StoreFor(context.Background(), "active-tenant")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.Len(t, nsStore.ActiveStores(), 1)

	// Hold restore lock
	unlock := nsStore.BeginRestore()

	closeStarted := make(chan struct{})
	closeDone := make(chan error, 1)

	go func() {
		close(closeStarted)
		closeDone <- nsStore.Close()
	}()

	<-closeStarted
	// Ensure Close() is blocked while restoreMu is held
	select {
	case <-closeDone:
		t.Fatal("Close() should be blocked while restoreMu is locked")
	default:
	}

	// Release restore lock
	unlock()

	// Now Close() should complete
	var closeErr error
	require.Eventually(t, func() bool {
		select {
		case closeErr = <-closeDone:
			return true
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, closeErr)

	// Active stores should now be cleared
	assert.Empty(t, nsStore.ActiveStores())
}

func TestNamespaceStore_Close_ConcurrentWithStoreFor(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	nsStore, err := NewNamespaceStore(context.Background(), dataDir)
	require.NoError(t, err)

	const workers = 10
	var wg sync.WaitGroup
	startCh := make(chan struct{})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startCh
			_, _ = nsStore.StoreFor(context.Background(), "concurrent-tenant")
		}(i)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-startCh
		_ = nsStore.Close()
	}()

	close(startCh)
	wg.Wait()
}

func TestNamespaceStore_StoreFor_AfterCloseReturnsError(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	nsStore, err := NewNamespaceStore(context.Background(), dataDir)
	require.NoError(t, err)

	// Open a store for an active tenant
	st, err := nsStore.StoreFor(context.Background(), "tenant-a")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.Len(t, nsStore.ActiveStores(), 1)

	// Close the namespace store permanently
	require.NoError(t, nsStore.Close())

	// Calling StoreFor on previously opened tenant must fail with closed error
	st1, err1 := nsStore.StoreFor(context.Background(), "tenant-a")
	require.Error(t, err1)
	assert.Nil(t, st1)
	assert.Contains(t, err1.Error(), "namespace store is closed")

	// Calling StoreFor on a new tenant must fail with closed error and not create a store
	st2, err2 := nsStore.StoreFor(context.Background(), "tenant-b")
	require.Error(t, err2)
	assert.Nil(t, st2)
	assert.Contains(t, err2.Error(), "namespace store is closed")

	// Active stores must remain empty
	assert.Empty(t, nsStore.ActiveStores())

	// Verify database file for tenant-b was not created
	tenantBPath := NamespaceDBPath(dataDir, "tenant-b")
	_, statErr := os.Stat(tenantBPath)
	assert.True(t, os.IsNotExist(statErr), "tenant-b database file should not have been created after store is closed")
}

func TestNamespaceStore_Reset_NilReceiver(t *testing.T) {
	t.Parallel()

	var nsStore *NamespaceStore
	require.NoError(t, nsStore.Reset())
	require.NoError(t, nsStore.ResetLocked())
}

func TestNamespaceStore_Reset_CoordinatesWithRestoreLock(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	nsStore, err := NewNamespaceStore(context.Background(), dataDir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	st, err := nsStore.StoreFor(context.Background(), "reset-tenant")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.Len(t, nsStore.ActiveStores(), 1)

	// Hold restore lock
	unlock := nsStore.BeginRestore()

	resetStarted := make(chan struct{})
	resetDone := make(chan error, 1)

	go func() {
		close(resetStarted)
		resetDone <- nsStore.Reset()
	}()

	<-resetStarted
	// Ensure Reset() is blocked while restoreMu is held
	select {
	case <-resetDone:
		t.Fatal("Reset() should be blocked while restoreMu is locked")
	default:
	}

	// Release restore lock
	unlock()

	// Now Reset() should complete
	var resetErr error
	require.Eventually(t, func() bool {
		select {
		case resetErr = <-resetDone:
			return true
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, resetErr)

	// Active stores should now be cleared
	assert.Empty(t, nsStore.ActiveStores())
}

func TestNamespaceStore_ResetLocked_WithRestoreLockHeld(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	nsStore, err := NewNamespaceStore(context.Background(), dataDir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	st, err := nsStore.StoreFor(context.Background(), "locked-tenant")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.Len(t, nsStore.ActiveStores(), 1)

	// Holding restore lock and calling ResetLocked must succeed without deadlocking
	unlock := nsStore.BeginRestore()
	defer unlock()

	err = nsStore.ResetLocked()
	require.NoError(t, err)
	assert.Empty(t, nsStore.ActiveStores())
}

func TestNamespaceStore_Reset_ConcurrentWithStoreFor(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	nsStore, err := NewNamespaceStore(context.Background(), dataDir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	const workers = 10
	var wg sync.WaitGroup
	startCh := make(chan struct{})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startCh
			for j := 0; j < 5; j++ {
				st, sErr := nsStore.StoreFor(context.Background(), "concurrent-tenant")
				if sErr == nil && st != nil {
					_ = st
				}
			}
		}(i)
	}

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startCh
			for j := 0; j < 3; j++ {
				_ = nsStore.Reset()
			}
		}()
	}

	close(startCh)
	wg.Wait()
}
