package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	logrus.SetOutput(io.Discard)
}

func closeStore(t *testing.T, store Store) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Errorf("close store: %v", err)
	}
}

func rollbackTxTest(t *testing.T, tx *sql.Tx) {
	t.Helper()
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		t.Errorf("rollback transaction: %v", err)
	}
}

func TestNewCreatesConnection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	var enabled int
	if err := store.DB().QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&enabled); err != nil {
		assert.NoError(t, err, "checking foreign_keys pragma")
		t.FailNow()
	}
	assert.Equal(t, 1, enabled, "foreign_keys pragma should be enabled")
}

func TestSQLiteWALJournalModeEnabled(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "wal_test.db")
	store, err := New(ctx, dbPath)
	require.NoError(t, err)
	defer closeStore(t, store)

	var journalMode string
	err = store.DB().QueryRowContext(ctx, "PRAGMA journal_mode;").Scan(&journalMode)
	require.NoError(t, err)
	assert.Equal(t, "wal", journalMode)
}

func TestSQLiteBusyTimeoutConfigured(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "busy_timeout_test.db")
	store, err := New(ctx, dbPath)
	require.NoError(t, err)
	defer closeStore(t, store)

	var busyTimeout int
	err = store.DB().QueryRowContext(ctx, "PRAGMA busy_timeout;").Scan(&busyTimeout)
	require.NoError(t, err)
	assert.Equal(t, 5000, busyTimeout, "busy_timeout pragma should be configured to 5000")
}




func TestMigrateCreatesTables(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	tables := []string{"hosts", "schema_definitions", "requests", "registers", "grants"}
	for _, name := range tables {
		var count int
		if err := store.DB().QueryRowContext(ctx,
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
			name).Scan(&count); err != nil {
			assert.NoError(t, err, "checking table %s", name)
			t.FailNow()
		}
		assert.Equal(t, 1, count, "expected table %s to exist", name)
	}
}

func TestHostCRUD(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host := Host{
		Labels: map[string]string{
			"env": "test",
		},
		UniqueKey: "host:primary",
	}

	created, err := store.CreateHost(ctx, host)
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}

	host = created

	loaded, err := store.GetHost(ctx, host.ID)
	if err != nil {
		assert.NoError(t, err, "GetHost() error")
		t.FailNow()
	}
	assert.Equal(t, host.ID, loaded.ID, "loaded host ID")
	assert.Equal(t, "test", loaded.Labels["env"], "loaded host labels")
	assert.Equal(t, "host:primary", loaded.UniqueKey, "loaded host unique key")
	assert.False(t, loaded.CreatedAt.IsZero(), "created_at should be populated")

	hosts, err := store.ListHosts(ctx)
	if err != nil {
		assert.NoError(t, err, "ListHosts() error")
		t.FailNow()
	}
	assert.Len(t, hosts, 1, "expected one host")

	if err := store.DeleteHost(ctx, host.ID); err != nil {
		assert.NoError(t, err, "DeleteHost() error")
		t.FailNow()
	}

	_, err = store.GetHost(ctx, host.ID)
	assert.ErrorIs(t, err, ErrHostNotFound, "expected host to be deleted")
}

func TestHostUniqueKeyEmptyAllowsDuplicates(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	for i := 0; i < 3; i++ {
		_, err := store.CreateHost(ctx, Host{})
		assert.NoError(t, err, "expected host without unique_key to succeed")
	}
}

func TestHostUniqueKeyConflicts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	_, err = store.CreateHost(ctx, Host{UniqueKey: "unique:shared"})
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}

	_, err = store.CreateHost(ctx, Host{UniqueKey: "unique:shared"})
	assert.ErrorIs(t, err, ErrHostUniqueKeyConflict, "expected unique key conflict")
}

func TestHostUniqueKeyReuseAfterDelete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host, err := store.CreateHost(ctx, Host{UniqueKey: "unique:shared"})
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}

	if err := store.DeleteHost(ctx, host.ID); err != nil {
		assert.NoError(t, err, "DeleteHost() error")
		t.FailNow()
	}

	_, err = store.CreateHost(ctx, Host{UniqueKey: "unique:shared"})
	assert.NoError(t, err, "expected unique key to be reusable after delete")
}

func TestCreateHostGeneratesUniqueIDs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	first, err := store.CreateHost(ctx, Host{})
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}

	second, err := store.CreateHost(ctx, Host{})
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}

	assert.NotEqual(t, first.ID, second.ID, "expected unique IDs")
}

func TestUpdateHostLabels(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host := Host{
		Labels: map[string]string{
			"env": "old",
		},
	}
	created, err := store.CreateHost(ctx, host)
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}
	host = created

	if err := store.UpdateHostLabels(ctx, host.ID, map[string]string{"env": "new"}); err != nil {
		assert.NoError(t, err, "UpdateHostLabels() error")
		t.FailNow()
	}

	updated, err := store.GetHost(ctx, host.ID)
	if err != nil {
		assert.NoError(t, err, "GetHost() error")
		t.FailNow()
	}
	assert.Equal(t, "new", updated.Labels["env"], "labels should update")

	if err := store.UpdateHostLabels(ctx, host.ID, nil); err != nil {
		assert.NoError(t, err, "UpdateHostLabels() error")
		t.FailNow()
	}

	cleared, err := store.GetHost(ctx, host.ID)
	if err != nil {
		assert.NoError(t, err, "GetHost() error")
		t.FailNow()
	}
	assert.Nil(t, cleared.Labels, "labels should be cleared")
}

func TestCreateRequestMissingHost(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	_, err = store.CreateRequest(ctx, Request{
		ID:     "req-no-host",
		HostID: "missing-host",
	})
	assert.ErrorIs(t, err, ErrReferencedHostNotFound, "expected host reference error")
}

func TestCreateRegisterMissingHost(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	_, err = store.CreateRegister(ctx, Register{
		HostID: "missing-host",
	})
	assert.ErrorIs(t, err, ErrReferencedHostNotFound, "expected host reference error")
}

func TestRequestCRUD(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host := Host{}
	createdHost, err := store.CreateHost(ctx, host)
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}
	host = createdHost

	request := Request{
		HostID:    host.ID,
		UniqueKey: "unique:example",
		Payload: map[string]any{
			"name": "example",
		},
		Labels: map[string]string{
			"env": "test",
		},
	}
	createdRequest, err := store.CreateRequest(ctx, request)
	if err != nil {
		assert.NoError(t, err, "CreateRequest() error")
		t.FailNow()
	}

	loaded, err := store.GetRequest(ctx, createdRequest.ID)
	if err != nil {
		assert.NoError(t, err, "GetRequest() error")
		t.FailNow()
	}
	assert.Equal(t, request.HostID, loaded.HostID, "loaded request host ID")
	assert.Equal(t, request.UniqueKey, loaded.UniqueKey, "loaded request unique key")
	assert.Equal(t, "example", loaded.Payload["name"], "loaded request data")
	assert.Equal(t, "test", loaded.Labels["env"], "loaded request labels")
	assert.False(t, loaded.HasGrant, "new requests should not yet have grants")

	grant := Grant{
		RequestID: createdRequest.ID,
		Payload:   map[string]any{"value": "payload"},
	}
	if _, err := store.CreateGrant(ctx, grant); err != nil {
		assert.NoError(t, err, "CreateGrant() error")
		t.FailNow()
	}

	afterGrant, err := store.GetRequest(ctx, createdRequest.ID)
	if err != nil {
		assert.NoError(t, err, "GetRequest() error after grant")
		t.FailNow()
	}
	assert.True(t, afterGrant.HasGrant, "request should reflect existing grant")

	requests, err := store.ListRequests(ctx, nil)
	if err != nil {
		assert.NoError(t, err, "ListRequests() error")
		t.FailNow()
	}
	assert.Len(t, requests, 1, "expected single request")
	assert.True(t, requests[0].HasGrant, "listed request should mark has_grant")

	if err := store.DeleteRequest(ctx, createdRequest.ID); err != nil {
		assert.NoError(t, err, "DeleteRequest() error")
		t.FailNow()
	}
	_, err = store.GetRequest(ctx, createdRequest.ID)
	assert.ErrorIs(t, err, ErrRequestNotFound, "expected request to be deleted")
}

func TestRequestUniqueKeyConflict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host := Host{}
	createdHost, err := store.CreateHost(ctx, host)
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}

	request := Request{
		HostID:    createdHost.ID,
		UniqueKey: "unique:shared",
	}
	createdRequest, err := store.CreateRequest(ctx, request)
	if err != nil {
		assert.NoError(t, err, "CreateRequest() error")
		t.FailNow()
	}

	_, err = store.CreateRequest(ctx, Request{
		HostID:    createdHost.ID,
		UniqueKey: "unique:shared",
	})
	assert.ErrorIs(t, err, ErrRequestUniqueKeyConflict, "expected unique key conflict")

	if err := store.DeleteRequest(ctx, createdRequest.ID); err != nil {
		assert.NoError(t, err, "DeleteRequest() error")
		t.FailNow()
	}

	_, err = store.CreateRequest(ctx, Request{
		HostID:    createdHost.ID,
		UniqueKey: "unique:shared",
	})
	assert.NoError(t, err, "expected unique key to be reusable after deletion")
}

func TestRequestUniqueKeyEmptyAllowsDuplicates(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host := Host{}
	createdHost, err := store.CreateHost(ctx, host)
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}

	for i := 0; i < 3; i++ {
		_, err := store.CreateRequest(ctx, Request{
			HostID: createdHost.ID,
		})
		assert.NoError(t, err, "expected request without unique_key to succeed")
	}
}

func TestRequestUniqueKeyConflictsAcrossHosts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	hostA, err := store.CreateHost(ctx, Host{})
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}
	hostB, err := store.CreateHost(ctx, Host{})
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}

	_, err = store.CreateRequest(ctx, Request{
		HostID:    hostA.ID,
		UniqueKey: "unique:shared",
	})
	if err != nil {
		assert.NoError(t, err, "CreateRequest() error")
		t.FailNow()
	}

	_, err = store.CreateRequest(ctx, Request{
		HostID:    hostB.ID,
		UniqueKey: "unique:shared",
	})
	assert.ErrorIs(t, err, ErrRequestUniqueKeyConflict, "expected unique key conflict across hosts")
}

func TestRequestUniqueKeyReuseAfterDeleteWithGrant(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host, err := store.CreateHost(ctx, Host{})
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}

	request, err := store.CreateRequest(ctx, Request{
		HostID:    host.ID,
		UniqueKey: "unique:shared",
	})
	if err != nil {
		assert.NoError(t, err, "CreateRequest() error")
		t.FailNow()
	}

	_, err = store.CreateGrant(ctx, Grant{
		RequestID: request.ID,
		Payload:   map[string]any{"value": "payload"},
	})
	if err != nil {
		assert.NoError(t, err, "CreateGrant() error")
		t.FailNow()
	}

	if err := store.DeleteRequest(ctx, request.ID); err != nil {
		assert.NoError(t, err, "DeleteRequest() error")
		t.FailNow()
	}

	_, err = store.CreateRequest(ctx, Request{
		HostID:    host.ID,
		UniqueKey: "unique:shared",
	})
	assert.NoError(t, err, "expected unique key to be reusable after delete with grant")
}

func TestRegisterCRUD(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host := Host{}
	createdHost, err := store.CreateHost(ctx, host)
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}
	host = createdHost

	register := Register{
		HostID:    host.ID,
		UniqueKey: "unique:register",
		Payload: map[string]any{
			"ip": "10.0.0.1",
		},
		Labels: map[string]string{
			"role": "db",
		},
	}
	createdReg, err := store.CreateRegister(ctx, register)
	if err != nil {
		assert.NoError(t, err, "CreateRegister() error")
		t.FailNow()
	}

	loaded, err := store.GetRegister(ctx, createdReg.ID)
	if err != nil {
		assert.NoError(t, err, "GetRegister() error")
		t.FailNow()
	}
	assert.Equal(t, register.HostID, loaded.HostID, "loaded register host ID")
	assert.Equal(t, register.UniqueKey, loaded.UniqueKey, "loaded register unique key")
	assert.Equal(t, "10.0.0.1", loaded.Payload["ip"], "loaded register data")

	registers, err := store.ListRegisters(ctx, nil)
	if err != nil {
		assert.NoError(t, err, "ListRegisters() error")
		t.FailNow()
	}
	assert.Len(t, registers, 1, "expected single register")

	if err := store.UpdateRegisterLabels(ctx, createdReg.ID, map[string]string{"role": "cache"}); err != nil {
		assert.NoError(t, err, "UpdateRegisterLabels() error")
		t.FailNow()
	}

	updated, err := store.GetRegister(ctx, createdReg.ID)
	if err != nil {
		assert.NoError(t, err, "GetRegister() error")
		t.FailNow()
	}
	assert.Equal(t, "cache", updated.Labels["role"], "labels should update")

	if err := store.DeleteRegister(ctx, createdReg.ID); err != nil {
		assert.NoError(t, err, "DeleteRegister() error")
		t.FailNow()
	}
	_, err = store.GetRegister(ctx, createdReg.ID)
	assert.ErrorIs(t, err, ErrRegisterNotFound, "expected register to be deleted")
}

func TestRegisterUniqueKeyConflict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host := Host{}
	createdHost, err := store.CreateHost(ctx, host)
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}

	register := Register{
		HostID:    createdHost.ID,
		UniqueKey: "unique:shared",
	}
	createdReg, err := store.CreateRegister(ctx, register)
	if err != nil {
		assert.NoError(t, err, "CreateRegister() error")
		t.FailNow()
	}

	_, err = store.CreateRegister(ctx, Register{
		HostID:    createdHost.ID,
		UniqueKey: "unique:shared",
	})
	assert.ErrorIs(t, err, ErrRegisterUniqueKeyConflict, "expected unique key conflict")

	if err := store.DeleteRegister(ctx, createdReg.ID); err != nil {
		assert.NoError(t, err, "DeleteRegister() error")
		t.FailNow()
	}

	_, err = store.CreateRegister(ctx, Register{
		HostID:    createdHost.ID,
		UniqueKey: "unique:shared",
	})
	assert.NoError(t, err, "expected unique key to be reusable after deletion")
}

func TestRegisterUniqueKeyEmptyAllowsDuplicates(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host := Host{}
	createdHost, err := store.CreateHost(ctx, host)
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}

	for i := 0; i < 3; i++ {
		_, err := store.CreateRegister(ctx, Register{
			HostID: createdHost.ID,
		})
		assert.NoError(t, err, "expected register without unique_key to succeed")
	}
}

func TestRegisterUniqueKeyConflictsAcrossHosts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	hostA, err := store.CreateHost(ctx, Host{})
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}
	hostB, err := store.CreateHost(ctx, Host{})
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}

	_, err = store.CreateRegister(ctx, Register{
		HostID:    hostA.ID,
		UniqueKey: "unique:shared",
	})
	if err != nil {
		assert.NoError(t, err, "CreateRegister() error")
		t.FailNow()
	}

	_, err = store.CreateRegister(ctx, Register{
		HostID:    hostB.ID,
		UniqueKey: "unique:shared",
	})
	assert.ErrorIs(t, err, ErrRegisterUniqueKeyConflict, "expected unique key conflict across hosts")
}

func TestListRequestsWithFilters(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err, "New() error")
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx), "Migrate() error")

	host, err := store.CreateHost(ctx, Host{Labels: map[string]string{"env": "prod"}})
	require.NoError(t, err, "CreateHost() error")

	reqA, err := store.CreateRequest(ctx, Request{
		HostID: host.ID,
		Labels: map[string]string{"env": "prod", "team": "ops"},
	})
	require.NoError(t, err, "CreateRequest() error")

	reqB, err := store.CreateRequest(ctx, Request{
		HostID: host.ID,
		Labels: map[string]string{"env": "prod", "team": "dev"},
	})
	require.NoError(t, err, "CreateRequest() error")

	otherHost, err := store.CreateHost(ctx, Host{Labels: map[string]string{"env": "staging"}})
	require.NoError(t, err, "CreateHost() error")

	otherReq, err := store.CreateRequest(ctx, Request{
		HostID: otherHost.ID,
		Labels: map[string]string{"env": "prod", "team": "ops"},
	})
	require.NoError(t, err, "CreateRequest() error")

	_, err = store.CreateGrant(ctx, Grant{RequestID: reqA.ID})
	require.NoError(t, err, "CreateGrant() error")

	withGrant, err := store.ListRequests(ctx, &RequestListFilters{HasGrant: ptrBool(true)})
	require.NoError(t, err, "ListRequests() error")
	assert.Len(t, withGrant, 1, "has_grant filter should return one request")
	assert.Equal(t, reqA.ID, withGrant[0].ID, "has_grant filter should return granted request")

	withoutGrant, err := store.ListRequests(ctx, &RequestListFilters{HasGrant: ptrBool(false)})
	require.NoError(t, err, "ListRequests() error")
	assert.Len(t, withoutGrant, 2, "has_grant=false filter should return ungranted requests")
	for _, req := range withoutGrant {
		assert.NotEqual(t, reqA.ID, req.ID, "has_grant=false filter should exclude granted request")
	}

	envFilter, err := store.ListRequests(ctx, &RequestListFilters{Labels: map[string]string{"env": "prod"}})
	require.NoError(t, err, "ListRequests() error")
	assert.Len(t, envFilter, 3, "env filter should return all requests with env=prod")

	multiLabel, err := store.ListRequests(ctx, &RequestListFilters{Labels: map[string]string{"env": "prod", "team": "ops"}})
	require.NoError(t, err, "ListRequests() error")
	assert.Len(t, multiLabel, 2, "multi-label filter should return matching requests")
	for _, req := range multiLabel {
		assert.NotEqual(t, reqB.ID, req.ID, "multi-label filter should exclude mismatched team")
	}

	mismatch, err := store.ListRequests(ctx, &RequestListFilters{Labels: map[string]string{"env": "prod", "team": "missing"}})
	require.NoError(t, err, "ListRequests() error")
	assert.Len(t, mismatch, 0, "multi-label filter should exclude non-matching requests")

	hostFilter, err := store.ListRequests(ctx, &RequestListFilters{HostLabels: map[string]string{"env": "prod"}})
	require.NoError(t, err, "ListRequests() error")
	assert.Len(t, hostFilter, 2, "host label filter should return requests from matching hosts")
	for _, req := range hostFilter {
		assert.NotEqual(t, otherReq.ID, req.ID, "host label filter should exclude non-matching hosts")
	}

	unfiltered, err := store.ListRequests(ctx, &RequestListFilters{})
	require.NoError(t, err, "ListRequests() error")
	assert.Len(t, unfiltered, 3, "empty filters should return all requests")
}

func TestListRegistersWithFilters(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err, "New() error")
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx), "Migrate() error")

	host, err := store.CreateHost(ctx, Host{Labels: map[string]string{"env": "prod"}})
	require.NoError(t, err, "CreateHost() error")

	regA, err := store.CreateRegister(ctx, Register{
		HostID: host.ID,
		Labels: map[string]string{"env": "prod", "role": "db"},
	})
	require.NoError(t, err, "CreateRegister() error")

	regB, err := store.CreateRegister(ctx, Register{
		HostID: host.ID,
		Labels: map[string]string{"env": "prod", "role": "cache"},
	})
	require.NoError(t, err, "CreateRegister() error")

	otherHost, err := store.CreateHost(ctx, Host{Labels: map[string]string{"env": "staging"}})
	require.NoError(t, err, "CreateHost() error")

	otherReg, err := store.CreateRegister(ctx, Register{
		HostID: otherHost.ID,
		Labels: map[string]string{"env": "prod", "role": "db"},
	})
	require.NoError(t, err, "CreateRegister() error")

	envFilter, err := store.ListRegisters(ctx, &RegisterListFilters{Labels: map[string]string{"env": "prod"}})
	require.NoError(t, err, "ListRegisters() error")
	assert.Len(t, envFilter, 3, "env filter should return all registers with env=prod")

	multiLabel, err := store.ListRegisters(ctx, &RegisterListFilters{Labels: map[string]string{"env": "prod", "role": "db"}})
	require.NoError(t, err, "ListRegisters() error")
	assert.Len(t, multiLabel, 2, "multi-label filter should return matching registers")
	for _, reg := range multiLabel {
		assert.NotEqual(t, regB.ID, reg.ID, "multi-label filter should exclude mismatched role")
	}

	mismatch, err := store.ListRegisters(ctx, &RegisterListFilters{Labels: map[string]string{"env": "prod", "role": "missing"}})
	require.NoError(t, err, "ListRegisters() error")
	assert.Len(t, mismatch, 0, "multi-label filter should exclude non-matching registers")
	assert.NotEqual(t, regB.ID, regA.ID, "sanity check register ids differ")

	hostFilter, err := store.ListRegisters(ctx, &RegisterListFilters{HostLabels: map[string]string{"env": "prod"}})
	require.NoError(t, err, "ListRegisters() error")
	assert.Len(t, hostFilter, 2, "host label filter should return registers from matching hosts")
	for _, reg := range hostFilter {
		assert.NotEqual(t, otherReg.ID, reg.ID, "host label filter should exclude non-matching hosts")
	}

	unfiltered, err := store.ListRegisters(ctx, &RegisterListFilters{})
	require.NoError(t, err, "ListRegisters() error")
	assert.Len(t, unfiltered, 3, "empty filters should return all registers")
}

func TestUpdateRequestLabelsRefreshesTimestamp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err, "New() error")
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx), "Migrate() error")

	host := Host{}
	createdHost, err := store.CreateHost(ctx, host)
	require.NoError(t, err, "CreateHost() error")
	host = createdHost

	request := Request{
		HostID: host.ID,
		Labels: map[string]string{"env": "before"},
	}
	createdRequest, err := store.CreateRequest(ctx, request)
	require.NoError(t, err, "CreateRequest() error")

	originalUpdated := createdRequest.UpdatedAt
	time.Sleep(5 * time.Millisecond)

	require.NoError(t, store.UpdateRequestLabels(ctx, createdRequest.ID, map[string]string{"env": "after"}))

	updated, err := store.GetRequest(ctx, createdRequest.ID)
	require.NoError(t, err, "GetRequest() error")
	assert.True(t, updated.UpdatedAt.After(originalUpdated), "updated_at should advance when labels change")
}

func TestUpdateRegisterLabelsRefreshesTimestamp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err, "New() error")
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx), "Migrate() error")

	host := Host{}
	createdHost, err := store.CreateHost(ctx, host)
	require.NoError(t, err, "CreateHost() error")
	host = createdHost

	register := Register{
		HostID: host.ID,
		Labels: map[string]string{"role": "before"},
	}
	createdReg, err := store.CreateRegister(ctx, register)
	require.NoError(t, err, "CreateRegister() error")

	originalUpdated := createdReg.UpdatedAt
	time.Sleep(5 * time.Millisecond)

	require.NoError(t, store.UpdateRegisterLabels(ctx, createdReg.ID, map[string]string{"role": "after"}))

	updated, err := store.GetRegister(ctx, createdReg.ID)
	require.NoError(t, err, "GetRegister() error")
	assert.True(t, updated.UpdatedAt.After(originalUpdated), "updated_at should advance when labels change")
}

func TestUpdateRequestPayloadRefreshesTimestamp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err, "New() error")
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx), "Migrate() error")

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err, "CreateHost() error")

	createdRequest, err := store.CreateRequest(ctx, Request{
		HostID:  host.ID,
		Mutable: true,
		Payload: map[string]any{"v": "1"},
	})
	require.NoError(t, err, "CreateRequest() error")

	originalUpdated := createdRequest.UpdatedAt
	time.Sleep(5 * time.Millisecond)

	newPayload := map[string]any{"v": "2"}
	require.NoError(t, store.UpdateRequest(ctx, createdRequest.ID, &newPayload, nil))

	updated, err := store.GetRequest(ctx, createdRequest.ID)
	require.NoError(t, err, "GetRequest() error")
	assert.True(t, updated.UpdatedAt.After(originalUpdated), "updated_at should advance when payload changes")
	assert.Equal(t, 2, updated.Version, "version should increment")

	// Test with deterministic time
	detTime := time.Date(2028, 5, 12, 10, 30, 0, 123000000, time.UTC)
	ctxDet := WithDeterministicTime(ctx, detTime)
	newPayload3 := map[string]any{"v": "3"}
	require.NoError(t, store.UpdateRequest(ctxDet, createdRequest.ID, &newPayload3, nil))

	updatedDet, err := store.GetRequest(ctx, createdRequest.ID)
	require.NoError(t, err, "GetRequest() error")
	assert.Equal(t, detTime.Truncate(time.Millisecond), updatedDet.UpdatedAt.Truncate(time.Millisecond))
	assert.Equal(t, 3, updatedDet.Version, "version should increment")
}

func TestUpdateRegisterPayloadRefreshesTimestamp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err, "New() error")
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx), "Migrate() error")

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err, "CreateHost() error")

	createdReg, err := store.CreateRegister(ctx, Register{
		HostID:  host.ID,
		Mutable: true,
		Payload: map[string]any{"key": "val1"},
	})
	require.NoError(t, err, "CreateRegister() error")

	originalUpdated := createdReg.UpdatedAt
	time.Sleep(5 * time.Millisecond)

	newPayload := map[string]any{"key": "val2"}
	require.NoError(t, store.UpdateRegister(ctx, createdReg.ID, &newPayload, nil))

	updated, err := store.GetRegister(ctx, createdReg.ID)
	require.NoError(t, err, "GetRegister() error")
	assert.True(t, updated.UpdatedAt.After(originalUpdated), "updated_at should advance when payload changes")

	// Test with deterministic time
	detTime := time.Date(2028, 6, 15, 14, 20, 0, 456000000, time.UTC)
	ctxDet := WithDeterministicTime(ctx, detTime)
	newPayload3 := map[string]any{"key": "val3"}
	require.NoError(t, store.UpdateRegister(ctxDet, createdReg.ID, &newPayload3, nil))

	updatedDet, err := store.GetRegister(ctx, createdReg.ID)
	require.NoError(t, err, "GetRegister() error")
	assert.Equal(t, detTime.Truncate(time.Millisecond), updatedDet.UpdatedAt.Truncate(time.Millisecond))
}

func ptrBool(v bool) *bool {
	return &v
}

func TestCountRegisters(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host := Host{}
	createdHost, err := store.CreateHost(ctx, host)
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}
	host = createdHost

	if _, err := store.CreateRegister(ctx, Register{HostID: host.ID}); err != nil {
		assert.NoError(t, err, "CreateRegister() error")
		t.FailNow()
	}
	if _, err := store.CreateRegister(ctx, Register{HostID: host.ID}); err != nil {
		assert.NoError(t, err, "CreateRegister() error")
		t.FailNow()
	}

	counts, err := store.CountRegisters(ctx)
	if err != nil {
		assert.NoError(t, err, "CountRegisters() error")
		t.FailNow()
	}
	assert.EqualValues(t, 2, counts["total"], "register count")
}

func TestGrantCRUD(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host := Host{}
	createdHost, err := store.CreateHost(ctx, host)
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}
	host = createdHost

	request := Request{
		HostID: host.ID,
	}
	createdRequest, err := store.CreateRequest(ctx, request)
	if err != nil {
		assert.NoError(t, err, "CreateRequest() error")
		t.FailNow()
	}

	grant := Grant{
		RequestID: createdRequest.ID,
		Payload:   map[string]any{"value": "secret"},
	}
	createdGrant, err := store.CreateGrant(ctx, grant)
	if err != nil {
		assert.NoError(t, err, "CreateGrant() error")
		t.FailNow()
	}

	list, err := store.ListGrants(ctx)
	if err != nil {
		assert.NoError(t, err, "ListGrants() error")
		t.FailNow()
	}
	assert.Len(t, list, 1, "expected one grant")

	fetched, err := store.GetGrant(ctx, createdGrant.ID)
	if err != nil {
		assert.NoError(t, err, "GetGrant() error")
		t.FailNow()
	}
	assert.Equal(t, grant.RequestID, fetched.RequestID, "grant request ID should match")

	if err := store.DeleteGrant(ctx, createdGrant.ID); err != nil {
		assert.NoError(t, err, "DeleteGrant() error")
		t.FailNow()
	}
	_, err = store.GetGrant(ctx, createdGrant.ID)
	assert.ErrorIs(t, err, ErrGrantNotFound, "expected grant to be deleted")
}

func TestGrantUpdateAllowsPayloadCorrectionAtSameRequestVersion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)

	req, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	require.NoError(t, err)
	require.EqualValues(t, 1, req.Version)

	grant, err := store.CreateGrant(ctx, Grant{
		RequestID:      req.ID,
		RequestVersion: req.Version,
		Payload:        map[string]any{"value": "old"},
	})
	require.NoError(t, err)

	err = store.UpdateGrant(ctx, grant.ID, map[string]any{"value": "new"}, req.Version)
	require.NoError(t, err)

	updated, err := store.GetGrant(ctx, grant.ID)
	require.NoError(t, err)
	assert.EqualValues(t, req.Version, updated.RequestVersion)
	assert.Equal(t, "new", updated.Payload["value"])
}

func TestUpdateGrantPayloadRefreshesTimestamp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err, "New() error")
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx), "Migrate() error")

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err, "CreateHost() error")

	req, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	require.NoError(t, err, "CreateRequest() error")

	grant, err := store.CreateGrant(ctx, Grant{
		RequestID:      req.ID,
		RequestVersion: req.Version,
		Payload:        map[string]any{"val": "one"},
	})
	require.NoError(t, err, "CreateGrant() error")

	originalUpdated := grant.UpdatedAt
	time.Sleep(5 * time.Millisecond)

	// Test normal update advances updated_at
	require.NoError(t, store.UpdateGrant(ctx, grant.ID, map[string]any{"val": "two"}, req.Version))
	updated, err := store.GetGrant(ctx, grant.ID)
	require.NoError(t, err, "GetGrant() error")
	assert.True(t, updated.UpdatedAt.After(originalUpdated), "updated_at should advance when payload changes")

	// Test with deterministic time (requestVersion > 0)
	detTime := time.Date(2028, 7, 20, 11, 45, 0, 123000000, time.UTC)
	ctxDet := WithDeterministicTime(ctx, detTime)
	require.NoError(t, store.UpdateGrant(ctxDet, grant.ID, map[string]any{"val": "three"}, req.Version))

	updatedDet, err := store.GetGrant(ctx, grant.ID)
	require.NoError(t, err, "GetGrant() error")
	assert.Equal(t, detTime.Truncate(time.Millisecond), updatedDet.UpdatedAt.Truncate(time.Millisecond))

	// Test with deterministic time (requestVersion == 0)
	detTime2 := time.Date(2029, 8, 25, 12, 15, 0, 789000000, time.UTC)
	ctxDet2 := WithDeterministicTime(ctx, detTime2)
	require.NoError(t, store.UpdateGrant(ctxDet2, grant.ID, map[string]any{"val": "four"}, 0))

	updatedDet2, err := store.GetGrant(ctx, grant.ID)
	require.NoError(t, err, "GetGrant() error")
	assert.Equal(t, detTime2.Truncate(time.Millisecond), updatedDet2.UpdatedAt.Truncate(time.Millisecond))

	// Test idempotent no-op update also respects deterministic time
	detTime3 := time.Date(2030, 9, 30, 15, 0, 0, 321000000, time.UTC)
	ctxDet3 := WithDeterministicTime(ctx, detTime3)
	require.NoError(t, store.UpdateGrant(ctxDet3, grant.ID, map[string]any{"val": "four"}, 0))

	updatedDet3, err := store.GetGrant(ctx, grant.ID)
	require.NoError(t, err, "GetGrant() error")
	assert.Equal(t, detTime3.Truncate(time.Millisecond), updatedDet3.UpdatedAt.Truncate(time.Millisecond))
}

func TestGrantVersionConflictOnCreateAndUpdate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)

	req, err := store.CreateRequest(ctx, Request{HostID: host.ID, Mutable: true, Payload: map[string]any{"v": "one"}})
	require.NoError(t, err)
	require.EqualValues(t, 1, req.Version)

	_, err = store.CreateGrant(ctx, Grant{
		RequestID:      req.ID,
		RequestVersion: req.Version + 1,
		Payload:        map[string]any{"value": "stale"},
	})
	require.ErrorIs(t, err, ErrGrantRequestVersionConflict)

	grant, err := store.CreateGrant(ctx, Grant{
		RequestID:      req.ID,
		RequestVersion: req.Version,
		Payload:        map[string]any{"value": "ok"},
	})
	require.NoError(t, err)

	payloadV2 := map[string]any{"v": "two"}
	require.NoError(t, store.UpdateRequest(ctx, req.ID, &payloadV2, nil))

	err = store.UpdateGrant(ctx, grant.ID, map[string]any{"value": "stale-update"}, req.Version)
	require.ErrorIs(t, err, ErrGrantRequestVersionConflict)
}

func TestGrantUpdateNoOpSamePayloadAndVersionSucceeds(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)

	req, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	require.NoError(t, err)

	grant, err := store.CreateGrant(ctx, Grant{
		RequestID:      req.ID,
		RequestVersion: req.Version,
		Payload:        map[string]any{"value": "same"},
	})
	require.NoError(t, err)

	err = store.UpdateGrant(ctx, grant.ID, map[string]any{"value": "same"}, req.Version)
	require.NoError(t, err)
}

func TestGrantUpdateIdempotentAuditOldPayloadMatchesTransactionPayload(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)

	req, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	require.NoError(t, err)

	initialPayload := map[string]any{"key": "initial_value", "nested": float64(42)}
	grant, err := store.CreateGrant(ctx, Grant{
		RequestID:      req.ID,
		RequestVersion: req.Version,
		Payload:        initialPayload,
	})
	require.NoError(t, err)

	// Perform idempotent update with identical payload
	err = store.UpdateGrant(ctx, grant.ID, initialPayload, req.Version)
	require.NoError(t, err)

	// Verify the latest audit event for this grant records old_payload matching initialPayload
	var (
		eventType  string
		oldPayload sql.NullString
		newPayload sql.NullString
	)
	err = store.DB().QueryRowContext(ctx, `
		SELECT event_type, old_payload, new_payload
		FROM resource_events
		WHERE resource_type = 'grant' AND resource_id = ?
		ORDER BY rowid DESC
		LIMIT 1
	`, grant.ID).Scan(&eventType, &oldPayload, &newPayload)
	require.NoError(t, err)
	assert.Equal(t, "updated", eventType)
	require.True(t, oldPayload.Valid)
	require.True(t, newPayload.Valid)

	var decodedOld map[string]any
	require.NoError(t, json.Unmarshal([]byte(oldPayload.String), &decodedOld))
	assert.Equal(t, initialPayload, decodedOld)

	var decodedNew map[string]any
	require.NoError(t, json.Unmarshal([]byte(newPayload.String), &decodedNew))
	assert.Equal(t, initialPayload, decodedNew)
}

func TestCountRequestsByGrantPresence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host := Host{}
	createdHost, err := store.CreateHost(ctx, host)
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}
	host = createdHost

	if _, err := store.CreateRequest(ctx, Request{HostID: host.ID}); err != nil {
		assert.NoError(t, err, "CreateRequest() error")
		t.FailNow()
	}
	reqWithGrant, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	if err != nil {
		assert.NoError(t, err, "CreateRequest() error")
		t.FailNow()
	}
	if _, err := store.CreateGrant(ctx, Grant{RequestID: reqWithGrant.ID, Payload: map[string]any{"value": "secret"}}); err != nil {
		assert.NoError(t, err, "CreateGrant() error")
		t.FailNow()
	}

	counts, err := store.CountRequestsByGrantPresence(ctx)
	if err != nil {
		assert.NoError(t, err, "CountRequestsByGrantPresence() error")
		t.FailNow()
	}
	assert.EqualValues(t, 1, counts["without_grant"], "request without grant count")
	assert.EqualValues(t, 1, counts["with_grant"], "request with grant count")
}

func TestCountGrants(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}
	host := Host{}
	createdHost, err := store.CreateHost(ctx, host)
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}
	host = createdHost
	req1, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	if err != nil {
		assert.NoError(t, err, "CreateRequest() error")
		t.FailNow()
	}
	req2, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	if err != nil {
		assert.NoError(t, err, "CreateRequest() error")
		t.FailNow()
	}

	if _, err := store.CreateGrant(ctx, Grant{RequestID: req1.ID, Payload: map[string]any{"value": "secret"}}); err != nil {
		assert.NoError(t, err, "CreateGrant() error")
		t.FailNow()
	}
	if _, err := store.CreateGrant(ctx, Grant{RequestID: req2.ID, Payload: map[string]any{"value": "secret"}}); err != nil {
		assert.NoError(t, err, "CreateGrant() error")
		t.FailNow()
	}

	counts, err := store.CountGrants(ctx)
	if err != nil {
		assert.NoError(t, err, "CountGrants() error")
		t.FailNow()
	}
	assert.EqualValues(t, 2, counts["total"], "total grant count")
}

func TestSetNamespaceNormalization(t *testing.T) {
	t.Parallel()

	store := &sqliteStore{}
	store.SetNamespace("  custom  ")
	assert.Equal(t, "custom", store.namespaceForLog(), "namespace should be trimmed")
	store.SetNamespace("  ")
	assert.Equal(t, unknownNamespace, store.namespaceForLog(), "empty namespace should default to unknown")
}

func TestConcurrentSetNamespaceAndLogDBOperation(t *testing.T) {
	t.Parallel()

	store := &sqliteStore{}
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	const goroutines = 8

	// Writers calling SetNamespace concurrently
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					store.SetNamespace(fmt.Sprintf("ns-%d", id))
				}
			}
		}(i)
	}

	// Readers calling logDBOperation and namespaceForLog concurrently
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					store.logDBOperation("hosts", "create", nil)
					_ = store.namespaceForLog()
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestPostgresStore_ConcurrentNamespaceAccess(t *testing.T) {
	t.Parallel()

	store := &postgresStore{}
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	const goroutines = 8

	// Writers calling SetNamespace concurrently
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					store.SetNamespace(fmt.Sprintf("ns-%d", id))
				}
			}
		}(i)
	}

	// Readers calling table, logDBOperation, and namespaceForLog concurrently
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					_ = store.table("hosts")
					_ = store.namespaceForLog()
					store.logDBOperation("hosts", "create", nil)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestPostgresSetNamespaceNormalization(t *testing.T) {
	t.Parallel()

	var nilStore *postgresStore
	nilStore.SetNamespace("test")
	assert.Equal(t, unknownNamespace, nilStore.namespaceForLog())
	assert.Equal(t, `"hosts"`, nilStore.table("hosts"))

	store := &postgresStore{}
	store.SetNamespace("  custom  ")
	assert.Equal(t, "custom", store.namespaceForLog())
	assert.Equal(t, `"custom"."hosts"`, store.table("hosts"))
	store.SetNamespace("  ")
	assert.Equal(t, unknownNamespace, store.namespaceForLog())
	assert.Equal(t, `"hosts"`, store.table("hosts"))
}

func TestConcurrentSetNamespaceAndDBOperations(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, s)
	require.NoError(t, s.Migrate(ctx))

	sqStore, ok := s.(*sqliteStore)
	require.True(t, ok)

	var wg sync.WaitGroup
	const goroutines = 4

	// Concurrent SetNamespace writers
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					sqStore.SetNamespace(fmt.Sprintf("tenant-%d", id))
				}
			}
		}(i)
	}

	// Concurrent DB operations that call logDBOperation
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					sqStore.logDBOperation("hosts", "query", nil)
					_, _ = s.ListHosts(ctx)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestMigrateRequiresStore(t *testing.T) {
	t.Parallel()

	var store *sqliteStore
	err := store.Migrate(context.Background())
	assert.Error(t, err, "migrate should fail when store uninitialized")
}

func TestCreateHostLabelKeyTooLong(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	key := strings.Repeat("k", maxLabelLength+1)
	_, err = store.CreateHost(ctx, Host{Labels: map[string]string{key: "value"}})
	assert.Error(t, err, "labels exceeding max length should error")
}

func TestCreateRequestRequiresHostID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	_, err = store.CreateRequest(ctx, Request{})
	assert.Error(t, err, "request must include host_id")
}

func TestCreateRequestLabelKeyTooLong(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)

	key := strings.Repeat("k", maxLabelLength+1)
	_, err = store.CreateRequest(ctx, Request{HostID: host.ID, Labels: map[string]string{key: "value"}})
	assert.Error(t, err, "request labels with oversized key should error")
}

func TestCreateRegisterRequiresHostID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	_, err = store.CreateRegister(ctx, Register{})
	assert.Error(t, err, "register must include host_id")
}

func TestCreateRegisterLabelKeyTooLong(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)

	key := strings.Repeat("k", maxLabelLength+1)
	_, err = store.CreateRegister(ctx, Register{HostID: host.ID, Labels: map[string]string{key: "value"}})
	assert.Error(t, err, "register labels with oversized key should error")
}

func TestCreateHostFailsWhenStoreNil(t *testing.T) {
	t.Parallel()

	var store *sqliteStore
	_, err := store.CreateHost(context.Background(), Host{})
	assert.Error(t, err, "create host should fail on nil store")
}

func TestCreateRequestFailsWhenStoreNil(t *testing.T) {
	t.Parallel()

	var store *sqliteStore
	_, err := store.CreateRequest(context.Background(), Request{HostID: "any"})
	assert.Error(t, err, "create request should fail on nil store")
}

func TestCreateRegisterFailsWhenStoreNil(t *testing.T) {
	t.Parallel()

	var store *sqliteStore
	_, err := store.CreateRegister(context.Background(), Register{HostID: "any"})
	assert.Error(t, err, "create register should fail on nil store")
}

func TestCreateGrantFailsWhenStoreNil(t *testing.T) {
	t.Parallel()

	var store *sqliteStore
	_, err := store.CreateGrant(context.Background(), Grant{RequestID: "any", Payload: map[string]any{"value": "p"}})
	assert.Error(t, err, "create grant should fail on nil store")
}

func TestCreateRequestPayloadEncodeError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)

	// functions cannot be JSON marshaled
	_, err = store.CreateRequest(ctx, Request{
		HostID: host.ID,
		Payload: map[string]any{
			"fn": func() {},
		},
	})
	assert.Error(t, err, "invalid payload should fail to encode")
	assert.Contains(t, err.Error(), "encode request payload")
}

func TestCreateRegisterPayloadEncodeError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)

	_, err = store.CreateRegister(ctx, Register{
		HostID: host.ID,
		Payload: map[string]any{
			"fn": func() {},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encode register payload")
}

func TestCreateGrantMissingBits(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	_, err = store.CreateGrant(ctx, Grant{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request_id is required")

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)
	req, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	require.NoError(t, err)

	grant, err := store.CreateGrant(ctx, Grant{RequestID: req.ID})
	require.NoError(t, err)
	assert.Equal(t, req.ID, grant.RequestID, "grant should belong to the provided request")
	assert.Nil(t, grant.Payload, "payload should be nil when not provided")
}

func TestOperationsAfterCloseAlwaysError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)
	req, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	require.NoError(t, err)
	reg, err := store.CreateRegister(ctx, Register{HostID: host.ID})
	require.NoError(t, err)
	grant, err := store.CreateGrant(ctx, Grant{RequestID: req.ID, Payload: map[string]any{"value": "p"}})
	require.NoError(t, err)

	require.NoError(t, store.Close())

	_, err = store.CreateHost(ctx, Host{})
	assert.Error(t, err)
	_, err = store.CreateRequest(ctx, Request{HostID: host.ID})
	assert.Error(t, err)
	_, err = store.CreateRegister(ctx, Register{HostID: host.ID})
	assert.Error(t, err)
	_, err = store.CreateGrant(ctx, Grant{RequestID: req.ID, Payload: map[string]any{"value": "p"}})
	assert.Error(t, err)

	_, err = store.ListHosts(ctx)
	assert.Error(t, err)
	_, err = store.ListRequests(ctx, nil)
	assert.Error(t, err)
	_, err = store.ListRegisters(ctx, nil)
	assert.Error(t, err)
	_, err = store.ListGrants(ctx)
	assert.Error(t, err)

	_, err = store.CountRequestsByGrantPresence(ctx)
	assert.Error(t, err)
	_, err = store.CountRegisters(ctx)
	assert.Error(t, err)
	_, err = store.CountGrants(ctx)
	assert.Error(t, err)

	err = store.UpdateHostLabels(ctx, host.ID, map[string]string{"env": "x"})
	assert.Error(t, err)
	err = store.UpdateRequestLabels(ctx, req.ID, map[string]string{"env": "x"})
	assert.Error(t, err)
	err = store.UpdateRegisterLabels(ctx, reg.ID, map[string]string{"env": "x"})
	assert.Error(t, err)
	err = store.DeleteHost(ctx, host.ID)
	assert.Error(t, err)
	err = store.DeleteRequest(ctx, req.ID)
	assert.Error(t, err)
	err = store.DeleteRegister(ctx, reg.ID)
	assert.Error(t, err)
	err = store.DeleteGrant(ctx, grant.ID)
	assert.Error(t, err)

	_, err = store.GetHost(ctx, host.ID)
	assert.Error(t, err)
	_, err = store.GetRequest(ctx, req.ID)
	assert.Error(t, err)
	_, err = store.GetRegister(ctx, reg.ID)
	assert.Error(t, err)
	_, err = store.GetGrant(ctx, grant.ID)
	assert.Error(t, err)
}

func TestEnsureTablesReturnErrorWhenContextCanceled(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	sqliteStore, ok := store.(*sqliteStore)
	require.True(t, ok, "expected sqlite store implementation")

	tests := []struct {
		name string
		fn   func(context.Context, *sql.Tx) error
	}{
		{"hosts", sqliteStore.ensureHostsTable},
		{"schema_definitions", sqliteStore.ensureSchemaDefinitionsTable},
		{"requests", sqliteStore.ensureRequestsTable},
		{"registers", sqliteStore.ensureRegistersTable},
		{"grants", sqliteStore.ensureGrantsTable},
		{"host_labels", sqliteStore.ensureHostLabelsTable},
		{"request_labels", sqliteStore.ensureRequestLabelsTable},
		{"register_labels", sqliteStore.ensureRegisterLabelsTable},
		{"grant_labels", sqliteStore.ensureGrantLabelsTable},
		{"schema_definition_labels", sqliteStore.ensureSchemaDefinitionLabelsTable},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tx, err := store.DB().BeginTx(ctx, nil)
			require.NoError(t, err)
			defer rollbackTxTest(t, tx)
			cancelCtx, cancel := context.WithCancel(ctx)
			cancel()
			assert.Error(t, tc.fn(cancelCtx, tx), "expected failure for %s", tc.name)
		})
	}
}

func TestSQLiteMigrateSchemaDefinitionsAndRequests(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)

	sqliteStore, ok := store.(*sqliteStore)
	require.True(t, ok, "expected sqlite store implementation")

	_, err = sqliteStore.DB().ExecContext(ctx, `
CREATE TABLE schema_definitions (
	id TEXT PRIMARY KEY,
	request_schema TEXT,
	grant_schema TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE hosts (
	id TEXT PRIMARY KEY,
	unique_key TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE requests (
	id TEXT PRIMARY KEY,
	host_id TEXT NOT NULL,
	schema_definition_id TEXT,
	unique_key TEXT,
	data TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
	FOREIGN KEY(schema_definition_id) REFERENCES schema_definitions(id) ON DELETE SET NULL
);
`)
	require.NoError(t, err)

	defID := "schema-legacy"
	hostID := "host-legacy"
	reqID := "request-legacy"
	requestSchema := `{"type":"object"}`
	grantSchema := `{"type":"object","required":["detail"]}`

	_, err = sqliteStore.DB().ExecContext(ctx, `INSERT INTO schema_definitions (id, request_schema, grant_schema) VALUES (?, ?, ?)`, defID, requestSchema, grantSchema)
	require.NoError(t, err)
	_, err = sqliteStore.DB().ExecContext(ctx, `INSERT INTO hosts (id) VALUES (?)`, hostID)
	require.NoError(t, err)
	_, err = sqliteStore.DB().ExecContext(ctx, `INSERT INTO requests (id, host_id, schema_definition_id) VALUES (?, ?, ?)`, reqID, hostID, defID)
	require.NoError(t, err)

	require.NoError(t, sqliteStore.Migrate(ctx))

	var schemaValue string
	err = sqliteStore.DB().QueryRowContext(ctx, `SELECT schema FROM schema_definitions WHERE id = ?`, defID).Scan(&schemaValue)
	require.NoError(t, err)
	assert.JSONEq(t, requestSchema, schemaValue, "schema should backfill from request_schema")

	var requestSchemaID, grantSchemaID sql.NullString
	err = sqliteStore.DB().QueryRowContext(ctx, `SELECT request_schema_definition_id, grant_schema_definition_id FROM requests WHERE id = ?`, reqID).Scan(&requestSchemaID, &grantSchemaID)
	require.NoError(t, err)
	require.True(t, requestSchemaID.Valid)
	require.True(t, grantSchemaID.Valid)
	assert.Equal(t, defID, requestSchemaID.String)
	assert.NotEqual(t, defID, grantSchemaID.String)

	var grantDefID string
	err = sqliteStore.DB().QueryRowContext(ctx, `SELECT id FROM schema_definitions WHERE id != ? AND schema = ?`, defID, grantSchema).Scan(&grantDefID)
	require.NoError(t, err)
	assert.Equal(t, grantDefID, grantSchemaID.String)
}

func TestNamespaceForLogHandlesNilAndTrim(t *testing.T) {
	t.Parallel()

	var store *sqliteStore
	assert.Equal(t, unknownNamespace, store.namespaceForLog(), "nil store should return unknown namespace")

	store = &sqliteStore{}
	store.SetNamespace("  custom  ")
	assert.Equal(t, "custom", store.namespaceForLog(), "should trim namespace")
}

func TestSQLiteDeleteSchemaDefinitionNullsRequestReference(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	sqliteStore, ok := store.(*sqliteStore)
	require.True(t, ok, "expected sqlite store implementation")

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)

	def, err := store.CreateSchemaDefinition(ctx, SchemaDefinition{
		Schema: json.RawMessage(`{"type":"object"}`),
	})
	require.NoError(t, err)

	req, err := store.CreateRequest(ctx, Request{
		HostID:                    host.ID,
		RequestSchemaDefinitionID: def.ID,
		Payload:                   map[string]any{"name": "db"},
	})
	require.NoError(t, err)

	var before sql.NullString
	err = store.DB().QueryRowContext(ctx, `SELECT request_schema_definition_id FROM requests WHERE id = ?`, req.ID).Scan(&before)
	require.NoError(t, err)
	require.True(t, before.Valid)
	require.Equal(t, def.ID, before.String)

	require.NoError(t, sqliteStore.DeleteSchemaDefinition(ctx, def.ID))

	var after sql.NullString
	err = store.DB().QueryRowContext(ctx, `SELECT request_schema_definition_id FROM requests WHERE id = ?`, req.ID).Scan(&after)
	require.NoError(t, err)
	require.False(t, after.Valid, "request_schema_definition_id should be NULL after delete")
}

func TestSQLiteSchemaDefinitionUniqueKeyConflictAndLabels(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	created, err := store.CreateSchemaDefinition(ctx, SchemaDefinition{
		UniqueKey: "invoice.v1",
		Schema:    json.RawMessage(`{"type":"object"}`),
		Labels:    map[string]string{"family": "invoice", "version": "1"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)

	loaded, err := store.GetSchemaDefinition(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "invoice.v1", loaded.UniqueKey)
	assert.Equal(t, map[string]string{"family": "invoice", "version": "1"}, loaded.Labels)

	_, err = store.CreateSchemaDefinition(ctx, SchemaDefinition{
		UniqueKey: "invoice.v1",
		Schema:    json.RawMessage(`{"type":"object"}`),
	})
	assert.ErrorIs(t, err, ErrSchemaDefinitionUniqueKeyConflict, "expected unique key conflict")

	require.NoError(t, store.UpdateSchemaDefinitionLabels(ctx, created.ID, map[string]string{"family": "invoice", "version": "2"}))
	updated, err := store.GetSchemaDefinition(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"family": "invoice", "version": "2"}, updated.Labels)
}

func TestNewFailsWhenForeignKeyEnableContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New(ctx, ":memory:")
	assert.Error(t, err, "enabling foreign keys should respect context cancellation")
}

func TestCloseAndDBHandleNilStore(t *testing.T) {
	t.Parallel()

	var store *sqliteStore
	assert.NoError(t, store.Close(), "closing nil store should be a no-op")
	assert.Nil(t, store.DB(), "nil store should expose no DB")
}

func TestDecodeAnyMapReturnsErrorForBadJSON(t *testing.T) {
	t.Parallel()

	_, err := decodeAnyMap(sql.NullString{String: "{bad", Valid: true})
	assert.Error(t, err, "decoding invalid JSON should error")
}

func TestReplaceLabelsBehavesWhenContextCanceled(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	tx, err := store.DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer rollbackTxTest(t, tx)

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	err = replaceLabels(cancelCtx, tx, hostLabelsTable, "host_id", "id", map[string]string{"env": "err"})
	assert.Error(t, err, "replaceLabels should honor context cancellation")
}

func TestEnsureRequestExists(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	assert.NoError(t, err)
	defer closeStore(t, store)
	assert.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	assert.NoError(t, err)

	req, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	assert.NoError(t, err)

	sqliteStore, ok := store.(*sqliteStore)
	require.True(t, ok, "expected sqlite store implementation")

	assert.NoError(t, sqliteStore.ensureRequestExists(ctx, req.ID))
	assert.ErrorIs(t, sqliteStore.ensureRequestExists(ctx, "missing"), ErrReferencedRequestNotFound)
}

func TestUpdateRequestLabelsAppliesChanges(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	assert.NoError(t, err)
	defer closeStore(t, store)
	assert.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	assert.NoError(t, err)

	req, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	assert.NoError(t, err)

	assert.NoError(t, store.UpdateRequestLabels(ctx, req.ID, map[string]string{"env": "prod"}))
	updated, err := store.GetRequest(ctx, req.ID)
	assert.NoError(t, err)
	assert.Equal(t, "prod", updated.Labels["env"])

	assert.NoError(t, store.UpdateRequestLabels(ctx, req.ID, nil))
	afterClear, err := store.GetRequest(ctx, req.ID)
	assert.NoError(t, err)
	assert.Nil(t, afterClear.Labels)
}

func TestGetGrantForRequest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	assert.NoError(t, err)
	defer closeStore(t, store)
	assert.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	assert.NoError(t, err)

	req, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	assert.NoError(t, err)

	grant, found, err := store.GetGrantForRequest(ctx, req.ID)
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, Grant{}, grant)

	payload := map[string]any{"value": "secret"}
	createdGrant, err := store.CreateGrant(ctx, Grant{RequestID: req.ID, Payload: payload})
	assert.NoError(t, err)

	latest, found, err := store.GetGrantForRequest(ctx, req.ID)
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, createdGrant.ID, latest.ID)
}

func TestStorageOperationsErrorWhenDBClosed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err, "New() should succeed")
	require.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)

	req, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	require.NoError(t, err)

	reg, err := store.CreateRegister(ctx, Register{HostID: host.ID})
	require.NoError(t, err)

	grant, err := store.CreateGrant(ctx, Grant{RequestID: req.ID, Payload: map[string]any{"value": "payload"}})
	require.NoError(t, err)

	require.NoError(t, store.Close())

	_, err = store.CreateHost(ctx, Host{})
	assert.Error(t, err)
	_, err = store.CreateRequest(ctx, Request{HostID: host.ID})
	assert.Error(t, err)
	_, err = store.CreateRegister(ctx, Register{HostID: host.ID})
	assert.Error(t, err)
	_, err = store.CreateGrant(ctx, Grant{RequestID: req.ID, Payload: map[string]any{"value": "payload"}})
	assert.Error(t, err)

	_, err = store.ListHosts(ctx)
	assert.Error(t, err)
	_, err = store.ListRequests(ctx, nil)
	assert.Error(t, err)
	_, err = store.ListRegisters(ctx, nil)
	assert.Error(t, err)
	_, err = store.ListGrants(ctx)
	assert.Error(t, err)

	_, err = store.CountRequestsByGrantPresence(ctx)
	assert.Error(t, err)
	_, err = store.CountRegisters(ctx)
	assert.Error(t, err)
	_, err = store.CountGrants(ctx)
	assert.Error(t, err)

	assert.Error(t, store.UpdateHostLabels(ctx, host.ID, map[string]string{"env": "x"}))
	assert.Error(t, store.UpdateRequestLabels(ctx, req.ID, map[string]string{"env": "x"}))
	assert.Error(t, store.UpdateRegisterLabels(ctx, reg.ID, map[string]string{"env": "x"}))
	assert.Error(t, store.UpdateSchemaDefinitionLabels(ctx, "missing", map[string]string{"env": "x"}))

	assert.Error(t, store.DeleteHost(ctx, host.ID))
	assert.Error(t, store.DeleteRequest(ctx, req.ID))
	assert.Error(t, store.DeleteRegister(ctx, reg.ID))
	assert.Error(t, store.DeleteGrant(ctx, grant.ID))

	_, err = store.GetHost(ctx, host.ID)
	assert.Error(t, err)
	_, err = store.GetRequest(ctx, req.ID)
	assert.Error(t, err)
	_, err = store.GetRegister(ctx, reg.ID)
	assert.Error(t, err)
	_, err = store.GetGrant(ctx, grant.ID)
	assert.Error(t, err)
}

func TestCreateGrantIsUniquePerRequest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	if err != nil {
		assert.NoError(t, err, "New() error")
		t.FailNow()
	}
	defer closeStore(t, store)

	if err := store.Migrate(ctx); err != nil {
		assert.NoError(t, err, "Migrate() error")
		t.FailNow()
	}

	host := Host{}
	createdHost, err := store.CreateHost(ctx, host)
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}
	host = createdHost
	req, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	if err != nil {
		assert.NoError(t, err, "CreateRequest() error")
		t.FailNow()
	}

	first := Grant{RequestID: req.ID, Payload: map[string]any{"value": "secret"}}
	if _, err := store.CreateGrant(ctx, first); err != nil {
		assert.NoError(t, err, "CreateGrant() error")
		t.FailNow()
	}
	second := Grant{RequestID: req.ID, Payload: map[string]any{"value": "secret"}}
	_, err = store.CreateGrant(ctx, second)
	assert.ErrorIs(t, err, ErrGrantAlreadyExists, "expected duplicate request grant to fail")
}

func TestParseCreatedAtFractionalSeconds(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		input    string
		expected time.Time
	}{
		{
			input:    "2026-09-07 10:15:20.123456",
			expected: time.Date(2026, 9, 7, 10, 15, 20, 123456000, time.UTC),
		},
		{
			input:    "2026-09-07 10:15:20.123",
			expected: time.Date(2026, 9, 7, 10, 15, 20, 123000000, time.UTC),
		},
		{
			input:    "2026-09-07 10:15:20",
			expected: time.Date(2026, 9, 7, 10, 15, 20, 0, time.UTC),
		},
		{
			input:    "2026-09-07T10:15:20.123456Z",
			expected: time.Date(2026, 9, 7, 10, 15, 20, 123456000, time.UTC),
		},
	}

	for _, tc := range testCases {
		parsed, err := parseCreatedAt(tc.input)
		require.NoError(t, err, "failed to parse timestamp %q", tc.input)
		assert.Equal(t, tc.expected.UnixNano(), parsed.UnixNano(), "timestamp mismatch for %q", tc.input)
	}
}

func TestParseCreatedAt_WhitespaceTrimming(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected time.Time
	}{
		{
			name:     "whitespace only returns zero time without error",
			input:    "   \t\r\n  ",
			expected: time.Time{},
		},
		{
			name:     "createdAtLayout with leading and trailing spaces",
			input:    "   2026-09-07 10:15:20.123   ",
			expected: time.Date(2026, 9, 7, 10, 15, 20, 123000000, time.UTC),
		},
		{
			name:     "standard datetime with tabs and newline",
			input:    "\t2026-09-07 10:15:20\n",
			expected: time.Date(2026, 9, 7, 10, 15, 20, 0, time.UTC),
		},
		{
			name:     "fractional microsecond layout with whitespace",
			input:    " \t 2026-09-07 10:15:20.123456 \r\n ",
			expected: time.Date(2026, 9, 7, 10, 15, 20, 123456000, time.UTC),
		},
		{
			name:     "RFC3339Nano with leading and trailing spaces",
			input:    "  2026-09-07T10:15:20.123456Z  ",
			expected: time.Date(2026, 9, 7, 10, 15, 20, 123456000, time.UTC),
		},
		{
			name:     "RFC3339 with leading and trailing spaces",
			input:    "  2026-09-07T10:15:20Z  ",
			expected: time.Date(2026, 9, 7, 10, 15, 20, 0, time.UTC),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parsed, err := parseCreatedAt(tc.input)
			require.NoError(t, err, "failed to parse timestamp %q", tc.input)
			assert.Equal(t, tc.expected.UnixNano(), parsed.UnixNano(), "timestamp mismatch for %q", tc.input)

			// Also verify via parseDBTime as string
			parsedDBStr, err := parseDBTime(tc.input)
			require.NoError(t, err, "parseDBTime failed for string %q", tc.input)
			assert.Equal(t, tc.expected.UnixNano(), parsedDBStr.UnixNano())

			// Also verify via parseDBTime as []byte
			parsedDBBytes, err := parseDBTime([]byte(tc.input))
			require.NoError(t, err, "parseDBTime failed for []byte %q", tc.input)
			assert.Equal(t, tc.expected.UnixNano(), parsedDBBytes.UnixNano())
		})
	}
}

func TestFormatDBTimeAndRoundTrip(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "2006-01-02 15:04:05.000", DBTimeLayout)

	// 1. Millisecond precision formatting
	ts := time.Date(2026, 9, 7, 12, 34, 56, 789000000, time.UTC)
	formatted := FormatDBTime(ts)
	assert.Equal(t, "2026-09-07 12:34:56.789", formatted)
	assert.Equal(t, formatted, FormatDBTime(ts))

	// 2. Trailing zero milliseconds preserved
	tsZeroMs := time.Date(2026, 9, 7, 12, 34, 56, 0, time.UTC)
	formattedZero := FormatDBTime(tsZeroMs)
	assert.Equal(t, "2026-09-07 12:34:56.000", formattedZero)
	assert.Equal(t, formattedZero, FormatDBTime(tsZeroMs))

	// 3. Non-UTC time converted to UTC
	loc := time.FixedZone("UTC+2", 2*60*60)
	tsNonUTC := time.Date(2026, 9, 7, 14, 34, 56, 789000000, loc)
	assert.Equal(t, "2026-09-07 12:34:56.789", FormatDBTime(tsNonUTC))

	// 4. Round-trip through parseCreatedAt
	parsed, err := parseCreatedAt(formatted)
	require.NoError(t, err)
	assert.Equal(t, ts.UnixNano(), parsed.UnixNano())

	parsedZero, err := parseCreatedAt(formattedZero)
	require.NoError(t, err)
	assert.Equal(t, tsZeroMs.UnixNano(), parsedZero.UnixNano())
}

func TestNullableDBTime(t *testing.T) {
	t.Parallel()

	// 1. Zero time returns nil
	var zeroTime time.Time
	assert.Nil(t, nullableDBTime(zeroTime))
	assert.Nil(t, nullableDBTime(time.Time{}))

	// 2. Non-zero time returns formatted string
	ts := time.Date(2026, 9, 7, 12, 34, 56, 789000000, time.UTC)
	val := nullableDBTime(ts)
	require.NotNil(t, val)
	assert.Equal(t, "2026-09-07 12:34:56.789", val)
	assert.Equal(t, FormatDBTime(ts), val)

	// 3. Non-UTC time converted to UTC string
	loc := time.FixedZone("UTC+2", 2*60*60)
	tsNonUTC := time.Date(2026, 9, 7, 14, 34, 56, 789000000, loc)
	valNonUTC := nullableDBTime(tsNonUTC)
	require.NotNil(t, valNonUTC)
	assert.Equal(t, "2026-09-07 12:34:56.789", valNonUTC)
}


func TestRecordSignatureNonceCleanupSameDay(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx))

	h, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)
	hostID := h.ID

	now := time.Now().UTC()
	// Record signature with an expiration timestamp 1 hour in the past
	expiredNonce := "nonce-expired"
	expiredAt := now.Add(-1 * time.Hour)
	err = store.RecordSignature(ctx, hostID, now.Add(-2*time.Hour).Unix(), expiredNonce, expiredAt)
	require.NoError(t, err)

	// Record another signature with timestamp % 10 == 0 to trigger cleanup
	activeNonce := "nonce-active"
	activeExpiresAt := now.Add(1 * time.Hour)
	triggerTimestamp := (now.Unix()/10 + 1) * 10
	err = store.RecordSignature(ctx, hostID, triggerTimestamp, activeNonce, activeExpiresAt)
	require.NoError(t, err)

	// Query nonces table to verify the expired nonce was deleted (assert row count = 1, not 2)
	var count int
	err = store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM nonces").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "expired nonce should have been deleted during cleanup")

	var remainingNonce, rawExpiresAt string
	err = store.DB().QueryRowContext(ctx, "SELECT nonce, CAST(expires_at AS TEXT) FROM nonces").Scan(&remainingNonce, &rawExpiresAt)
	require.NoError(t, err)
	assert.Equal(t, activeNonce, remainingNonce)
	assert.Equal(t, FormatDBTime(activeExpiresAt), rawExpiresAt, "expires_at should be formatted using FormatDBTime")
}

func TestInsertResourceEventSQLite_RapidSuccessionIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx))

	tx, err := store.DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer rollbackTxTest(t, tx)

	fixedTS := time.Date(2026, 9, 7, 12, 0, 0, 123456789, time.UTC)
	payload := map[string]any{"key": "value"}
	labels := map[string]string{"env": "test"}

	// First insert
	err = insertResourceEventSQLite(ctx, tx, ResourceEventParams{
		ResourceType:  "request",
		ResourceID:    "req-1",
		EventType:     "created",
		NewPayloadMap: payload,
		NewLabelsMap:  labels,
		Timestamp:     fixedTS,
	})
	require.NoError(t, err)

	// Rapid succession call with identical parameters and timestamp
	err = insertResourceEventSQLite(ctx, tx, ResourceEventParams{
		ResourceType:  "request",
		ResourceID:    "req-1",
		EventType:     "created",
		NewPayloadMap: payload,
		NewLabelsMap:  labels,
		Timestamp:     fixedTS,
	})
	require.NoError(t, err, "rapid succession insert with identical deterministic timestamp must be idempotent")

	// Commit transaction
	require.NoError(t, tx.Commit())

	// Verify only 1 event was recorded
	var count int
	err = store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_events WHERE resource_id = 'req-1'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "duplicate event must be ignored")
}

func TestInsertResourceEventSQLite_ParamsWithoutTimestamp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx))

	tx, err := store.DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer rollbackTxTest(t, tx)

	err = insertResourceEventSQLite(ctx, tx, ResourceEventParams{
		ResourceType:  "grant",
		ResourceID:    "grant-1",
		EventType:     "created",
		NewPayloadMap: map[string]any{"role": "admin"},
	})
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	var count int
	err = store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_events WHERE resource_id = 'grant-1'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestInsertResourceEventSQLite_HashCollisionPrevention(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx))

	tx, err := store.DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer rollbackTxTest(t, tx)

	fixedTime := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	err = insertResourceEventSQLite(ctx, tx, ResourceEventParams{
		ResourceType: "request",
		ResourceID:   "req-event-test",
		EventType:    "labels_updated",
		NewLabelsMap: map[string]string{"env": "staging"},
		Timestamp:    fixedTime,
	})
	require.NoError(t, err)

	err = insertResourceEventSQLite(ctx, tx, ResourceEventParams{
		ResourceType: "request",
		ResourceID:   "req-event-test",
		EventType:    "labels_updated",
		NewLabelsMap: map[string]string{"env": "prod"},
		Timestamp:    fixedTime,
	})
	require.NoError(t, err, "different labels must yield distinct hash IDs without collision")

	require.NoError(t, tx.Commit())
}

func TestInsertLabelsPostgresDeterministicSorting(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)

	// Create a dummy table with positional parameter compatibility ($1, $2, $3 works in SQLite)
	_, err = store.DB().ExecContext(ctx, `CREATE TABLE test_labels (id TEXT, key TEXT, value TEXT, seq INTEGER PRIMARY KEY AUTOINCREMENT)`)
	require.NoError(t, err)

	// Test empty labels returns nil
	tx, err := store.DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, insertLabelsPostgres(ctx, tx, "test_labels", "id", "empty-id", nil))
	rollbackTxTest(t, tx)

	// Test sorted insertion
	tx, err = store.DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer rollbackTxTest(t, tx)

	labels := map[string]string{
		"zebra":  "val-z",
		"apple":  "val-a",
		"mango":  "val-m",
		"banana": "val-b",
		"cherry": "val-c",
	}

	err = insertLabelsPostgres(ctx, tx, "test_labels", "id", "test-id-1", labels)
	require.NoError(t, err)

	require.NoError(t, tx.Commit())

	rows, err := store.DB().QueryContext(ctx, `SELECT key FROM test_labels WHERE id = ? ORDER BY seq ASC`, "test-id-1")
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var insertedKeys []string
	for rows.Next() {
		var key string
		require.NoError(t, rows.Scan(&key))
		insertedKeys = append(insertedKeys, key)
	}
	require.NoError(t, rows.Err())

	expectedKeys := []string{"apple", "banana", "cherry", "mango", "zebra"}
	assert.Equal(t, expectedKeys, insertedKeys, "postgres label rows must be inserted in strictly sorted alphabetical order")

	// Test label key exceeds maxLabelLength
	tx, err = store.DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer rollbackTxTest(t, tx)
	tooLongKey := strings.Repeat("x", maxLabelLength+1)
	err = insertLabelsPostgres(ctx, tx, "test_labels", "id", "test-id-2", map[string]string{tooLongKey: "val"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds 256 characters")

	// Test label value exceeds maxLabelLength
	tooLongVal := strings.Repeat("y", maxLabelLength+1)
	err = insertLabelsPostgres(ctx, tx, "test_labels", "id", "test-id-3", map[string]string{"short": tooLongVal})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds 256 characters")
}

func TestStandaloneCallerProvidedIDsPreserved(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)
	require.NoError(t, store.Migrate(ctx))

	// Verify deterministic time is absent from context (verifying standalone mode)
	_, hasDeterministicTime := DeterministicTimeFromContext(ctx)
	require.False(t, hasDeterministicTime, "standalone test must not have deterministic context time")

	// 1. Host with caller-supplied ID
	customHostID := "custom-host-uuid-1234"
	host, err := store.CreateHost(ctx, Host{
		ID:        customHostID,
		UniqueKey: "host-standalone-1",
		Labels:    map[string]string{"env": "test"},
	})
	require.NoError(t, err)
	assert.Equal(t, customHostID, host.ID, "caller-provided host ID must be preserved in standalone mode")

	fetchedHost, err := store.GetHost(ctx, customHostID)
	require.NoError(t, err)
	assert.Equal(t, customHostID, fetchedHost.ID)

	// Duplicate host ID should fail
	_, err = store.CreateHost(ctx, Host{
		ID:        customHostID,
		UniqueKey: "host-standalone-1-dup",
	})
	require.ErrorIs(t, err, ErrHostAlreadyExists)

	// 2. SchemaDefinition with caller-supplied ID
	customSchemaDefID := "custom-schemadef-uuid-1234"
	schemaDef, err := store.CreateSchemaDefinition(ctx, SchemaDefinition{
		ID:        customSchemaDefID,
		UniqueKey: "schema-standalone-1",
		Schema:    json.RawMessage(`{"type":"object"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, customSchemaDefID, schemaDef.ID, "caller-provided schema definition ID must be preserved in standalone mode")

	fetchedDef, err := store.GetSchemaDefinition(ctx, customSchemaDefID)
	require.NoError(t, err)
	assert.Equal(t, customSchemaDefID, fetchedDef.ID)

	// Duplicate schema definition ID should fail
	_, err = store.CreateSchemaDefinition(ctx, SchemaDefinition{
		ID:        customSchemaDefID,
		UniqueKey: "schema-standalone-1-dup",
		Schema:    json.RawMessage(`{}`),
	})
	require.ErrorIs(t, err, ErrSchemaDefinitionAlreadyExists)

	// 3. Request with caller-supplied ID
	customRequestID := "custom-request-uuid-1234"
	req, err := store.CreateRequest(ctx, Request{
		ID:                        customRequestID,
		HostID:                    host.ID,
		RequestSchemaDefinitionID: schemaDef.ID,
		UniqueKey:                 "req-standalone-1",
		Payload:                   map[string]any{"key": "value"},
	})
	require.NoError(t, err)
	assert.Equal(t, customRequestID, req.ID, "caller-provided request ID must be preserved in standalone mode")

	fetchedReq, err := store.GetRequest(ctx, customRequestID)
	require.NoError(t, err)
	assert.Equal(t, customRequestID, fetchedReq.ID)

	// Duplicate request ID should fail
	_, err = store.CreateRequest(ctx, Request{
		ID:        customRequestID,
		HostID:    host.ID,
		UniqueKey: "req-standalone-1-dup",
	})
	require.ErrorIs(t, err, ErrRequestAlreadyExists)

	// 4. Register with caller-supplied ID
	customRegisterID := "custom-register-uuid-1234"
	reg, err := store.CreateRegister(ctx, Register{
		ID:                 customRegisterID,
		HostID:             host.ID,
		SchemaDefinitionID: schemaDef.ID,
		UniqueKey:          "reg-standalone-1",
		Payload:            map[string]any{"status": "ok"},
	})
	require.NoError(t, err)
	assert.Equal(t, customRegisterID, reg.ID, "caller-provided register ID must be preserved in standalone mode")

	fetchedReg, err := store.GetRegister(ctx, customRegisterID)
	require.NoError(t, err)
	assert.Equal(t, customRegisterID, fetchedReg.ID)

	// Duplicate register ID should fail
	_, err = store.CreateRegister(ctx, Register{
		ID:        customRegisterID,
		HostID:    host.ID,
		UniqueKey: "reg-standalone-1-dup",
	})
	require.ErrorIs(t, err, ErrRegisterAlreadyExists)

	// 5. Grant with caller-supplied ID
	customGrantID := "custom-grant-uuid-1234"
	grant, err := store.CreateGrant(ctx, Grant{
		ID:             customGrantID,
		RequestID:      req.ID,
		RequestVersion: req.Version,
		Payload:        map[string]any{"token": "xyz"},
	})
	require.NoError(t, err)
	assert.Equal(t, customGrantID, grant.ID, "caller-provided grant ID must be preserved in standalone mode")

	fetchedGrant, err := store.GetGrant(ctx, customGrantID)
	require.NoError(t, err)
	assert.Equal(t, customGrantID, fetchedGrant.ID)

	// Duplicate grant ID should fail
	_, err = store.CreateGrant(ctx, Grant{
		ID:             customGrantID,
		RequestID:      req.ID,
		RequestVersion: req.Version,
	})
	require.ErrorIs(t, err, ErrGrantAlreadyExists)

	// Verify that empty IDs generate new non-empty IDs
	hostAuto, err := store.CreateHost(ctx, Host{UniqueKey: "host-auto-id"})
	require.NoError(t, err)
	assert.NotEmpty(t, hostAuto.ID, "empty host ID must generate a new ID")
	assert.NotEqual(t, customHostID, hostAuto.ID)

	defAuto, err := store.CreateSchemaDefinition(ctx, SchemaDefinition{
		UniqueKey: "schema-auto-id",
		Schema:    json.RawMessage(`{}`),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, defAuto.ID, "empty schema definition ID must generate a new ID")
	assert.NotEqual(t, customSchemaDefID, defAuto.ID)

	reqAuto, err := store.CreateRequest(ctx, Request{HostID: hostAuto.ID, UniqueKey: "req-auto-id"})
	require.NoError(t, err)
	assert.NotEmpty(t, reqAuto.ID, "empty request ID must generate a new ID")
	assert.NotEqual(t, customRequestID, reqAuto.ID)

	regAuto, err := store.CreateRegister(ctx, Register{HostID: hostAuto.ID, UniqueKey: "reg-auto-id"})
	require.NoError(t, err)
	assert.NotEmpty(t, regAuto.ID, "empty register ID must generate a new ID")
	assert.NotEqual(t, customRegisterID, regAuto.ID)

	grantAuto, err := store.CreateGrant(ctx, Grant{RequestID: reqAuto.ID, RequestVersion: reqAuto.Version})
	require.NoError(t, err)
	assert.NotEmpty(t, grantAuto.ID, "empty grant ID must generate a new ID")
	assert.NotEqual(t, customGrantID, grantAuto.ID)
}

func TestStorageUniqueConstraintErrorHelpers(t *testing.T) {
	t.Parallel()

	// 1. IsUniqueConstraintError
	assert.False(t, IsUniqueConstraintError(nil))
	assert.False(t, IsUniqueConstraintError(errors.New("generic error")))
	assert.True(t, IsUniqueConstraintError(errors.New("UNIQUE constraint failed: table.col")))
	assert.True(t, IsUniqueConstraintError(&pgconn.PgError{Code: "23505"}))
	assert.False(t, IsUniqueConstraintError(&pgconn.PgError{Code: "42P01"}))

	// 2. isUniqueKeyConstraintError
	assert.False(t, isUniqueKeyConstraintError(nil))
	assert.False(t, isUniqueKeyConstraintError(errors.New("generic error")))
	assert.True(t, isUniqueKeyConstraintError(errors.New("UNIQUE constraint failed: requests.unique_key")))
	assert.True(t, isUniqueKeyConstraintError(&pgconn.PgError{ConstraintName: "requests_unique_key_idx"}))
	assert.False(t, isUniqueKeyConstraintError(&pgconn.PgError{ConstraintName: "other_idx"}))

	// 3. isUniqueRegisterKeyConstraintError
	assert.False(t, isUniqueRegisterKeyConstraintError(nil))
	assert.False(t, isUniqueRegisterKeyConstraintError(errors.New("generic error")))
	assert.True(t, isUniqueRegisterKeyConstraintError(errors.New("UNIQUE constraint failed: registers.unique_key")))
	assert.True(t, isUniqueRegisterKeyConstraintError(&pgconn.PgError{ConstraintName: "registers_unique_key_idx"}))
	assert.False(t, isUniqueRegisterKeyConstraintError(&pgconn.PgError{ConstraintName: "other_idx"}))

	// 4. isUniqueHostKeyConstraintError
	assert.False(t, isUniqueHostKeyConstraintError(nil))
	assert.False(t, isUniqueHostKeyConstraintError(errors.New("generic error")))
	assert.True(t, isUniqueHostKeyConstraintError(errors.New("UNIQUE constraint failed: hosts.unique_key")))
	assert.True(t, isUniqueHostKeyConstraintError(&pgconn.PgError{ConstraintName: "hosts_unique_key_idx"}))
	assert.False(t, isUniqueHostKeyConstraintError(&pgconn.PgError{ConstraintName: "other_idx"}))

	// 5. isUniqueSchemaDefinitionKeyConstraintError
	assert.False(t, isUniqueSchemaDefinitionKeyConstraintError(nil))
	assert.False(t, isUniqueSchemaDefinitionKeyConstraintError(errors.New("generic error")))
	assert.True(t, isUniqueSchemaDefinitionKeyConstraintError(errors.New("UNIQUE constraint failed: schema_definitions.unique_key")))
	assert.True(t, isUniqueSchemaDefinitionKeyConstraintError(&pgconn.PgError{ConstraintName: "schema_definitions_unique_key_idx"}))
	assert.False(t, isUniqueSchemaDefinitionKeyConstraintError(&pgconn.PgError{ConstraintName: "other_idx"}))
}

func TestIsNamedUniqueConstraintError(t *testing.T) {
	t.Parallel()

	assert.False(t, isNamedUniqueConstraintError(nil, "my_idx", "my_table.col"))
	assert.False(t, isNamedUniqueConstraintError(errors.New("generic error"), "my_idx", "my_table.col"))
	assert.True(t, isNamedUniqueConstraintError(errors.New("UNIQUE constraint failed: my_table.col"), "my_idx", "my_table.col"))
	assert.False(t, isNamedUniqueConstraintError(errors.New("UNIQUE constraint failed: other_table.col"), "my_idx", "my_table.col"))
	assert.True(t, isNamedUniqueConstraintError(&pgconn.PgError{ConstraintName: "my_idx"}, "my_idx", "my_table.col"))
	assert.False(t, isNamedUniqueConstraintError(&pgconn.PgError{ConstraintName: "other_idx"}, "my_idx", "my_table.col"))
}

func TestNormalizeEntityIDAndTimestamps(t *testing.T) {
	t.Parallel()

	t.Run("nil arguments are handled safely", func(t *testing.T) {
		ctx := context.Background()
		assert.NotPanics(t, func() {
			normalizeEntityIDAndTimestamps(ctx, nil, nil, nil)
		})
	})

	t.Run("generates ID when empty", func(t *testing.T) {
		ctx := context.Background()
		var id string
		normalizeEntityIDAndTimestamps(ctx, &id, nil, nil)
		assert.NotEmpty(t, id)
	})

	t.Run("preserves caller-provided ID", func(t *testing.T) {
		ctx := context.Background()
		id := "custom-uuid-1234"
		normalizeEntityIDAndTimestamps(ctx, &id, nil, nil)
		assert.Equal(t, "custom-uuid-1234", id)
	})

	t.Run("sets deterministic timestamps when present in context", func(t *testing.T) {
		fixedTime := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
		ctx := WithDeterministicTime(context.Background(), fixedTime)

		var id string
		var createdAt, updatedAt time.Time
		normalizeEntityIDAndTimestamps(ctx, &id, &createdAt, &updatedAt)

		assert.NotEmpty(t, id)
		assert.Equal(t, fixedTime, createdAt)
		assert.Equal(t, fixedTime, updatedAt)
	})

	t.Run("preserves existing createdAt and sets updatedAt to createdAt", func(t *testing.T) {
		existingTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		ctx := context.Background()

		id := "my-id"
		createdAt := existingTime
		var updatedAt time.Time
		normalizeEntityIDAndTimestamps(ctx, &id, &createdAt, &updatedAt)

		assert.Equal(t, "my-id", id)
		assert.Equal(t, existingTime, createdAt)
		assert.Equal(t, existingTime, updatedAt)
	})

	t.Run("preserves existing updatedAt", func(t *testing.T) {
		createdTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		updatedTime := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
		ctx := context.Background()

		id := "my-id"
		createdAt := createdTime
		updatedAt := updatedTime
		normalizeEntityIDAndTimestamps(ctx, &id, &createdAt, &updatedAt)

		assert.Equal(t, "my-id", id)
		assert.Equal(t, createdTime, createdAt)
		assert.Equal(t, updatedTime, updatedAt)
	})

	t.Run("without deterministic time and zero timestamps defaults to current UTC time", func(t *testing.T) {
		ctx := context.Background()
		var id string
		var createdAt, updatedAt time.Time
		before := time.Now().UTC()
		normalizeEntityIDAndTimestamps(ctx, &id, &createdAt, &updatedAt)
		after := time.Now().UTC()

		assert.NotEmpty(t, id)
		assert.False(t, createdAt.IsZero())
		assert.False(t, updatedAt.IsZero())
		assert.Equal(t, createdAt, updatedAt)
		assert.True(t, !createdAt.Before(before) && !createdAt.After(after))
	})
}

func TestSortedMapKeys(t *testing.T) {
	t.Parallel()

	assert.Nil(t, sortedMapKeys(nil))
	assert.Nil(t, sortedMapKeys(map[string]string{}))

	single := map[string]string{"k1": "v1"}
	assert.Equal(t, []string{"k1"}, sortedMapKeys(single))

	multi := map[string]string{
		"zebra":  "z",
		"apple":  "a",
		"mango":  "m",
		"banana": "b",
		"cherry": "c",
	}
	expected := []string{"apple", "banana", "cherry", "mango", "zebra"}
	assert.Equal(t, expected, sortedMapKeys(multi))
}

type mockPGExecRecord struct {
	query string
	args  []any
}

type mockPGDriver struct {
	mu      sync.Mutex
	records []mockPGExecRecord
}

func (m *mockPGDriver) Open(name string) (driver.Conn, error) {
	return &mockPGConn{drv: m}, nil
}

type mockPGConnector struct {
	drv *mockPGDriver
}

func (c *mockPGConnector) Connect(context.Context) (driver.Conn, error) {
	return &mockPGConn{drv: c.drv}, nil
}

func (c *mockPGConnector) Driver() driver.Driver {
	return c.drv
}

type mockPGConn struct {
	drv *mockPGDriver
}

func (c *mockPGConn) Prepare(query string) (driver.Stmt, error) {
	return &mockPGStmt{drv: c.drv, query: query}, nil
}

func (c *mockPGConn) Close() error { return nil }

func (c *mockPGConn) Begin() (driver.Tx, error) {
	return &mockPGTx{}, nil
}

func (c *mockPGConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return &mockPGTx{}, nil
}

type mockPGTx struct{}

func (t *mockPGTx) Commit() error   { return nil }
func (t *mockPGTx) Rollback() error { return nil }

type mockPGRows struct {
	columns []string
	values  [][]driver.Value
	idx     int
}

func (r *mockPGRows) Columns() []string { return r.columns }
func (r *mockPGRows) Close() error      { return nil }
func (r *mockPGRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.idx])
	r.idx++
	return nil
}

type mockPGStmt struct {
	drv   *mockPGDriver
	query string
}

func (s *mockPGStmt) Close() error   { return nil }
func (s *mockPGStmt) NumInput() int { return -1 }

func (s *mockPGStmt) Exec(args []driver.Value) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

func (s *mockPGStmt) Query(args []driver.Value) (driver.Rows, error) {
	return nil, io.EOF
}

func (s *mockPGStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	s.drv.mu.Lock()
	defer s.drv.mu.Unlock()
	vals := make([]any, len(args))
	for i, a := range args {
		vals[i] = a.Value
	}
	s.drv.records = append(s.drv.records, mockPGExecRecord{
		query: s.query,
		args:  vals,
	})
	return driver.RowsAffected(1), nil
}

func (s *mockPGStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	s.drv.mu.Lock()
	defer s.drv.mu.Unlock()
	vals := make([]any, len(args))
	for i, a := range args {
		vals[i] = a.Value
	}
	s.drv.records = append(s.drv.records, mockPGExecRecord{
		query: s.query,
		args:  vals,
	})
	if strings.Contains(s.query, "FROM") && strings.Contains(s.query, "hosts") {
		return &mockPGRows{
			columns: []string{"id", "unique_key", "public_key", "last_signature_timestamp", "created_at"},
			values:  [][]driver.Value{{"host-1", "key", "pub", int64(0), time.Now().UTC()}},
		}, nil
	}
	if strings.Contains(s.query, "RETURNING request_version") {
		return &mockPGRows{
			columns: []string{"request_version"},
			values:  [][]driver.Value{{int64(1)}},
		}, nil
	}
	return &mockPGRows{}, nil
}

func TestSetUpdatedAtPostgresDeterministicTime(t *testing.T) {
	t.Parallel()

	drv := &mockPGDriver{}
	db := sql.OpenDB(&mockPGConnector{drv: drv})
	defer func() { _ = db.Close() }()

	fixedTime := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	// 1. Deterministic time in context: generates parameterized query with $1 = time and $2 = id
	ctxWithTime := WithDeterministicTime(context.Background(), fixedTime)
	tx, err := db.BeginTx(ctxWithTime, nil)
	require.NoError(t, err)

	err = setUpdatedAtPostgres(ctxWithTime, tx, `"grantory"."requests"`, "id", "req-100")
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	drv.mu.Lock()
	require.Len(t, drv.records, 1)
	assert.Equal(t, `UPDATE "grantory"."requests" SET updated_at = $1 WHERE id = $2`, drv.records[0].query)
	require.Len(t, drv.records[0].args, 2)
	assert.Equal(t, fixedTime, drv.records[0].args[0])
	assert.Equal(t, "req-100", drv.records[0].args[1])
	drv.records = nil
	drv.mu.Unlock()

	// 2. No deterministic time in context: uses NOW() and $1 = id
	ctxWithoutTime := context.Background()
	tx, err = db.BeginTx(ctxWithoutTime, nil)
	require.NoError(t, err)

	err = setUpdatedAtPostgres(ctxWithoutTime, tx, `"grantory"."requests"`, "id", "req-200")
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	drv.mu.Lock()
	require.Len(t, drv.records, 1)
	assert.Equal(t, `UPDATE "grantory"."requests" SET updated_at = NOW() WHERE id = $1`, drv.records[0].query)
	require.Len(t, drv.records[0].args, 1)
	assert.Equal(t, "req-200", drv.records[0].args[0])
	drv.records = nil
	drv.mu.Unlock()
}

func TestInsertResourceEventPostgresTimestamps(t *testing.T) {
	t.Parallel()

	drv := &mockPGDriver{}
	db := sql.OpenDB(&mockPGConnector{drv: drv})
	defer func() { _ = db.Close() }()

	explicitTime := time.Date(2026, 5, 1, 10, 30, 0, 0, time.UTC)
	contextTime := time.Date(2026, 9, 10, 14, 0, 0, 0, time.UTC)

	// Case 1: Explicit Timestamp provided on ResourceEventParams
	t.Run("explicit timestamp on params", func(t *testing.T) {
		tx, err := db.BeginTx(context.Background(), nil)
		require.NoError(t, err)

		params := ResourceEventParams{
			ResourceType:  "request",
			ResourceID:    "req-1",
			EventType:     "create",
			OldPayloadMap: map[string]any{"old": "val"},
			NewPayloadMap: map[string]any{"new": "val"},
			OldLabelsMap:  map[string]string{"k": "v1"},
			NewLabelsMap:  map[string]string{"k": "v2"},
			Timestamp:     explicitTime,
		}

		err = insertResourceEventPostgres(context.Background(), tx, `"grantory"."resource_events"`, params)
		require.NoError(t, err)
		require.NoError(t, tx.Commit())

		drv.mu.Lock()
		defer drv.mu.Unlock()
		require.Len(t, drv.records, 1)
		rec := drv.records[0]
		drv.records = nil

		assert.Contains(t, rec.query, `INSERT INTO "grantory"."resource_events" (id, resource_type, resource_id, event_type, old_payload, new_payload, old_labels, new_labels, created_at)`)
		assert.Contains(t, rec.query, `VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9)`)
		assert.Contains(t, rec.query, `ON CONFLICT (id) DO NOTHING`)
		require.Len(t, rec.args, 9)
		hashInput := fmt.Sprintf("%s:%s:%s:%d:%s:%s:%s:%s", params.ResourceType, params.ResourceID, params.EventType, explicitTime.UnixNano(), `{"old":"val"}`, `{"new":"val"}`, `{"k":"v1"}`, `{"k":"v2"}`)
		expectedEventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(hashInput)).String()
		assert.Equal(t, expectedEventID, rec.args[0])
		assert.Equal(t, "request", rec.args[1])
		assert.Equal(t, "req-1", rec.args[2])
		assert.Equal(t, "create", rec.args[3])
		assert.Equal(t, `{"old":"val"}`, rec.args[4])
		assert.Equal(t, `{"new":"val"}`, rec.args[5])
		assert.Equal(t, `{"k":"v1"}`, rec.args[6])
		assert.Equal(t, `{"k":"v2"}`, rec.args[7])
		assert.Equal(t, explicitTime, rec.args[8])
	})

	// Case 2: Deterministic time in context when params.Timestamp is zero
	t.Run("deterministic time from context", func(t *testing.T) {
		ctxWithTime := WithDeterministicTime(context.Background(), contextTime)
		tx, err := db.BeginTx(ctxWithTime, nil)
		require.NoError(t, err)

		params := ResourceEventParams{
			ResourceType: "register",
			ResourceID:   "reg-1",
			EventType:    "update",
		}

		err = insertResourceEventPostgres(ctxWithTime, tx, `"grantory"."resource_events"`, params)
		require.NoError(t, err)
		require.NoError(t, tx.Commit())

		drv.mu.Lock()
		defer drv.mu.Unlock()
		require.Len(t, drv.records, 1)
		rec := drv.records[0]
		drv.records = nil

		assert.Contains(t, rec.query, `ON CONFLICT (id) DO NOTHING`)
		require.Len(t, rec.args, 9)
		oldP, _ := encodeJSON(params.OldPayloadMap)
		newP, _ := encodeJSON(params.NewPayloadMap)
		oldL, _ := encodeJSON(params.OldLabelsMap)
		newL, _ := encodeJSON(params.NewLabelsMap)
		hashInput := fmt.Sprintf("%s:%s:%s:%d:%s:%s:%s:%s", params.ResourceType, params.ResourceID, params.EventType, contextTime.UnixNano(), derefString(oldP), derefString(newP), derefString(oldL), derefString(newL))
		expectedEventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(hashInput)).String()
		assert.Equal(t, expectedEventID, rec.args[0])
		assert.Equal(t, contextTime, rec.args[8])
	})

	// Case 3: Explicit timestamp takes precedence over context deterministic time
	t.Run("explicit timestamp takes precedence over context deterministic time", func(t *testing.T) {
		ctxWithTime := WithDeterministicTime(context.Background(), contextTime)
		tx, err := db.BeginTx(ctxWithTime, nil)
		require.NoError(t, err)

		params := ResourceEventParams{
			ResourceType: "register",
			ResourceID:   "reg-1",
			EventType:    "update",
			Timestamp:    explicitTime,
		}

		err = insertResourceEventPostgres(ctxWithTime, tx, `"grantory"."resource_events"`, params)
		require.NoError(t, err)
		require.NoError(t, tx.Commit())

		drv.mu.Lock()
		defer drv.mu.Unlock()
		require.Len(t, drv.records, 1)
		rec := drv.records[0]
		drv.records = nil

		assert.Contains(t, rec.query, `ON CONFLICT (id) DO NOTHING`)
		require.Len(t, rec.args, 9)
		oldP, _ := encodeJSON(params.OldPayloadMap)
		newP, _ := encodeJSON(params.NewPayloadMap)
		oldL, _ := encodeJSON(params.OldLabelsMap)
		newL, _ := encodeJSON(params.NewLabelsMap)
		hashInput := fmt.Sprintf("%s:%s:%s:%d:%s:%s:%s:%s", params.ResourceType, params.ResourceID, params.EventType, explicitTime.UnixNano(), derefString(oldP), derefString(newP), derefString(oldL), derefString(newL))
		expectedEventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(hashInput)).String()
		assert.Equal(t, expectedEventID, rec.args[0])
		assert.Equal(t, explicitTime, rec.args[8])
	})

	// Case 4: Neither explicit timestamp nor context time -> fallback to NOW()
	t.Run("fallback to system clock", func(t *testing.T) {
		tx, err := db.BeginTx(context.Background(), nil)
		require.NoError(t, err)

		params := ResourceEventParams{
			ResourceType: "grant",
			ResourceID:   "grant-1",
			EventType:    "create",
		}

		err = insertResourceEventPostgres(context.Background(), tx, `"grantory"."resource_events"`, params)
		require.NoError(t, err)
		require.NoError(t, tx.Commit())

		drv.mu.Lock()
		defer drv.mu.Unlock()
		require.Len(t, drv.records, 1)
		rec := drv.records[0]
		drv.records = nil

		assert.Contains(t, rec.query, `VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, NOW())`)
		assert.NotContains(t, rec.query, `ON CONFLICT (id) DO NOTHING`)
		require.Len(t, rec.args, 8)
		assert.NotEmpty(t, rec.args[0])
		assert.Equal(t, "grant", rec.args[1])
		assert.Equal(t, "grant-1", rec.args[2])
		assert.Equal(t, "create", rec.args[3])
	})
}

func TestInsertResourceEventPostgresDeterminismParityWithSQLite(t *testing.T) {
	t.Parallel()

	drv := &mockPGDriver{}
	pgDB := sql.OpenDB(&mockPGConnector{drv: drv})
	defer func() { _ = pgDB.Close() }()

	sqStore, err := New(context.Background(), ":memory:")
	require.NoError(t, err)
	defer closeStore(t, sqStore)
	require.NoError(t, sqStore.Migrate(context.Background()))

	fixedTime := time.Date(2026, 9, 12, 12, 34, 56, 789000000, time.UTC)

	testCases := []struct {
		name   string
		ctx    context.Context
		params ResourceEventParams
	}{
		{
			name: "explicit timestamp on params",
			ctx:  context.Background(),
			params: ResourceEventParams{
				ResourceType:  "request",
				ResourceID:    "req-test-parity",
				EventType:     "create",
				OldPayloadMap: map[string]any{"action": "create"},
				NewPayloadMap: map[string]any{"action": "done", "status": "active"},
				OldLabelsMap:  map[string]string{"env": "staging"},
				NewLabelsMap:  map[string]string{"env": "production", "tier": "web"},
				Timestamp:     fixedTime,
			},
		},
		{
			name: "deterministic time from context",
			ctx:  WithDeterministicTime(context.Background(), fixedTime),
			params: ResourceEventParams{
				ResourceType:  "host",
				ResourceID:    "host-test-parity",
				EventType:     "update",
				OldPayloadMap: nil,
				NewPayloadMap: map[string]any{"version": float64(2)},
				OldLabelsMap:  map[string]string{"region": "us-west"},
				NewLabelsMap:  map[string]string{"region": "us-east"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Run insertResourceEventPostgres
			pgTx, err := pgDB.BeginTx(tc.ctx, nil)
			require.NoError(t, err)
			err = insertResourceEventPostgres(tc.ctx, pgTx, `"grantory"."resource_events"`, tc.params)
			require.NoError(t, err)
			require.NoError(t, pgTx.Commit())

			drv.mu.Lock()
			require.Len(t, drv.records, 1)
			pgRecord := drv.records[0]
			drv.records = nil
			drv.mu.Unlock()

			pgEventID, ok := pgRecord.args[0].(string)
			require.True(t, ok)
			require.NotEmpty(t, pgEventID)

			// 2. Run insertResourceEventSQLite
			sqTx, err := sqStore.(*sqliteStore).db.BeginTx(tc.ctx, nil)
			require.NoError(t, err)
			err = insertResourceEventSQLite(tc.ctx, sqTx, tc.params)
			require.NoError(t, err)
			require.NoError(t, sqTx.Commit())

			// Query SQLite to get the inserted event ID
			var sqEventID string
			err = sqStore.(*sqliteStore).db.QueryRowContext(tc.ctx,
				"SELECT id FROM resource_events WHERE resource_type = ? AND resource_id = ?",
				tc.params.ResourceType, tc.params.ResourceID,
			).Scan(&sqEventID)
			require.NoError(t, err)

			// 3. Compare parity: both PostgreSQL and SQLite must generate the exact same deterministic UUID
			assert.Equal(t, sqEventID, pgEventID, "PostgreSQL deterministic event ID must match SQLite deterministic event ID")

			// 4. Calling insertResourceEventPostgres again with identical params produces identical ID
			pgTx2, err := pgDB.BeginTx(tc.ctx, nil)
			require.NoError(t, err)
			err = insertResourceEventPostgres(tc.ctx, pgTx2, `"grantory"."resource_events"`, tc.params)
			require.NoError(t, err)
			require.NoError(t, pgTx2.Commit())

			drv.mu.Lock()
			require.Len(t, drv.records, 1)
			pgRecord2 := drv.records[0]
			drv.records = nil
			drv.mu.Unlock()

			pgEventID2, ok := pgRecord2.args[0].(string)
			require.True(t, ok)
			assert.Equal(t, pgEventID, pgEventID2, "subsequent insert with identical deterministic params must generate identical ID")
		})
	}
}

func findInsertRecord(records []mockPGExecRecord, table string) *mockPGExecRecord {
	for _, r := range records {
		if strings.Contains(r.query, "INSERT INTO") && strings.Contains(r.query, table) {
			return &r
		}
	}
	return nil
}

func newTestStore(drv *mockPGDriver) (*postgresStore, func()) {
	db := sql.OpenDB(&mockPGConnector{drv: drv})
	store := &postgresStore{db: db}
	store.SetNamespace("default")
	return store, func() { _ = db.Close() }
}

func TestPostgresEntityCreationTimestamps(t *testing.T) {
	t.Parallel()

	explicitCreated := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	explicitUpdated := time.Date(2026, 4, 1, 11, 0, 0, 0, time.UTC)
	detTime := time.Date(2026, 9, 10, 15, 30, 0, 0, time.UTC)

	t.Run("CreateHost timestamps", func(t *testing.T) {
		t.Parallel()

		// 1. Explicit caller timestamp
		drv := &mockPGDriver{}
		store, cleanup := newTestStore(drv)
		defer cleanup()

		host, err := store.CreateHost(context.Background(), Host{
			ID:        "host-exp-1",
			UniqueKey: "host-key-1",
			CreatedAt: explicitCreated,
		})
		require.NoError(t, err)
		assert.Equal(t, explicitCreated, host.CreatedAt)

		drv.mu.Lock()
		rec := findInsertRecord(drv.records, `"hosts"`)
		require.NotNil(t, rec, "hosts insert record must exist")
		assert.Equal(t, `INSERT INTO "default"."hosts" (id, unique_key, public_key, created_at) VALUES ($1, $2, $3, COALESCE($4::timestamptz, NOW()))`, rec.query)
		require.Len(t, rec.args, 4)
		assert.Equal(t, "host-exp-1", rec.args[0])
		assert.Equal(t, "host-key-1", rec.args[1])
		assert.Nil(t, rec.args[2])
		assert.Equal(t, explicitCreated, rec.args[3])
		drv.records = nil
		drv.mu.Unlock()

		// 2. Deterministic context time
		ctxDet := WithDeterministicTime(context.Background(), detTime)
		hostDet, err := store.CreateHost(ctxDet, Host{
			ID: "host-det-1",
		})
		require.NoError(t, err)
		assert.Equal(t, detTime, hostDet.CreatedAt)

		drv.mu.Lock()
		rec = findInsertRecord(drv.records, `"hosts"`)
		require.NotNil(t, rec)
		assert.Equal(t, detTime, rec.args[3])
		drv.records = nil
		drv.mu.Unlock()

		// 3. Zero timestamps without deterministic time (defaults to current UTC time in memory and passes native time.Time)
		hostZero, err := store.CreateHost(context.Background(), Host{
			ID: "host-zero-1",
		})
		require.NoError(t, err)
		assert.False(t, hostZero.CreatedAt.IsZero())

		drv.mu.Lock()
		rec = findInsertRecord(drv.records, `"hosts"`)
		require.NotNil(t, rec)
		assert.Equal(t, hostZero.CreatedAt, rec.args[3], "arg 4 should bind native time.Time")
		drv.records = nil
		drv.mu.Unlock()
	})

	t.Run("CreateRequest timestamps", func(t *testing.T) {
		t.Parallel()

		drv := &mockPGDriver{}
		store, cleanup := newTestStore(drv)
		defer cleanup()

		// 1. Explicit caller timestamps
		req, err := store.CreateRequest(context.Background(), Request{
			ID:        "req-exp-1",
			HostID:    "host-1",
			Payload:   map[string]any{"data": "val"},
			CreatedAt: explicitCreated,
			UpdatedAt: explicitUpdated,
		})
		require.NoError(t, err)
		assert.Equal(t, explicitCreated, req.CreatedAt)
		assert.Equal(t, explicitUpdated, req.UpdatedAt)

		drv.mu.Lock()
		rec := findInsertRecord(drv.records, `"requests"`)
		require.NotNil(t, rec, "requests insert record must exist")
		assert.Equal(t, `INSERT INTO "default"."requests" (id, host_id, request_schema_definition_id, grant_schema_definition_id, unique_key, data, mutable, version, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9::timestamptz, NOW()), COALESCE($10::timestamptz, NOW()))`, rec.query)
		require.Len(t, rec.args, 10)
		assert.Equal(t, "req-exp-1", rec.args[0])
		assert.Equal(t, "host-1", rec.args[1])
		assert.Equal(t, explicitCreated, rec.args[8])
		assert.Equal(t, explicitUpdated, rec.args[9])

		recEvent := findInsertRecord(drv.records, `"resource_events"`)
		require.NotNil(t, recEvent, "resource_events insert record must exist")
		assert.Equal(t, explicitCreated, recEvent.args[8], "resource event timestamp must match req.CreatedAt")
		assert.NotEmpty(t, recEvent.args[0])
		drv.records = nil
		drv.mu.Unlock()

		// 2. Deterministic context time
		ctxDet := WithDeterministicTime(context.Background(), detTime)
		reqDet, err := store.CreateRequest(ctxDet, Request{
			ID:      "req-det-1",
			HostID:  "host-1",
			Payload: map[string]any{"data": "val"},
		})
		require.NoError(t, err)
		assert.Equal(t, detTime, reqDet.CreatedAt)
		assert.Equal(t, detTime, reqDet.UpdatedAt)

		drv.mu.Lock()
		rec = findInsertRecord(drv.records, `"requests"`)
		require.NotNil(t, rec)
		assert.Equal(t, detTime, rec.args[8])
		assert.Equal(t, detTime, rec.args[9])

		recEvent = findInsertRecord(drv.records, `"resource_events"`)
		require.NotNil(t, recEvent)
		assert.Equal(t, detTime, recEvent.args[8])
		assert.NotEmpty(t, recEvent.args[0])
		drv.records = nil
		drv.mu.Unlock()

		// 3. Zero timestamps
		reqZero, err := store.CreateRequest(context.Background(), Request{
			ID:      "req-zero-1",
			HostID:  "host-1",
			Payload: map[string]any{"data": "val"},
		})
		require.NoError(t, err)
		assert.False(t, reqZero.CreatedAt.IsZero())
		assert.False(t, reqZero.UpdatedAt.IsZero())

		drv.mu.Lock()
		rec = findInsertRecord(drv.records, `"requests"`)
		require.NotNil(t, rec)
		assert.Equal(t, reqZero.CreatedAt, rec.args[8])
		assert.Equal(t, reqZero.UpdatedAt, rec.args[9])

		recEvent = findInsertRecord(drv.records, `"resource_events"`)
		require.NotNil(t, recEvent)
		assert.Equal(t, reqZero.CreatedAt, recEvent.args[8])
		assert.NotEmpty(t, recEvent.args[0])
		drv.records = nil
		drv.mu.Unlock()
	})

	t.Run("CreateRegister timestamps", func(t *testing.T) {
		t.Parallel()

		drv := &mockPGDriver{}
		store, cleanup := newTestStore(drv)
		defer cleanup()

		// 1. Explicit caller timestamps
		reg, err := store.CreateRegister(context.Background(), Register{
			ID:        "reg-exp-1",
			HostID:    "host-1",
			Payload:   map[string]any{"data": "val"},
			CreatedAt: explicitCreated,
			UpdatedAt: explicitUpdated,
		})
		require.NoError(t, err)
		assert.Equal(t, explicitCreated, reg.CreatedAt)
		assert.Equal(t, explicitUpdated, reg.UpdatedAt)

		drv.mu.Lock()
		rec := findInsertRecord(drv.records, `"registers"`)
		require.NotNil(t, rec, "registers insert record must exist")
		assert.Equal(t, `INSERT INTO "default"."registers" (id, host_id, schema_definition_id, unique_key, data, mutable, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7::timestamptz, NOW()), COALESCE($8::timestamptz, NOW()))`, rec.query)
		require.Len(t, rec.args, 8)
		assert.Equal(t, "reg-exp-1", rec.args[0])
		assert.Equal(t, "host-1", rec.args[1])
		assert.Equal(t, explicitCreated, rec.args[6])
		assert.Equal(t, explicitUpdated, rec.args[7])

		recEvent := findInsertRecord(drv.records, `"resource_events"`)
		require.NotNil(t, recEvent, "resource_events insert record must exist")
		assert.Equal(t, explicitCreated, recEvent.args[8], "resource event timestamp must match reg.CreatedAt")
		assert.NotEmpty(t, recEvent.args[0])
		drv.records = nil
		drv.mu.Unlock()

		// 2. Deterministic context time
		ctxDet := WithDeterministicTime(context.Background(), detTime)
		regDet, err := store.CreateRegister(ctxDet, Register{
			ID:      "reg-det-1",
			HostID:  "host-1",
			Payload: map[string]any{"data": "val"},
		})
		require.NoError(t, err)
		assert.Equal(t, detTime, regDet.CreatedAt)
		assert.Equal(t, detTime, regDet.UpdatedAt)

		drv.mu.Lock()
		rec = findInsertRecord(drv.records, `"registers"`)
		require.NotNil(t, rec)
		assert.Equal(t, detTime, rec.args[6])
		assert.Equal(t, detTime, rec.args[7])

		recEvent = findInsertRecord(drv.records, `"resource_events"`)
		require.NotNil(t, recEvent)
		assert.Equal(t, detTime, recEvent.args[8])
		assert.NotEmpty(t, recEvent.args[0])
		drv.records = nil
		drv.mu.Unlock()

		// 3. Zero timestamps
		regZero, err := store.CreateRegister(context.Background(), Register{
			ID:      "reg-zero-1",
			HostID:  "host-1",
			Payload: map[string]any{"data": "val"},
		})
		require.NoError(t, err)
		assert.False(t, regZero.CreatedAt.IsZero())
		assert.False(t, regZero.UpdatedAt.IsZero())

		drv.mu.Lock()
		rec = findInsertRecord(drv.records, `"registers"`)
		require.NotNil(t, rec)
		assert.Equal(t, regZero.CreatedAt, rec.args[6])
		assert.Equal(t, regZero.UpdatedAt, rec.args[7])

		recEvent = findInsertRecord(drv.records, `"resource_events"`)
		require.NotNil(t, recEvent)
		assert.Equal(t, regZero.CreatedAt, recEvent.args[8])
		assert.NotEmpty(t, recEvent.args[0])
		drv.records = nil
		drv.mu.Unlock()
	})

	t.Run("CreateGrant timestamps", func(t *testing.T) {
		t.Parallel()

		drv := &mockPGDriver{}
		store, cleanup := newTestStore(drv)
		defer cleanup()

		// 1. Explicit caller timestamps with RequestVersion > 0
		grant, err := store.CreateGrant(context.Background(), Grant{
			ID:             "grant-exp-1",
			RequestID:      "req-1",
			RequestVersion: 1,
			Payload:        map[string]any{"ok": true},
			CreatedAt:      explicitCreated,
			UpdatedAt:      explicitUpdated,
		})
		require.NoError(t, err)
		assert.Equal(t, explicitCreated, grant.CreatedAt)
		assert.Equal(t, explicitUpdated, grant.UpdatedAt)

		drv.mu.Lock()
		rec := findInsertRecord(drv.records, `"grants"`)
		require.NotNil(t, rec, "grants insert record must exist")
		assert.Contains(t, rec.query, `INSERT INTO "default"."grants" (id, request_id, payload, request_version, created_at, updated_at)`)
		assert.Contains(t, rec.query, `COALESCE($5::timestamptz, NOW()), COALESCE($6::timestamptz, NOW())`)
		require.Len(t, rec.args, 6)
		assert.Equal(t, "grant-exp-1", rec.args[0])
		assert.Equal(t, `{"ok":true}`, rec.args[1])
		assert.Equal(t, "req-1", rec.args[2])
		assert.Equal(t, int64(1), rec.args[3])
		assert.Equal(t, explicitCreated, rec.args[4])
		assert.Equal(t, explicitUpdated, rec.args[5])

		recEvent := findInsertRecord(drv.records, `"resource_events"`)
		require.NotNil(t, recEvent, "resource_events insert record must exist")
		assert.Equal(t, explicitCreated, recEvent.args[8], "resource event timestamp must match grant CreatedAt")
		assert.NotEmpty(t, recEvent.args[0])
		drv.records = nil
		drv.mu.Unlock()

		// 2. Explicit caller timestamps with RequestVersion <= 0
		grant2, err := store.CreateGrant(context.Background(), Grant{
			ID:        "grant-exp-2",
			RequestID: "req-1",
			Payload:   map[string]any{"ok": true},
			CreatedAt: explicitCreated,
			UpdatedAt: explicitUpdated,
		})
		require.NoError(t, err)
		assert.Equal(t, explicitCreated, grant2.CreatedAt)
		assert.Equal(t, explicitUpdated, grant2.UpdatedAt)

		drv.mu.Lock()
		rec = findInsertRecord(drv.records, `"grants"`)
		require.NotNil(t, rec)
		assert.Contains(t, rec.query, `COALESCE($4::timestamptz, NOW()), COALESCE($5::timestamptz, NOW())`)
		require.Len(t, rec.args, 5)
		assert.Equal(t, "grant-exp-2", rec.args[0])
		assert.Equal(t, `{"ok":true}`, rec.args[1])
		assert.Equal(t, "req-1", rec.args[2])
		assert.Equal(t, explicitCreated, rec.args[3])
		assert.Equal(t, explicitUpdated, rec.args[4])

		recEvent = findInsertRecord(drv.records, `"resource_events"`)
		require.NotNil(t, recEvent)
		assert.Equal(t, explicitCreated, recEvent.args[8])
		assert.NotEmpty(t, recEvent.args[0])
		drv.records = nil
		drv.mu.Unlock()

		// 3. Deterministic context time
		ctxDet := WithDeterministicTime(context.Background(), detTime)
		grantDet, err := store.CreateGrant(ctxDet, Grant{
			ID:             "grant-det-1",
			RequestID:      "req-1",
			RequestVersion: 2,
		})
		require.NoError(t, err)
		assert.Equal(t, detTime, grantDet.CreatedAt)
		assert.Equal(t, detTime, grantDet.UpdatedAt)

		drv.mu.Lock()
		rec = findInsertRecord(drv.records, `"grants"`)
		require.NotNil(t, rec)
		assert.Equal(t, detTime, rec.args[4])
		assert.Equal(t, detTime, rec.args[5])

		recEvent = findInsertRecord(drv.records, `"resource_events"`)
		require.NotNil(t, recEvent)
		assert.Equal(t, detTime, recEvent.args[8])
		assert.NotEmpty(t, recEvent.args[0])
		drv.records = nil
		drv.mu.Unlock()

		// 4. Zero timestamps
		grantZero, err := store.CreateGrant(context.Background(), Grant{
			ID:        "grant-zero-1",
			RequestID: "req-1",
		})
		require.NoError(t, err)
		assert.False(t, grantZero.CreatedAt.IsZero())
		assert.False(t, grantZero.UpdatedAt.IsZero())

		drv.mu.Lock()
		rec = findInsertRecord(drv.records, `"grants"`)
		require.NotNil(t, rec)
		assert.Equal(t, grantZero.CreatedAt, rec.args[3])
		assert.Equal(t, grantZero.UpdatedAt, rec.args[4])

		recEvent = findInsertRecord(drv.records, `"resource_events"`)
		require.NotNil(t, recEvent)
		assert.Equal(t, grantZero.CreatedAt, recEvent.args[8])
		assert.NotEmpty(t, recEvent.args[0])
		drv.records = nil
		drv.mu.Unlock()
	})

	t.Run("CreateSchemaDefinition timestamps", func(t *testing.T) {
		t.Parallel()

		drv := &mockPGDriver{}
		store, cleanup := newTestStore(drv)
		defer cleanup()

		// 1. Explicit caller timestamp
		def, err := store.CreateSchemaDefinition(context.Background(), SchemaDefinition{
			ID:        "def-exp-1",
			UniqueKey: "schema-1",
			Schema:    json.RawMessage(`{"type":"object"}`),
			CreatedAt: explicitCreated,
		})
		require.NoError(t, err)
		assert.Equal(t, explicitCreated, def.CreatedAt)

		drv.mu.Lock()
		rec := findInsertRecord(drv.records, `"schema_definitions"`)
		require.NotNil(t, rec, "schema_definitions insert record must exist")
		assert.Equal(t, `INSERT INTO "default"."schema_definitions" (id, unique_key, schema, created_at) VALUES ($1, $2, $3, COALESCE($4::timestamptz, NOW()))`, rec.query)
		require.Len(t, rec.args, 4)
		assert.Equal(t, "def-exp-1", rec.args[0])
		assert.Equal(t, "schema-1", rec.args[1])
		assert.Equal(t, `{"type":"object"}`, rec.args[2])
		assert.Equal(t, explicitCreated, rec.args[3])
		drv.records = nil
		drv.mu.Unlock()

		// 2. Deterministic context time
		ctxDet := WithDeterministicTime(context.Background(), detTime)
		defDet, err := store.CreateSchemaDefinition(ctxDet, SchemaDefinition{
			ID:     "def-det-1",
			Schema: json.RawMessage(`{}`),
		})
		require.NoError(t, err)
		assert.Equal(t, detTime, defDet.CreatedAt)

		drv.mu.Lock()
		rec = findInsertRecord(drv.records, `"schema_definitions"`)
		require.NotNil(t, rec)
		assert.Equal(t, detTime, rec.args[3])
		drv.records = nil
		drv.mu.Unlock()

		// 3. Zero timestamps
		defZero, err := store.CreateSchemaDefinition(context.Background(), SchemaDefinition{
			ID:     "def-zero-1",
			Schema: json.RawMessage(`{}`),
		})
		require.NoError(t, err)
		assert.False(t, defZero.CreatedAt.IsZero())

		drv.mu.Lock()
		rec = findInsertRecord(drv.records, `"schema_definitions"`)
		require.NotNil(t, rec)
		assert.Equal(t, defZero.CreatedAt, rec.args[3])
		drv.records = nil
		drv.mu.Unlock()
	})
}

func TestPostgresEntityCreationEventParityWithSQLite(t *testing.T) {
	t.Parallel()

	sqStore, err := New(context.Background(), ":memory:")
	require.NoError(t, err)
	defer closeStore(t, sqStore)
	require.NoError(t, sqStore.Migrate(context.Background()))

	fixedTime := time.Date(2026, 9, 12, 12, 34, 56, 789000000, time.UTC)

	// Prerequisite host for SQLite FK constraints
	host, err := sqStore.CreateHost(context.Background(), Host{
		ID:        "host-parity-1",
		UniqueKey: "host-parity-key",
		CreatedAt: fixedTime,
	})
	require.NoError(t, err)

	t.Run("CreateRequest parity", func(t *testing.T) {
		reqInput := Request{
			ID:        "req-parity-1",
			HostID:    host.ID,
			Payload:   map[string]any{"action": "create", "role": "admin"},
			Labels:    map[string]string{"env": "prod", "tier": "backend"},
			CreatedAt: fixedTime,
			UpdatedAt: fixedTime,
		}

		// 1. SQLite creation
		_, err := sqStore.CreateRequest(context.Background(), reqInput)
		require.NoError(t, err)

		var sqEventID string
		err = sqStore.(*sqliteStore).db.QueryRowContext(context.Background(),
			"SELECT id FROM resource_events WHERE resource_type = 'request' AND resource_id = ?",
			reqInput.ID,
		).Scan(&sqEventID)
		require.NoError(t, err)
		require.NotEmpty(t, sqEventID)

		// 2. PostgreSQL creation
		drv := &mockPGDriver{}
		pgStore, cleanup := newTestStore(drv)
		defer cleanup()

		_, err = pgStore.CreateRequest(context.Background(), reqInput)
		require.NoError(t, err)

		drv.mu.Lock()
		recEvent := findInsertRecord(drv.records, `"resource_events"`)
		require.NotNil(t, recEvent, "resource_events insert record must exist for postgres request creation")
		pgEventID, ok := recEvent.args[0].(string)
		require.True(t, ok)
		pgTimestamp, ok := recEvent.args[8].(time.Time)
		require.True(t, ok)
		drv.records = nil
		drv.mu.Unlock()

		assert.Equal(t, fixedTime, pgTimestamp)
		assert.Equal(t, sqEventID, pgEventID, "PostgreSQL CreateRequest resource event ID must match SQLite")
	})

	t.Run("CreateRegister parity", func(t *testing.T) {
		regInput := Register{
			ID:        "reg-parity-1",
			HostID:    host.ID,
			Payload:   map[string]any{"service": "auth", "port": float64(8080)},
			Labels:    map[string]string{"env": "prod"},
			CreatedAt: fixedTime,
			UpdatedAt: fixedTime,
		}

		// 1. SQLite creation
		_, err := sqStore.CreateRegister(context.Background(), regInput)
		require.NoError(t, err)

		var sqEventID string
		err = sqStore.(*sqliteStore).db.QueryRowContext(context.Background(),
			"SELECT id FROM resource_events WHERE resource_type = 'register' AND resource_id = ?",
			regInput.ID,
		).Scan(&sqEventID)
		require.NoError(t, err)
		require.NotEmpty(t, sqEventID)

		// 2. PostgreSQL creation
		drv := &mockPGDriver{}
		pgStore, cleanup := newTestStore(drv)
		defer cleanup()

		_, err = pgStore.CreateRegister(context.Background(), regInput)
		require.NoError(t, err)

		drv.mu.Lock()
		recEvent := findInsertRecord(drv.records, `"resource_events"`)
		require.NotNil(t, recEvent, "resource_events insert record must exist for postgres register creation")
		pgEventID, ok := recEvent.args[0].(string)
		require.True(t, ok)
		pgTimestamp, ok := recEvent.args[8].(time.Time)
		require.True(t, ok)
		drv.records = nil
		drv.mu.Unlock()

		assert.Equal(t, fixedTime, pgTimestamp)
		assert.Equal(t, sqEventID, pgEventID, "PostgreSQL CreateRegister resource event ID must match SQLite")
	})

	t.Run("CreateGrant parity", func(t *testing.T) {
		// Prerequisite request in SQLite
		reqForGrant, err := sqStore.CreateRequest(context.Background(), Request{
			ID:        "req-for-grant-parity",
			HostID:    host.ID,
			CreatedAt: fixedTime,
			UpdatedAt: fixedTime,
		})
		require.NoError(t, err)

		grantInput := Grant{
			ID:             "grant-parity-1",
			RequestID:      reqForGrant.ID,
			RequestVersion: 1,
			Payload:        map[string]any{"allowed": true, "ttl": float64(3600)},
			CreatedAt:      fixedTime,
			UpdatedAt:      fixedTime,
		}

		// 1. SQLite creation
		_, err = sqStore.CreateGrant(context.Background(), grantInput)
		require.NoError(t, err)

		var sqEventID string
		err = sqStore.(*sqliteStore).db.QueryRowContext(context.Background(),
			"SELECT id FROM resource_events WHERE resource_type = 'grant' AND resource_id = ?",
			grantInput.ID,
		).Scan(&sqEventID)
		require.NoError(t, err)
		require.NotEmpty(t, sqEventID)

		// 2. PostgreSQL creation
		drv := &mockPGDriver{}
		pgStore, cleanup := newTestStore(drv)
		defer cleanup()

		_, err = pgStore.CreateGrant(context.Background(), grantInput)
		require.NoError(t, err)

		drv.mu.Lock()
		recEvent := findInsertRecord(drv.records, `"resource_events"`)
		require.NotNil(t, recEvent, "resource_events insert record must exist for postgres grant creation")
		pgEventID, ok := recEvent.args[0].(string)
		require.True(t, ok)
		pgTimestamp, ok := recEvent.args[8].(time.Time)
		require.True(t, ok)
		drv.records = nil
		drv.mu.Unlock()

		assert.Equal(t, fixedTime, pgTimestamp)
		assert.Equal(t, sqEventID, pgEventID, "PostgreSQL CreateGrant resource event ID must match SQLite")
	})
}

func TestPostgresNullableTime(t *testing.T) {
	t.Parallel()

	assert.Nil(t, nullableTime(time.Time{}))

	now := time.Now().UTC()
	val := nullableTime(now)
	require.IsType(t, time.Time{}, val)
	assert.Equal(t, now, val)
}

func TestStandaloneEntityCreationTimestamps(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer func() { _ = store.Close() }()
	require.NoError(t, store.Migrate(ctx))

	before := time.Now().UTC().Add(-2 * time.Second)

	// 1. Host
	host, err := store.CreateHost(ctx, Host{
		ID:        "host-sa-1",
		UniqueKey: "host-sa-key-1",
	})
	require.NoError(t, err)
	assert.False(t, host.CreatedAt.IsZero(), "host.CreatedAt must not be zero")
	assert.True(t, host.CreatedAt.After(before), "host.CreatedAt must be recent")

	// 2. SchemaDefinition
	def, err := store.CreateSchemaDefinition(ctx, SchemaDefinition{
		ID:        "def-sa-1",
		UniqueKey: "def-sa-key-1",
		Schema:    json.RawMessage(`{"type":"object"}`),
	})
	require.NoError(t, err)
	assert.False(t, def.CreatedAt.IsZero(), "def.CreatedAt must not be zero")
	assert.True(t, def.CreatedAt.After(before), "def.CreatedAt must be recent")

	// 3. Request
	req, err := store.CreateRequest(ctx, Request{
		ID:        "req-sa-1",
		HostID:    host.ID,
		UniqueKey: "req-sa-key-1",
		Payload:   map[string]any{"action": "test"},
	})
	require.NoError(t, err)
	assert.False(t, req.CreatedAt.IsZero(), "req.CreatedAt must not be zero")
	assert.False(t, req.UpdatedAt.IsZero(), "req.UpdatedAt must not be zero")
	assert.Equal(t, req.CreatedAt, req.UpdatedAt)
	assert.True(t, req.CreatedAt.After(before), "req.CreatedAt must be recent")

	// 4. Register
	reg, err := store.CreateRegister(ctx, Register{
		ID:        "reg-sa-1",
		HostID:    host.ID,
		UniqueKey: "reg-sa-key-1",
		Payload:   map[string]any{"state": "ready"},
	})
	require.NoError(t, err)
	assert.False(t, reg.CreatedAt.IsZero(), "reg.CreatedAt must not be zero")
	assert.False(t, reg.UpdatedAt.IsZero(), "reg.UpdatedAt must not be zero")
	assert.Equal(t, reg.CreatedAt, reg.UpdatedAt)
	assert.True(t, reg.CreatedAt.After(before), "reg.CreatedAt must be recent")

	// 5. Grant
	grant, err := store.CreateGrant(ctx, Grant{
		ID:        "grant-sa-1",
		RequestID: req.ID,
		Payload:   map[string]any{"approved": true},
	})
	require.NoError(t, err)
	assert.False(t, grant.CreatedAt.IsZero(), "grant.CreatedAt must not be zero")
	assert.False(t, grant.UpdatedAt.IsZero(), "grant.UpdatedAt must not be zero")
	assert.Equal(t, grant.CreatedAt, grant.UpdatedAt)
	assert.True(t, grant.CreatedAt.After(before), "grant.CreatedAt must be recent")
}

func TestStorageHelpers_EncodeJSON(t *testing.T) {
	t.Parallel()

	t.Run("nil value returns nil", func(t *testing.T) {
		val, err := encodeJSON(nil)
		require.NoError(t, err)
		assert.Nil(t, val)
	})

	t.Run("valid value marshals to string", func(t *testing.T) {
		data := map[string]any{"key": "value", "count": float64(1)}
		val, err := encodeJSON(data)
		require.NoError(t, err)
		require.NotNil(t, val)
		assert.JSONEq(t, `{"count":1,"key":"value"}`, *val)
	})

	t.Run("unmarshalable value returns error", func(t *testing.T) {
		ch := make(chan int)
		val, err := encodeJSON(ch)
		assert.Error(t, err)
		assert.Nil(t, val)
	})
}

func TestStorageHelpers_DecodeAnyMap(t *testing.T) {
	t.Parallel()

	t.Run("invalid NullString returns nil", func(t *testing.T) {
		res, err := decodeAnyMap(sql.NullString{Valid: false})
		require.NoError(t, err)
		assert.Nil(t, res)
	})

	t.Run("empty string returns nil", func(t *testing.T) {
		res, err := decodeAnyMap(sql.NullString{Valid: true, String: ""})
		require.NoError(t, err)
		assert.Nil(t, res)
	})

	t.Run("valid JSON decodes to map", func(t *testing.T) {
		res, err := decodeAnyMap(sql.NullString{Valid: true, String: `{"a":"b","num":42}`})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"a": "b", "num": float64(42)}, res)
	})

	t.Run("malformed JSON returns error", func(t *testing.T) {
		res, err := decodeAnyMap(sql.NullString{Valid: true, String: `not-json`})
		assert.Error(t, err)
		assert.Nil(t, res)
	})
}

func TestStorageHelpers_DecodeStringMap(t *testing.T) {
	t.Parallel()

	t.Run("invalid NullString returns nil", func(t *testing.T) {
		res, err := decodeStringMap(sql.NullString{Valid: false})
		require.NoError(t, err)
		assert.Nil(t, res)
	})

	t.Run("empty string returns nil", func(t *testing.T) {
		res, err := decodeStringMap(sql.NullString{Valid: true, String: ""})
		require.NoError(t, err)
		assert.Nil(t, res)
	})

	t.Run("valid JSON decodes to string map", func(t *testing.T) {
		res, err := decodeStringMap(sql.NullString{Valid: true, String: `{"env":"prod","region":"eu-central-1"}`})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"env": "prod", "region": "eu-central-1"}, res)
	})

	t.Run("malformed JSON returns error", func(t *testing.T) {
		res, err := decodeStringMap(sql.NullString{Valid: true, String: `{invalid`})
		assert.Error(t, err)
		assert.Nil(t, res)
	})
}

func TestStorageHelpers_DecodeRawJSON(t *testing.T) {
	t.Parallel()

	t.Run("invalid NullString returns nil", func(t *testing.T) {
		res, err := decodeRawJSON(sql.NullString{Valid: false})
		require.NoError(t, err)
		assert.Nil(t, res)
	})

	t.Run("empty string returns nil", func(t *testing.T) {
		res, err := decodeRawJSON(sql.NullString{Valid: true, String: ""})
		require.NoError(t, err)
		assert.Nil(t, res)
	})

	t.Run("valid JSON returns RawMessage", func(t *testing.T) {
		jsonStr := `{"type":"object","properties":{"foo":{"type":"string"}}}`
		res, err := decodeRawJSON(sql.NullString{Valid: true, String: jsonStr})
		require.NoError(t, err)
		assert.Equal(t, json.RawMessage(jsonStr), res)
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		res, err := decodeRawJSON(sql.NullString{Valid: true, String: `{"invalid":`})
		assert.Error(t, err)
		assert.EqualError(t, err, "invalid JSON payload")
		assert.Nil(t, res)
	})
}

func TestStorageHelpers_NullableText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected any
	}{
		{name: "empty string", input: "", expected: nil},
		{name: "whitespace only", input: "   \t\n  ", expected: nil},
		{name: "untrimmed string", input: "  hello world  ", expected: "hello world"},
		{name: "clean string", input: "my-id", expected: "my-id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, nullableText(tt.input))
		})
	}
}

func TestSQLiteZeroTimestampPrecision(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx))

	assertPrecision := func(t *testing.T, raw string, label string) {
		t.Helper()
		assert.Regexp(t, `^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$`, raw, "%s raw timestamp should have millisecond precision", label)
		parsed, err := time.Parse(DBTimeLayout, raw)
		require.NoError(t, err, "%s timestamp should parse with DBTimeLayout", label)
		assert.WithinDuration(t, time.Now().UTC(), parsed, 2*time.Minute, "%s timestamp should be recent", label)
	}

	// 1. Host
	host, err := store.CreateHost(ctx, Host{
		ID:        "host-zero-ts",
		UniqueKey: "host-zero-ts-key",
	})
	require.NoError(t, err)

	fetchedHost, err := store.GetHost(ctx, host.ID)
	require.NoError(t, err)
	assert.False(t, fetchedHost.CreatedAt.IsZero())

	var hostRawCreatedAt string
	err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT) FROM hosts WHERE id = ?", host.ID).Scan(&hostRawCreatedAt)
	require.NoError(t, err)
	assertPrecision(t, hostRawCreatedAt, "Host created_at")

	// 2. Schema Definition
	schemaDef, err := store.CreateSchemaDefinition(ctx, SchemaDefinition{
		ID:        "schema-zero-ts",
		UniqueKey: "schema-zero-ts-key",
		Schema:    json.RawMessage(`{"type":"object"}`),
	})
	require.NoError(t, err)

	fetchedDef, err := store.GetSchemaDefinition(ctx, schemaDef.ID)
	require.NoError(t, err)
	assert.False(t, fetchedDef.CreatedAt.IsZero())

	var schemaRawCreatedAt string
	err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT) FROM schema_definitions WHERE id = ?", schemaDef.ID).Scan(&schemaRawCreatedAt)
	require.NoError(t, err)
	assertPrecision(t, schemaRawCreatedAt, "SchemaDefinition created_at")

	// 3. Request
	req, err := store.CreateRequest(ctx, Request{
		ID:        "req-zero-ts",
		HostID:    host.ID,
		UniqueKey: "req-zero-ts-key",
		Payload:   map[string]any{"action": "test"},
		Mutable:   true,
	})
	require.NoError(t, err)

	fetchedReq, err := store.GetRequest(ctx, req.ID)
	require.NoError(t, err)
	assert.False(t, fetchedReq.CreatedAt.IsZero())
	assert.False(t, fetchedReq.UpdatedAt.IsZero())

	var reqRawCreatedAt, reqRawUpdatedAt string
	err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT), CAST(updated_at AS TEXT) FROM requests WHERE id = ?", req.ID).Scan(&reqRawCreatedAt, &reqRawUpdatedAt)
	require.NoError(t, err)
	assertPrecision(t, reqRawCreatedAt, "Request created_at")
	assertPrecision(t, reqRawUpdatedAt, "Request updated_at")

	// 4. Register
	reg, err := store.CreateRegister(ctx, Register{
		ID:        "reg-zero-ts",
		HostID:    host.ID,
		UniqueKey: "reg-zero-ts-key",
		Payload:   map[string]any{"key": "value"},
		Mutable:   true,
	})
	require.NoError(t, err)

	fetchedReg, err := store.GetRegister(ctx, reg.ID)
	require.NoError(t, err)
	assert.False(t, fetchedReg.CreatedAt.IsZero())
	assert.False(t, fetchedReg.UpdatedAt.IsZero())

	var regRawCreatedAt, regRawUpdatedAt string
	err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT), CAST(updated_at AS TEXT) FROM registers WHERE id = ?", reg.ID).Scan(&regRawCreatedAt, &regRawUpdatedAt)
	require.NoError(t, err)
	assertPrecision(t, regRawCreatedAt, "Register created_at")
	assertPrecision(t, regRawUpdatedAt, "Register updated_at")

	// 5. Grant (without version)
	grant1, err := store.CreateGrant(ctx, Grant{
		ID:        "grant-zero-ts-1",
		RequestID: req.ID,
		Payload:   map[string]any{"role": "reader"},
	})
	require.NoError(t, err)

	fetchedGrant1, err := store.GetGrant(ctx, grant1.ID)
	require.NoError(t, err)
	assert.False(t, fetchedGrant1.CreatedAt.IsZero())
	assert.False(t, fetchedGrant1.UpdatedAt.IsZero())

	var grant1RawCreatedAt, grant1RawUpdatedAt string
	err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT), CAST(updated_at AS TEXT) FROM grants WHERE id = ?", grant1.ID).Scan(&grant1RawCreatedAt, &grant1RawUpdatedAt)
	require.NoError(t, err)
	assertPrecision(t, grant1RawCreatedAt, "Grant1 created_at")
	assertPrecision(t, grant1RawUpdatedAt, "Grant1 updated_at")

	// 6. Grant (with version input, for a distinct request)
	req2, err := store.CreateRequest(ctx, Request{
		ID:        "req-zero-ts-2",
		HostID:    host.ID,
		UniqueKey: "req-zero-ts-key-2",
		Payload:   map[string]any{"action": "test2"},
	})
	require.NoError(t, err)

	grant2, err := store.CreateGrant(ctx, Grant{
		ID:             "grant-zero-ts-2",
		RequestID:      req2.ID,
		RequestVersion: 1,
		Payload:        map[string]any{"role": "writer"},
	})
	require.NoError(t, err)

	fetchedGrant2, err := store.GetGrant(ctx, grant2.ID)
	require.NoError(t, err)
	assert.False(t, fetchedGrant2.CreatedAt.IsZero())
	assert.False(t, fetchedGrant2.UpdatedAt.IsZero())

	var grant2RawCreatedAt, grant2RawUpdatedAt string
	err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT), CAST(updated_at AS TEXT) FROM grants WHERE id = ?", grant2.ID).Scan(&grant2RawCreatedAt, &grant2RawUpdatedAt)
	require.NoError(t, err)
	assertPrecision(t, grant2RawCreatedAt, "Grant2 created_at")
	assertPrecision(t, grant2RawUpdatedAt, "Grant2 updated_at")
}

func TestSQLiteResourceEventTimestampPrecision(t *testing.T) {
	t.Parallel()

	assertPrecision := func(t *testing.T, raw string, label string) {
		t.Helper()
		assert.Regexp(t, `^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$`, raw, "%s raw timestamp should have millisecond precision", label)
		parsed, err := time.Parse(DBTimeLayout, raw)
		require.NoError(t, err, "%s timestamp should parse with DBTimeLayout", label)
		assert.WithinDuration(t, time.Now().UTC(), parsed, 2*time.Minute, "%s timestamp should be recent", label)
	}

	t.Run("insertResourceEventSQLite zero timestamp fallback", func(t *testing.T) {
		ctx := context.Background()
		store, err := New(ctx, ":memory:")
		require.NoError(t, err)
		defer closeStore(t, store)
		require.NoError(t, store.Migrate(ctx))

		tx, err := store.DB().BeginTx(ctx, nil)
		require.NoError(t, err)
		defer rollbackTxTest(t, tx)

		err = insertResourceEventSQLite(ctx, tx, ResourceEventParams{
			ResourceType:  "request",
			ResourceID:    "res-zero-ts",
			EventType:     "created",
			NewPayloadMap: map[string]any{"hello": "world"},
		})
		require.NoError(t, err)
		require.NoError(t, tx.Commit())

		var rawCreatedAt string
		err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT) FROM resource_events WHERE resource_id = 'res-zero-ts'").Scan(&rawCreatedAt)
		require.NoError(t, err)
		assertPrecision(t, rawCreatedAt, "resource_event without timestamp fallback")
	})

	t.Run("insertResourceEventSQLite with deterministic time context", func(t *testing.T) {
		ctx := context.Background()
		store, err := New(ctx, ":memory:")
		require.NoError(t, err)
		defer closeStore(t, store)
		require.NoError(t, store.Migrate(ctx))

		detTime := time.Date(2026, 9, 10, 8, 15, 30, 456000000, time.UTC)
		ctxDet := WithDeterministicTime(ctx, detTime)

		tx, err := store.DB().BeginTx(ctxDet, nil)
		require.NoError(t, err)
		defer rollbackTxTest(t, tx)

		err = insertResourceEventSQLite(ctxDet, tx, ResourceEventParams{
			ResourceType:  "request",
			ResourceID:    "res-det-ts",
			EventType:     "created",
			NewPayloadMap: map[string]any{"hello": "world"},
		})
		require.NoError(t, err)
		require.NoError(t, tx.Commit())

		var rawCreatedAt string
		err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT) FROM resource_events WHERE resource_id = 'res-det-ts'").Scan(&rawCreatedAt)
		require.NoError(t, err)
		assert.Equal(t, FormatDBTime(detTime), rawCreatedAt)
	})

	t.Run("insertResourceEventSQLite with explicit timestamp param", func(t *testing.T) {
		ctx := context.Background()
		store, err := New(ctx, ":memory:")
		require.NoError(t, err)
		defer closeStore(t, store)
		require.NoError(t, store.Migrate(ctx))

		explicitTime := time.Date(2026, 9, 10, 14, 20, 10, 789000000, time.UTC)

		tx, err := store.DB().BeginTx(ctx, nil)
		require.NoError(t, err)
		defer rollbackTxTest(t, tx)

		err = insertResourceEventSQLite(ctx, tx, ResourceEventParams{
			ResourceType:  "request",
			ResourceID:    "res-explicit-ts",
			EventType:     "created",
			Timestamp:     explicitTime,
			NewPayloadMap: map[string]any{"hello": "world"},
		})
		require.NoError(t, err)
		require.NoError(t, tx.Commit())

		var rawCreatedAt string
		err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT) FROM resource_events WHERE resource_id = 'res-explicit-ts'").Scan(&rawCreatedAt)
		require.NoError(t, err)
		assert.Equal(t, FormatDBTime(explicitTime), rawCreatedAt)
	})

	t.Run("entity operations emit resource events with millisecond precision", func(t *testing.T) {
		ctx := context.Background()
		store, err := New(ctx, ":memory:")
		require.NoError(t, err)
		defer closeStore(t, store)
		require.NoError(t, store.Migrate(ctx))

		host, err := store.CreateHost(ctx, Host{ID: "host-events-test"})
		require.NoError(t, err)

		// CreateRequest
		req, err := store.CreateRequest(ctx, Request{
			ID:      "req-events-test",
			HostID:  host.ID,
			Payload: map[string]any{"stage": "init"},
			Labels:  map[string]string{"env": "test"},
			Mutable: true,
		})
		require.NoError(t, err)

		// UpdateRequest
		newPayload := map[string]any{"stage": "updated"}
		err = store.UpdateRequest(ctx, req.ID, &newPayload, nil)
		require.NoError(t, err)

		// CreateGrant
		grant, err := store.CreateGrant(ctx, Grant{
			ID:        "grant-events-test",
			RequestID: req.ID,
			Payload:   map[string]any{"granted": true},
		})
		require.NoError(t, err)

		// UpdateGrant
		err = store.UpdateGrant(ctx, grant.ID, map[string]any{"granted": true, "note": "extended"}, grant.RequestVersion)
		require.NoError(t, err)

		// DeleteGrant
		err = store.DeleteGrant(ctx, grant.ID)
		require.NoError(t, err)

		// DeleteRequest
		err = store.DeleteRequest(ctx, req.ID)
		require.NoError(t, err)

		// CreateRegister
		reg, err := store.CreateRegister(ctx, Register{
			ID:      "reg-events-test",
			HostID:  host.ID,
			Payload: map[string]any{"reg": "data"},
			Mutable: true,
		})
		require.NoError(t, err)

		// UpdateRegister
		regUpdated := map[string]any{"reg": "updated"}
		err = store.UpdateRegister(ctx, reg.ID, &regUpdated, nil)
		require.NoError(t, err)

		// DeleteRegister
		err = store.DeleteRegister(ctx, reg.ID)
		require.NoError(t, err)

		rows, err := store.DB().QueryContext(ctx, "SELECT id, resource_type, resource_id, event_type, CAST(created_at AS TEXT) FROM resource_events")
		require.NoError(t, err)
		defer func() { _ = rows.Close() }()

		eventCount := 0
		for rows.Next() {
			var eventID, resType, resID, eventType, rawCreatedAt string
			err := rows.Scan(&eventID, &resType, &resID, &eventType, &rawCreatedAt)
			require.NoError(t, err)
			assertPrecision(t, rawCreatedAt, fmt.Sprintf("event %s/%s:%s", resType, resID, eventType))
			eventCount++
		}
		require.NoError(t, rows.Err())
		assert.GreaterOrEqual(t, eventCount, 9, "all operations should have emitted resource events")
	})
}

func TestTranslateConstraintError(t *testing.T) {
	t.Parallel()

	// 1. Nil error
	assert.NoError(t, TranslateConstraintError(nil))

	// 2. Generic un-related error is passed through unchanged
	genericErr := errors.New("something went wrong")
	assert.Equal(t, genericErr, TranslateConstraintError(genericErr))

	// 3. PostgreSQL non-unique error code is passed through
	pgOtherErr := &pgconn.PgError{Code: "42P01", Message: "relation does not exist"}
	assert.Equal(t, pgOtherErr, TranslateConstraintError(pgOtherErr))

	// 4. Generic unique constraint violation (SQLite) -> ErrAlreadyExists
	sqliteUniqueErr := errors.New("UNIQUE constraint failed: hosts.id")
	assert.ErrorIs(t, TranslateConstraintError(sqliteUniqueErr), ErrAlreadyExists)
	assert.False(t, errors.Is(TranslateConstraintError(sqliteUniqueErr), ErrKeyAlreadyExists))

	// 5. Generic unique constraint violation (PostgreSQL) -> ErrAlreadyExists
	pgUniqueErr := &pgconn.PgError{Code: "23505", ConstraintName: "hosts_pkey"}
	assert.ErrorIs(t, TranslateConstraintError(pgUniqueErr), ErrAlreadyExists)
	assert.False(t, errors.Is(TranslateConstraintError(pgUniqueErr), ErrKeyAlreadyExists))

	// 6. Unique key constraint violation for requests (SQLite) -> ErrKeyAlreadyExists
	sqliteReqKeyErr := errors.New("UNIQUE constraint failed: requests.unique_key")
	assert.ErrorIs(t, TranslateConstraintError(sqliteReqKeyErr), ErrKeyAlreadyExists)

	// 7. Unique key constraint violation for requests (PostgreSQL) -> ErrKeyAlreadyExists
	pgReqKeyErr := &pgconn.PgError{Code: "23505", ConstraintName: "requests_unique_key_idx"}
	assert.ErrorIs(t, TranslateConstraintError(pgReqKeyErr), ErrKeyAlreadyExists)

	// 8. Unique key constraint violation for hosts (SQLite) -> ErrKeyAlreadyExists
	sqliteHostKeyErr := errors.New("UNIQUE constraint failed: hosts.unique_key")
	assert.ErrorIs(t, TranslateConstraintError(sqliteHostKeyErr), ErrKeyAlreadyExists)

	// 9. Unique key constraint violation for hosts (PostgreSQL) -> ErrKeyAlreadyExists
	pgHostKeyErr := &pgconn.PgError{Code: "23505", ConstraintName: "hosts_unique_key_idx"}
	assert.ErrorIs(t, TranslateConstraintError(pgHostKeyErr), ErrKeyAlreadyExists)

	// 10. Unique key constraint violation for registers (SQLite) -> ErrKeyAlreadyExists
	sqliteRegKeyErr := errors.New("UNIQUE constraint failed: registers.unique_key")
	assert.ErrorIs(t, TranslateConstraintError(sqliteRegKeyErr), ErrKeyAlreadyExists)

	// 11. Unique key constraint violation for registers (PostgreSQL) -> ErrKeyAlreadyExists
	pgRegKeyErr := &pgconn.PgError{Code: "23505", ConstraintName: "registers_unique_key_idx"}
	assert.ErrorIs(t, TranslateConstraintError(pgRegKeyErr), ErrKeyAlreadyExists)

	// 12. Unique key constraint violation for schema definitions (SQLite) -> ErrKeyAlreadyExists
	sqliteSchemaKeyErr := errors.New("UNIQUE constraint failed: schema_definitions.unique_key")
	assert.ErrorIs(t, TranslateConstraintError(sqliteSchemaKeyErr), ErrKeyAlreadyExists)

	// 13. Unique key constraint violation for schema definitions (PostgreSQL) -> ErrKeyAlreadyExists
	pgSchemaKeyErr := &pgconn.PgError{Code: "23505", ConstraintName: "schema_definitions_unique_key_idx"}
	assert.ErrorIs(t, TranslateConstraintError(pgSchemaKeyErr), ErrKeyAlreadyExists)

	// 14. SQLite index-name formatted constraint errors -> ErrKeyAlreadyExists
	sqliteReqIndexErr := errors.New("UNIQUE constraint failed: index requests_unique_key_idx")
	assert.ErrorIs(t, TranslateConstraintError(sqliteReqIndexErr), ErrKeyAlreadyExists)

	sqliteRegIndexErr := errors.New("UNIQUE constraint failed: index registers_unique_key_idx")
	assert.ErrorIs(t, TranslateConstraintError(sqliteRegIndexErr), ErrKeyAlreadyExists)

	sqliteHostIndexErr := errors.New("UNIQUE constraint failed: index hosts_unique_key_idx")
	assert.ErrorIs(t, TranslateConstraintError(sqliteHostIndexErr), ErrKeyAlreadyExists)

	sqliteSchemaIndexErr := errors.New("UNIQUE constraint failed: index schema_definitions_unique_key_idx")
	assert.ErrorIs(t, TranslateConstraintError(sqliteSchemaIndexErr), ErrKeyAlreadyExists)
}

func TestSQLiteDDLMillisecondPrecisionDefaults(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	defer closeStore(t, store)

	require.NoError(t, store.Migrate(ctx))

	tables := []string{
		"hosts",
		"requests",
		"schema_definitions",
		"registers",
		"grants",
		"resource_events",
	}

	// 1. Verify raw DDL statements in sqlite_master
	for _, tbl := range tables {
		var ddl string
		err := store.DB().QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name = ?", tbl).Scan(&ddl)
		require.NoError(t, err, "fetch DDL for table %s", tbl)

		assert.NotContains(t, ddl, "DEFAULT CURRENT_TIMESTAMP", "table %s DDL should not have DEFAULT CURRENT_TIMESTAMP", tbl)
		assert.Contains(t, ddl, "DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))", "table %s DDL should declare millisecond precision default", tbl)
	}

	assertPrecision := func(t *testing.T, raw string, label string) {
		t.Helper()
		assert.Regexp(t, `^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$`, raw, "%s raw timestamp should have millisecond precision", label)
		parsed, err := time.Parse(DBTimeLayout, raw)
		require.NoError(t, err, "%s timestamp should parse with DBTimeLayout", label)
		assert.WithinDuration(t, time.Now().UTC(), parsed, 2*time.Minute, "%s timestamp should be recent", label)
	}

	// 2. Verify default insertions (raw INSERT omitting created_at and updated_at)
	// a. hosts
	_, err = store.DB().ExecContext(ctx, "INSERT INTO hosts (id) VALUES (?)", "h-default-insert")
	require.NoError(t, err)
	var hostCreated string
	err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT) FROM hosts WHERE id = ?", "h-default-insert").Scan(&hostCreated)
	require.NoError(t, err)
	assertPrecision(t, hostCreated, "hosts.created_at default insert")

	// b. schema_definitions
	_, err = store.DB().ExecContext(ctx, "INSERT INTO schema_definitions (id, schema) VALUES (?, ?)", "s-default-insert", `{}`)
	require.NoError(t, err)
	var schemaCreated string
	err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT) FROM schema_definitions WHERE id = ?", "s-default-insert").Scan(&schemaCreated)
	require.NoError(t, err)
	assertPrecision(t, schemaCreated, "schema_definitions.created_at default insert")

	// c. requests
	_, err = store.DB().ExecContext(ctx, "INSERT INTO requests (id, host_id) VALUES (?, ?)", "r-default-insert", "h-default-insert")
	require.NoError(t, err)
	var reqCreated, reqUpdated string
	err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT), CAST(updated_at AS TEXT) FROM requests WHERE id = ?", "r-default-insert").Scan(&reqCreated, &reqUpdated)
	require.NoError(t, err)
	assertPrecision(t, reqCreated, "requests.created_at default insert")
	assertPrecision(t, reqUpdated, "requests.updated_at default insert")

	// d. registers
	_, err = store.DB().ExecContext(ctx, "INSERT INTO registers (id, host_id) VALUES (?, ?)", "reg-default-insert", "h-default-insert")
	require.NoError(t, err)
	var regCreated, regUpdated string
	err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT), CAST(updated_at AS TEXT) FROM registers WHERE id = ?", "reg-default-insert").Scan(&regCreated, &regUpdated)
	require.NoError(t, err)
	assertPrecision(t, regCreated, "registers.created_at default insert")
	assertPrecision(t, regUpdated, "registers.updated_at default insert")

	// e. grants
	_, err = store.DB().ExecContext(ctx, "INSERT INTO grants (id, request_id) VALUES (?, ?)", "g-default-insert", "r-default-insert")
	require.NoError(t, err)
	var grantCreated, grantUpdated string
	err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT), CAST(updated_at AS TEXT) FROM grants WHERE id = ?", "g-default-insert").Scan(&grantCreated, &grantUpdated)
	require.NoError(t, err)
	assertPrecision(t, grantCreated, "grants.created_at default insert")
	assertPrecision(t, grantUpdated, "grants.updated_at default insert")

	// f. resource_events
	_, err = store.DB().ExecContext(ctx, "INSERT INTO resource_events (id, resource_type, resource_id, event_type) VALUES (?, ?, ?, ?)", "evt-default-insert", "request", "r-default-insert", "created")
	require.NoError(t, err)
	var evtCreated string
	err = store.DB().QueryRowContext(ctx, "SELECT CAST(created_at AS TEXT) FROM resource_events WHERE id = ?", "evt-default-insert").Scan(&evtCreated)
	require.NoError(t, err)
	assertPrecision(t, evtCreated, "resource_events.created_at default insert")
}

func TestQuoteIdent(t *testing.T) {
	t.Parallel()

	assert.Equal(t, `"public"`, QuoteIdent("public"))
	assert.Equal(t, `"my_schema"`, QuoteIdent("my_schema"))
	assert.Equal(t, `"schema""with""quotes"`, QuoteIdent(`schema"with"quotes`))
	assert.Equal(t, `""`, QuoteIdent(""))
}

func TestDeterministicResourceEventID(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 3, 15, 10, 30, 0, 0, time.UTC)
	params := ResourceEventParams{
		ResourceType: "request",
		ResourceID:   "req-123",
		EventType:    "create",
	}
	oldPayloadStr := `{"a": 1}`
	newPayloadStr := `{"a": 2}`
	oldLabelsStr := `{"env": "dev"}`
	newLabelsStr := `{"env": "prod"}`

	oldPayload := &oldPayloadStr
	newPayload := &newPayloadStr
	oldLabels := &oldLabelsStr
	newLabels := &newLabelsStr

	id1 := DeterministicResourceEventID(params, ts, oldPayload, newPayload, oldLabels, newLabels)
	id2 := DeterministicResourceEventID(params, ts, oldPayload, newPayload, oldLabels, newLabels)

	// Verify determinism
	assert.Equal(t, id1, id2)

	// Verify valid UUID format and version 5 (SHA-1 namespace UUID)
	parsedUUID, err := uuid.Parse(id1)
	require.NoError(t, err)
	assert.Equal(t, uuid.Version(5), parsedUUID.Version())

	// Verify manual computation matches
	expectedHashInput := fmt.Sprintf("%s:%s:%s:%d:%s:%s:%s:%s",
		params.ResourceType,
		params.ResourceID,
		params.EventType,
		ts.UnixNano(),
		derefString(oldPayload),
		derefString(newPayload),
		derefString(oldLabels),
		derefString(newLabels),
	)
	expectedID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(expectedHashInput)).String()
	assert.Equal(t, expectedID, id1)

	// Verify nil inputs determinism and validity
	idNil1 := DeterministicResourceEventID(params, ts, nil, nil, nil, nil)
	idNil2 := DeterministicResourceEventID(params, ts, nil, nil, nil, nil)
	assert.Equal(t, idNil1, idNil2)
	assert.NotEqual(t, id1, idNil1)
	parsedNilUUID, err := uuid.Parse(idNil1)
	require.NoError(t, err)
	assert.Equal(t, uuid.Version(5), parsedNilUUID.Version())

	// Verify changing any argument changes the resulting UUID
	diffTime := ts.Add(time.Second)
	assert.NotEqual(t, id1, DeterministicResourceEventID(params, diffTime, oldPayload, newPayload, oldLabels, newLabels))

	diffParams := params
	diffParams.ResourceID = "req-456"
	assert.NotEqual(t, id1, DeterministicResourceEventID(diffParams, ts, oldPayload, newPayload, oldLabels, newLabels))

	assert.NotEqual(t, id1, DeterministicResourceEventID(params, ts, nil, newPayload, oldLabels, newLabels))
	assert.NotEqual(t, id1, DeterministicResourceEventID(params, ts, oldPayload, nil, oldLabels, newLabels))
	assert.NotEqual(t, id1, DeterministicResourceEventID(params, ts, oldPayload, newPayload, nil, newLabels))
	assert.NotEqual(t, id1, DeterministicResourceEventID(params, ts, oldPayload, newPayload, oldLabels, nil))

	diffStr := "different"
	assert.NotEqual(t, id1, DeterministicResourceEventID(params, ts, &diffStr, newPayload, oldLabels, newLabels))
	assert.NotEqual(t, id1, DeterministicResourceEventID(params, ts, oldPayload, &diffStr, oldLabels, newLabels))
	assert.NotEqual(t, id1, DeterministicResourceEventID(params, ts, oldPayload, newPayload, &diffStr, newLabels))
	assert.NotEqual(t, id1, DeterministicResourceEventID(params, ts, oldPayload, newPayload, oldLabels, &diffStr))

	// Verify millisecond truncation determinism: timestamps with sub-millisecond nanoseconds
	// produce the exact same UUID as their millisecond-truncated versions.
	tsWithSubMs1 := ts.Add(123*time.Millisecond + 456*time.Microsecond + 789*time.Nanosecond)
	tsWithSubMs2 := ts.Add(123*time.Millisecond + 999*time.Microsecond + 999*time.Nanosecond)
	tsTruncatedMs := ts.Add(123 * time.Millisecond)

	idTruncated := DeterministicResourceEventID(params, tsTruncatedMs, oldPayload, newPayload, oldLabels, newLabels)
	idSubMs1 := DeterministicResourceEventID(params, tsWithSubMs1, oldPayload, newPayload, oldLabels, newLabels)
	idSubMs2 := DeterministicResourceEventID(params, tsWithSubMs2, oldPayload, newPayload, oldLabels, newLabels)

	assert.Equal(t, idTruncated, idSubMs1)
	assert.Equal(t, idTruncated, idSubMs2)

	// But a different millisecond produces a different UUID
	tsDiffMs := ts.Add(124 * time.Millisecond)
	assert.NotEqual(t, idTruncated, DeterministicResourceEventID(params, tsDiffMs, oldPayload, newPayload, oldLabels, newLabels))
}

func TestSupportsSignatureBundling(t *testing.T) {
	t.Parallel()

	sq, err := New(context.Background(), ":memory:")
	require.NoError(t, err)
	defer closeStore(t, sq)

	bundler, ok := sq.(interface{ SupportsSignatureBundling() bool })
	require.True(t, ok, "sqliteStore must implement SupportsSignatureBundling")
	assert.True(t, bundler.SupportsSignatureBundling())

	pg := &postgresStore{}
	assert.True(t, pg.SupportsSignatureBundling())
}
