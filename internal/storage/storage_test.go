package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func closeStore(t *testing.T, store *Store) {
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

	tables := []string{"hosts", "requests", "registers", "grants"}
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
		HostID: host.ID,
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
	assert.Equal(t, "example", loaded.Payload["name"], "loaded request data")
	assert.Equal(t, "test", loaded.Labels["env"], "loaded request labels")
	assert.False(t, loaded.HasGrant, "new requests should not yet have grants")

	grant := Grant{
		RequestID: createdRequest.ID,
		Payload:   []byte("payload"),
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
		HostID: host.ID,
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
		Payload:   []byte("secret"),
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
	if _, err := store.CreateGrant(ctx, Grant{RequestID: reqWithGrant.ID, Payload: []byte("secret")}); err != nil {
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

	if _, err := store.CreateGrant(ctx, Grant{RequestID: req1.ID, Payload: []byte("secret")}); err != nil {
		assert.NoError(t, err, "CreateGrant() error")
		t.FailNow()
	}
	if _, err := store.CreateGrant(ctx, Grant{RequestID: req2.ID, Payload: []byte("secret")}); err != nil {
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

	store := &Store{}
	store.SetNamespace("  custom  ")
	assert.Equal(t, "custom", store.namespace, "namespace should be trimmed")
	store.SetNamespace("  ")
	assert.Equal(t, unknownNamespace, store.namespace, "empty namespace should default to unknown")
}

func TestMigrateRequiresStore(t *testing.T) {
	t.Parallel()

	var store *Store
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

	var store *Store
	_, err := store.CreateHost(context.Background(), Host{})
	assert.Error(t, err, "create host should fail on nil store")
}

func TestCreateRequestFailsWhenStoreNil(t *testing.T) {
	t.Parallel()

	var store *Store
	_, err := store.CreateRequest(context.Background(), Request{HostID: "any"})
	assert.Error(t, err, "create request should fail on nil store")
}

func TestCreateRegisterFailsWhenStoreNil(t *testing.T) {
	t.Parallel()

	var store *Store
	_, err := store.CreateRegister(context.Background(), Register{HostID: "any"})
	assert.Error(t, err, "create register should fail on nil store")
}

func TestCreateGrantFailsWhenStoreNil(t *testing.T) {
	t.Parallel()

	var store *Store
	_, err := store.CreateGrant(context.Background(), Grant{RequestID: "any", Payload: []byte("p")})
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
	grant, err := store.CreateGrant(ctx, Grant{RequestID: req.ID, Payload: []byte("p")})
	require.NoError(t, err)

	require.NoError(t, store.Close())

	_, err = store.CreateHost(ctx, Host{})
	assert.Error(t, err)
	_, err = store.CreateRequest(ctx, Request{HostID: host.ID})
	assert.Error(t, err)
	_, err = store.CreateRegister(ctx, Register{HostID: host.ID})
	assert.Error(t, err)
	_, err = store.CreateGrant(ctx, Grant{RequestID: req.ID, Payload: []byte("p")})
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

	tests := []struct {
		name string
		fn   func(context.Context, *sql.Tx) error
	}{
		{"hosts", store.ensureHostsTable},
		{"requests", store.ensureRequestsTable},
		{"registers", store.ensureRegistersTable},
		{"grants", store.ensureGrantsTable},
		{"host_labels", store.ensureHostLabelsTable},
		{"request_labels", store.ensureRequestLabelsTable},
		{"register_labels", store.ensureRegisterLabelsTable},
		{"grant_labels", store.ensureGrantLabelsTable},
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

func TestNamespaceForLogHandlesNilAndTrim(t *testing.T) {
	t.Parallel()

	var store *Store
	assert.Equal(t, unknownNamespace, store.namespaceForLog(), "nil store should return unknown namespace")

	store = &Store{}
	store.SetNamespace("  custom  ")
	assert.Equal(t, "custom", store.namespaceForLog(), "should trim namespace")
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

	var store *Store
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

	assert.NoError(t, store.ensureRequestExists(ctx, req.ID))
	assert.ErrorIs(t, store.ensureRequestExists(ctx, "missing"), ErrReferencedRequestNotFound)
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

func TestGetLatestGrantForRequest(t *testing.T) {
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

	grant, found, err := store.GetLatestGrantForRequest(ctx, req.ID)
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, Grant{}, grant)

	payload := []byte("secret")
	createdGrant, err := store.CreateGrant(ctx, Grant{RequestID: req.ID, Payload: payload})
	assert.NoError(t, err)

	latest, found, err := store.GetLatestGrantForRequest(ctx, req.ID)
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

	grant, err := store.CreateGrant(ctx, Grant{RequestID: req.ID, Payload: []byte("payload")})
	require.NoError(t, err)

	require.NoError(t, store.Close())

	_, err = store.CreateHost(ctx, Host{})
	assert.Error(t, err)
	_, err = store.CreateRequest(ctx, Request{HostID: host.ID})
	assert.Error(t, err)
	_, err = store.CreateRegister(ctx, Register{HostID: host.ID})
	assert.Error(t, err)
	_, err = store.CreateGrant(ctx, Grant{RequestID: req.ID, Payload: []byte("payload")})
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

	first := Grant{RequestID: req.ID, Payload: []byte("secret")}
	if _, err := store.CreateGrant(ctx, first); err != nil {
		assert.NoError(t, err, "CreateGrant() error")
		t.FailNow()
	}
	second := Grant{RequestID: req.ID, Payload: []byte("secret")}
	_, err = store.CreateGrant(ctx, second)
	assert.ErrorIs(t, err, ErrGrantAlreadyExists, "expected duplicate request grant to fail")
}

func TestCreateHostIgnoresSuppliedID(t *testing.T) {
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

	malicious := "malicious-host"
	host, err := store.CreateHost(ctx, Host{ID: malicious})
	if err != nil {
		assert.NoError(t, err, "CreateHost() error")
		t.FailNow()
	}
	assert.NotEqual(t, malicious, host.ID, "expected generated ID instead of supplied one")
	assert.NotEmpty(t, host.ID, "generated ID should be populated")
	_, err = store.GetHost(ctx, malicious)
	assert.ErrorIs(t, err, ErrHostNotFound, "malicious ID should not resolve")
}

func TestCreateRequestIgnoresSuppliedID(t *testing.T) {
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

	malicious := "malicious-request"
	request, err := store.CreateRequest(ctx, Request{
		ID:     malicious,
		HostID: host.ID,
	})
	if err != nil {
		assert.NoError(t, err, "CreateRequest() error")
		t.FailNow()
	}
	assert.NotEqual(t, malicious, request.ID, "expected generated ID instead of supplied one")
	assert.NotEmpty(t, request.ID, "generated ID should be populated")
	_, err = store.GetRequest(ctx, malicious)
	assert.ErrorIs(t, err, ErrRequestNotFound, "malicious ID should not resolve")
}

func TestCreateRegisterIgnoresSuppliedID(t *testing.T) {
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

	malicious := "malicious-register"
	register, err := store.CreateRegister(ctx, Register{
		ID:     malicious,
		HostID: host.ID,
	})
	if err != nil {
		assert.NoError(t, err, "CreateRegister() error")
		t.FailNow()
	}
	assert.NotEqual(t, malicious, register.ID, "expected generated ID instead of supplied one")
	assert.NotEmpty(t, register.ID, "generated ID should be populated")
	_, err = store.GetRegister(ctx, malicious)
	assert.ErrorIs(t, err, ErrRegisterNotFound, "malicious ID should not resolve")
}

func TestCreateGrantIgnoresSuppliedID(t *testing.T) {
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

	request, err := store.CreateRequest(ctx, Request{HostID: host.ID})
	if err != nil {
		assert.NoError(t, err, "CreateRequest() error")
		t.FailNow()
	}

	malicious := "malicious-grant"
	grant, err := store.CreateGrant(ctx, Grant{
		ID:        malicious,
		RequestID: request.ID,
		Payload:   []byte("payload"),
	})
	if err != nil {
		assert.NoError(t, err, "CreateGrant() error")
		t.FailNow()
	}
	assert.NotEqual(t, malicious, grant.ID, "expected generated ID instead of supplied one")
	assert.NotEmpty(t, grant.ID, "generated ID should be populated")
	_, err = store.GetGrant(ctx, malicious)
	assert.ErrorIs(t, err, ErrGrantNotFound, "malicious ID should not resolve")
}
