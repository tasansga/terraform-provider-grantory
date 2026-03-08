//go:build postgres

package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPostgresTestStore(t *testing.T) (*postgresStore, func()) {
	t.Helper()

	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set")
	}

	ctx := context.Background()
	store, err := NewPostgres(ctx, dsn)
	require.NoError(t, err)

	pgStore, ok := store.(*postgresStore)
	require.True(t, ok, "expected postgres store implementation")

	schemaName := fmt.Sprintf("inttest_%d", time.Now().UnixNano())
	pgStore.SetNamespace(schemaName)

	_, err = pgStore.db.ExecContext(ctx, fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, quoteIdent(schemaName)))
	require.NoError(t, err)

	require.NoError(t, pgStore.Migrate(ctx))

	cleanup := func() {
		_, _ = pgStore.db.ExecContext(ctx, fmt.Sprintf(`DROP SCHEMA IF EXISTS %s CASCADE`, quoteIdent(schemaName)))
		_ = pgStore.Close()
	}
	return pgStore, cleanup
}

func TestPostgresStoreCRUDAndFilters(t *testing.T) {
	store, cleanup := newPostgresTestStore(t)
	defer cleanup()

	ctx := context.Background()

	host, err := store.CreateHost(ctx, Host{
		UniqueKey: "host-unique",
		Labels:    map[string]string{"env": "inttest"},
	})
	require.NoError(t, err)

	require.NoError(t, store.UpdateHostLabels(ctx, host.ID, map[string]string{"env": "inttest", "team": "storage"}))
	loadedHost, err := store.GetHost(ctx, host.ID)
	require.NoError(t, err)
	assert.Equal(t, "storage", loadedHost.Labels["team"])

	hosts, err := store.ListHosts(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, hosts)

	def, err := store.CreateSchemaDefinition(ctx, SchemaDefinition{
		Schema: json.RawMessage(`{"type":"object"}`),
	})
	require.NoError(t, err)

	req, err := store.CreateRequest(ctx, Request{
		HostID:                    host.ID,
		RequestSchemaDefinitionID: def.ID,
		GrantSchemaDefinitionID:   def.ID,
		UniqueKey:                 "request-unique",
		Payload:                   map[string]any{"name": "db"},
		Labels:                    map[string]string{"pipeline": "inttest"},
	})
	require.NoError(t, err)

	grant, err := store.CreateGrant(ctx, Grant{
		RequestID: req.ID,
		Payload:   map[string]any{"detail": "ok"},
	})
	require.NoError(t, err)

	grants, err := store.ListGrants(ctx)
	require.NoError(t, err)
	assert.Len(t, grants, 1)

	foundGrant, found, err := store.GetGrantForRequest(ctx, req.ID)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, grant.ID, foundGrant.ID)

	reg, err := store.CreateRegister(ctx, Register{
		HostID:             host.ID,
		SchemaDefinitionID: def.ID,
		UniqueKey:          "register-unique",
		Payload:            map[string]any{"source": "inttest"},
		Labels:             map[string]string{"pipeline": "inttest"},
	})
	require.NoError(t, err)

	listedReqs, err := store.ListRequests(ctx, &RequestListFilters{
		HasGrant:   boolPtr(true),
		Labels:     map[string]string{"pipeline": "inttest"},
		HostLabels: map[string]string{"env": "inttest"},
	})
	require.NoError(t, err)
	assert.Len(t, listedReqs, 1)

	listedRegs, err := store.ListRegisters(ctx, &RegisterListFilters{
		Labels:     map[string]string{"pipeline": "inttest"},
		HostLabels: map[string]string{"env": "inttest"},
	})
	require.NoError(t, err)
	assert.Len(t, listedRegs, 1)
	assert.Equal(t, reg.ID, listedRegs[0].ID)
}

func TestPostgresUniqueKeyConflicts(t *testing.T) {
	store, cleanup := newPostgresTestStore(t)
	defer cleanup()

	ctx := context.Background()

	host, err := store.CreateHost(ctx, Host{UniqueKey: "host-unique"})
	require.NoError(t, err)

	_, err = store.CreateRequest(ctx, Request{
		HostID:    host.ID,
		UniqueKey: "request-unique",
	})
	require.NoError(t, err)

	_, err = store.CreateRequest(ctx, Request{
		HostID:    host.ID,
		UniqueKey: "request-unique",
	})
	assert.ErrorIs(t, err, ErrRequestUniqueKeyConflict)

	_, err = store.CreateRegister(ctx, Register{
		HostID:    host.ID,
		UniqueKey: "register-unique",
	})
	require.NoError(t, err)

	_, err = store.CreateRegister(ctx, Register{
		HostID:    host.ID,
		UniqueKey: "register-unique",
	})
	assert.ErrorIs(t, err, ErrRegisterUniqueKeyConflict)
}

func TestPostgresDeleteSchemaDefinitionNullsReferences(t *testing.T) {
	store, cleanup := newPostgresTestStore(t)
	defer cleanup()

	ctx := context.Background()

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)

	def, err := store.CreateSchemaDefinition(ctx, SchemaDefinition{
		Schema: json.RawMessage(`{"type":"object"}`),
	})
	require.NoError(t, err)

	req, err := store.CreateRequest(ctx, Request{
		HostID:                    host.ID,
		RequestSchemaDefinitionID: def.ID,
		GrantSchemaDefinitionID:   def.ID,
		Payload:                   map[string]any{"name": "db"},
	})
	require.NoError(t, err)

	reg, err := store.CreateRegister(ctx, Register{
		HostID:             host.ID,
		SchemaDefinitionID: def.ID,
		Payload:            map[string]any{"source": "inttest"},
	})
	require.NoError(t, err)

	require.NoError(t, store.DeleteSchemaDefinition(ctx, def.ID))

	reloadedReq, err := store.GetRequest(ctx, req.ID)
	require.NoError(t, err)
	assert.Empty(t, reloadedReq.RequestSchemaDefinitionID)
	assert.Empty(t, reloadedReq.GrantSchemaDefinitionID)

	reloadedReg, err := store.GetRegister(ctx, reg.ID)
	require.NoError(t, err)
	assert.Empty(t, reloadedReg.SchemaDefinitionID)
}

func boolPtr(value bool) *bool {
	return &value
}
