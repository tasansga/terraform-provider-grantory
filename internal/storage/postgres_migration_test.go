//go:build postgres

package storage

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgresMigrateSchemaDefinitionsAndRequests(t *testing.T) {
	t.Parallel()

	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set")
	}

	ctx := context.Background()
	store, err := NewPostgres(ctx, dsn)
	require.NoError(t, err)
	defer closeStore(t, store)

	pgStore, ok := store.(*postgresStore)
	require.True(t, ok, "expected postgres store implementation")

	schemaName := fmt.Sprintf("inttest_%d", time.Now().UnixNano()+int64(rand.Intn(1000)))
	pgStore.SetNamespace(schemaName)

	_, err = pgStore.db.ExecContext(ctx, fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, quoteIdent(schemaName)))
	require.NoError(t, err)
	defer func() {
		_, _ = pgStore.db.ExecContext(ctx, fmt.Sprintf(`DROP SCHEMA IF EXISTS %s CASCADE`, quoteIdent(schemaName)))
	}()

	_, err = pgStore.db.ExecContext(ctx, fmt.Sprintf(`
CREATE TABLE %s (
	id TEXT PRIMARY KEY,
	request_schema JSONB,
	grant_schema JSONB,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE %s (
	id TEXT PRIMARY KEY,
	unique_key TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE %s (
	id TEXT PRIMARY KEY,
	host_id TEXT NOT NULL,
	schema_definition_id TEXT,
	unique_key TEXT,
	data JSONB,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	FOREIGN KEY(host_id) REFERENCES %s(id) ON DELETE CASCADE,
	FOREIGN KEY(schema_definition_id) REFERENCES %s(id) ON DELETE SET NULL
);
`, pgStore.table("schema_definitions"), pgStore.table("hosts"), pgStore.table("requests"), pgStore.table("hosts"), pgStore.table("schema_definitions")))
	require.NoError(t, err)

	defID := "schema-legacy"
	hostID := "host-legacy"
	reqID := "request-legacy"
	requestSchema := `{"type":"object"}`
	grantSchema := `{"type":"object","required":["detail"]}`

	_, err = pgStore.db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (id, request_schema, grant_schema) VALUES ($1, $2, $3)`, pgStore.table("schema_definitions")), defID, requestSchema, grantSchema)
	require.NoError(t, err)
	_, err = pgStore.db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (id) VALUES ($1)`, pgStore.table("hosts")), hostID)
	require.NoError(t, err)
	_, err = pgStore.db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (id, host_id, schema_definition_id) VALUES ($1, $2, $3)`, pgStore.table("requests")), reqID, hostID, defID)
	require.NoError(t, err)

	require.NoError(t, pgStore.Migrate(ctx))

	var schemaValue []byte
	err = pgStore.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT schema FROM %s WHERE id = $1`, pgStore.table("schema_definitions")), defID).Scan(&schemaValue)
	require.NoError(t, err)
	assert.JSONEq(t, requestSchema, string(schemaValue), "schema should backfill from request_schema")

	var requestSchemaID, grantSchemaID sql.NullString
	err = pgStore.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT request_schema_definition_id, grant_schema_definition_id FROM %s WHERE id = $1`, pgStore.table("requests")), reqID).Scan(&requestSchemaID, &grantSchemaID)
	require.NoError(t, err)
	require.True(t, requestSchemaID.Valid)
	require.True(t, grantSchemaID.Valid)
	assert.Equal(t, defID, requestSchemaID.String)

	var grantDefID string
	err = pgStore.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT id FROM %s WHERE id <> $1 AND schema = $2`, pgStore.table("schema_definitions")), defID, grantSchema).Scan(&grantDefID)
	require.NoError(t, err)
	assert.Equal(t, grantDefID, grantSchemaID.String)
}
