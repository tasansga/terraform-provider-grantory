package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/sirupsen/logrus"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// postgresStore wraps a postgres database connection for the provisioner server.
type postgresStore struct {
	db        *sql.DB
	namespace string
	schema    string
}

// NewPostgres opens a postgres connection using the provided DSN.
func NewPostgres(ctx context.Context, dsn string) (Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres database: %w", err)
	}

	// A small pool is fine; per-namespace stores keep separate connections.
	db.SetMaxOpenConns(5)

	if err := db.PingContext(ctx); err != nil {
		if cerr := db.Close(); cerr != nil {
			logrus.WithError(cerr).Warn("close postgres database after ping failure")
		}
		return nil, fmt.Errorf("ping postgres database: %w", err)
	}

	return &postgresStore{db: db, namespace: unknownNamespace}, nil
}

// SetNamespace records the namespace associated with this store for logging and schema usage.
func (s *postgresStore) SetNamespace(namespace string) {
	if s == nil {
		return
	}
	if ns := strings.TrimSpace(namespace); ns != "" {
		s.namespace = ns
		s.schema = ns
		return
	}
	s.namespace = unknownNamespace
	s.schema = ""
}

func (s *postgresStore) namespaceForLog() string {
	if s == nil {
		return unknownNamespace
	}
	if ns := strings.TrimSpace(s.namespace); ns != "" {
		return ns
	}
	return unknownNamespace
}

func (s *postgresStore) logDBOperation(table, operation string, params logrus.Fields) {
	if s == nil {
		return
	}
	fields := logrus.Fields{
		"namespace": s.namespaceForLog(),
		"table":     table,
		"operation": operation,
	}
	for key, value := range params {
		fields[key] = value
	}
	logrus.WithFields(fields).Info("database operation")
}

// Close tears down the underlying database connection.
func (s *postgresStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// DB exposes the underlying *sql.DB for helpers and tests.
func (s *postgresStore) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

func (s *postgresStore) ensureSchema(ctx context.Context, tx *sql.Tx) error {
	if s == nil || s.schema == "" {
		return fmt.Errorf("namespace is required")
	}
	stmt := fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, quoteIdent(s.schema))
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	return nil
}

// Migrate ensures the schema for hosts, requests, registers, and grants exists.
func (s *postgresStore) Migrate(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}
	if strings.TrimSpace(s.schema) == "" {
		return fmt.Errorf("namespace is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	if err := s.ensureSchema(ctx, tx); err != nil {
		rollbackTx(tx, "rollback migration transaction")
		return err
	}

	tasks := []struct {
		name string
		fn   func(context.Context, *sql.Tx) error
	}{
		{"hosts", s.ensureHostsTable},
		{"schema definitions", s.ensureSchemaDefinitionsTable},
		{"requests", s.ensureRequestsTable},
		{"registers", s.ensureRegistersTable},
		{"grants", s.ensureGrantsTable},
		{"host labels", s.ensureHostLabelsTable},
		{"request labels", s.ensureRequestLabelsTable},
		{"register labels", s.ensureRegisterLabelsTable},
		{"resource events", s.ensureResourceEventsTable},
		{"grant labels", s.ensureGrantLabelsTable},
		{"schema definition labels", s.ensureSchemaDefinitionLabelsTable},
	}

	for _, task := range tasks {
		if err := task.fn(ctx, tx); err != nil {
			rollbackTx(tx, "rollback migration transaction")
			return fmt.Errorf("ensure %s schema: %w", task.name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}

	return nil
}

func (s *postgresStore) table(name string) string {
	return fmt.Sprintf("%s.%s", quoteIdent(s.schema), quoteIdent(name))
}

func (s *postgresStore) ensureHostsTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	id TEXT PRIMARY KEY,
	unique_key TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`, s.table("hosts"))
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create hosts table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS unique_key TEXT`, s.table("hosts"))); err != nil {
		return fmt.Errorf("add hosts unique_key column: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS hosts_unique_key_idx ON %s (unique_key) WHERE unique_key IS NOT NULL`, s.table("hosts"))); err != nil {
		return fmt.Errorf("create hosts unique_key index: %w", err)
	}
	return nil
}

func (s *postgresStore) ensureRequestsTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	id TEXT PRIMARY KEY,
	host_id TEXT NOT NULL,
	request_schema_definition_id TEXT,
	grant_schema_definition_id TEXT,
	unique_key TEXT,
	data JSONB,
	mutable BOOLEAN NOT NULL DEFAULT FALSE,
	version INTEGER NOT NULL DEFAULT 1,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	FOREIGN KEY(host_id) REFERENCES %s(id) ON DELETE CASCADE,
	FOREIGN KEY(request_schema_definition_id) REFERENCES %s(id) ON DELETE SET NULL,
	FOREIGN KEY(grant_schema_definition_id) REFERENCES %s(id) ON DELETE SET NULL
)`, s.table("requests"), s.table("hosts"), s.table("schema_definitions"), s.table("schema_definitions"))
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create requests table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS request_schema_definition_id TEXT`, s.table("requests"))); err != nil {
		return fmt.Errorf("add requests request_schema_definition_id column: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS grant_schema_definition_id TEXT`, s.table("requests"))); err != nil {
		return fmt.Errorf("add requests grant_schema_definition_id column: %w", err)
	}
	constraintStmt := fmt.Sprintf(`
DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1
		FROM pg_constraint
		WHERE conname = 'requests_request_schema_definition_fk'
			AND conrelid = '%s'::regclass
	) THEN
		ALTER TABLE %s
			ADD CONSTRAINT requests_request_schema_definition_fk
			FOREIGN KEY (request_schema_definition_id)
			REFERENCES %s(id)
			ON DELETE SET NULL;
	END IF;
END $$;`, s.table("requests"), s.table("requests"), s.table("schema_definitions"))
	if _, err := tx.ExecContext(ctx, constraintStmt); err != nil {
		return fmt.Errorf("add requests request_schema_definition_id foreign key: %w", err)
	}
	constraintStmt = fmt.Sprintf(`
DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1
		FROM pg_constraint
		WHERE conname = 'requests_grant_schema_definition_fk'
			AND conrelid = '%s'::regclass
	) THEN
		ALTER TABLE %s
			ADD CONSTRAINT requests_grant_schema_definition_fk
			FOREIGN KEY (grant_schema_definition_id)
			REFERENCES %s(id)
			ON DELETE SET NULL;
	END IF;
END $$;`, s.table("requests"), s.table("requests"), s.table("schema_definitions"))
	if _, err := tx.ExecContext(ctx, constraintStmt); err != nil {
		return fmt.Errorf("add requests grant_schema_definition_id foreign key: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS unique_key TEXT`, s.table("requests"))); err != nil {
		return fmt.Errorf("add requests unique_key column: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS mutable BOOLEAN NOT NULL DEFAULT FALSE`, s.table("requests"))); err != nil {
		return fmt.Errorf("add requests mutable column: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1`, s.table("requests"))); err != nil {
		return fmt.Errorf("add requests version column: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS requests_unique_key_idx ON %s (unique_key) WHERE unique_key IS NOT NULL`, s.table("requests"))); err != nil {
		return fmt.Errorf("create requests unique_key index: %w", err)
	}
	if err := s.migratePostgresRequestSchemaDefinitions(ctx, tx); err != nil {
		return err
	}
	return nil
}

func (s *postgresStore) ensureSchemaDefinitionsTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	id TEXT PRIMARY KEY,
	unique_key TEXT,
	schema JSONB,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`, s.table("schema_definitions"))
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create schema definitions table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS unique_key TEXT`, s.table("schema_definitions"))); err != nil {
		return fmt.Errorf("add schema_definitions unique_key column: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS schema_definitions_unique_key_idx ON %s (unique_key) WHERE unique_key IS NOT NULL`, s.table("schema_definitions"))); err != nil {
		return fmt.Errorf("create schema_definitions unique_key index: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS schema JSONB`, s.table("schema_definitions"))); err != nil {
		return fmt.Errorf("add schema_definitions schema column: %w", err)
	}
	if err := s.migratePostgresSchemaDefinitions(ctx, tx); err != nil {
		return err
	}
	return nil
}

func (s *postgresStore) ensureRegistersTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	id TEXT PRIMARY KEY,
	host_id TEXT NOT NULL,
	schema_definition_id TEXT,
	unique_key TEXT,
	data JSONB,
	mutable BOOLEAN NOT NULL DEFAULT FALSE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	FOREIGN KEY(host_id) REFERENCES %s(id) ON DELETE CASCADE,
	FOREIGN KEY(schema_definition_id) REFERENCES %s(id) ON DELETE SET NULL
)`, s.table("registers"), s.table("hosts"), s.table("schema_definitions"))
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create registers table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS schema_definition_id TEXT`, s.table("registers"))); err != nil {
		return fmt.Errorf("add registers schema_definition_id column: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS unique_key TEXT`, s.table("registers"))); err != nil {
		return fmt.Errorf("add registers unique_key column: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS mutable BOOLEAN NOT NULL DEFAULT FALSE`, s.table("registers"))); err != nil {
		return fmt.Errorf("add registers mutable column: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS registers_unique_key_idx ON %s (unique_key) WHERE unique_key IS NOT NULL`, s.table("registers"))); err != nil {
		return fmt.Errorf("create registers unique_key index: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`
DO $$ BEGIN
	IF NOT EXISTS (
		SELECT 1
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
		  ON tc.constraint_name = kcu.constraint_name
		 AND tc.constraint_schema = kcu.constraint_schema
		WHERE tc.constraint_type = 'FOREIGN KEY'
		  AND tc.table_schema = '%s'
		  AND tc.table_name = 'registers'
		  AND kcu.column_name = 'schema_definition_id'
	) THEN
		ALTER TABLE %s
			ADD CONSTRAINT registers_schema_definition_fk
			FOREIGN KEY (schema_definition_id)
			REFERENCES %s(id) ON DELETE SET NULL;
	END IF;
END $$;`, s.schema, s.table("registers"), s.table("schema_definitions"))); err != nil {
		return fmt.Errorf("add registers schema_definition_id foreign key: %w", err)
	}
	return nil
}

func (s *postgresStore) ensureResourceEventsTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	id TEXT PRIMARY KEY,
	resource_type TEXT NOT NULL,
	resource_id TEXT NOT NULL,
	event_type TEXT NOT NULL,
	old_payload JSONB,
	new_payload JSONB,
	old_labels JSONB,
	new_labels JSONB,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`, s.table("resource_events"))
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create resource events table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`CREATE INDEX IF NOT EXISTS resource_events_resource_idx ON %s (resource_type, resource_id, created_at DESC)`, s.table("resource_events"))); err != nil {
		return fmt.Errorf("create resource events resource index: %w", err)
	}
	return nil
}

func (s *postgresStore) ensureGrantsTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s (
	id TEXT PRIMARY KEY,
	request_id TEXT NOT NULL,
	payload JSONB,
	request_version INTEGER NOT NULL DEFAULT 1,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	FOREIGN KEY(request_id) REFERENCES %s(id) ON DELETE CASCADE,
	UNIQUE(request_id)
)`, s.table("grants"), s.table("requests"))
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create grants table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS request_version INTEGER NOT NULL DEFAULT 1`, s.table("grants"))); err != nil {
		return fmt.Errorf("add grants request_version column: %w", err)
	}
	return nil
}

func (s *postgresStore) ensureHostLabelsTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	host_id TEXT NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY (host_id, key),
	FOREIGN KEY(host_id) REFERENCES %s(id) ON DELETE CASCADE,
	CHECK(length(key) <= %d),
	CHECK(length(value) <= %d)
)`, s.table("host_labels"), s.table("hosts"), maxLabelLength, maxLabelLength)
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create host labels table: %w", err)
	}
	return nil
}

func (s *postgresStore) ensureRequestLabelsTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	request_id TEXT NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY (request_id, key),
	FOREIGN KEY(request_id) REFERENCES %s(id) ON DELETE CASCADE,
	CHECK(length(key) <= %d),
	CHECK(length(value) <= %d)
)`, s.table("request_labels"), s.table("requests"), maxLabelLength, maxLabelLength)
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create request labels table: %w", err)
	}
	return nil
}

func (s *postgresStore) ensureRegisterLabelsTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	register_id TEXT NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY (register_id, key),
	FOREIGN KEY(register_id) REFERENCES %s(id) ON DELETE CASCADE,
	CHECK(length(key) <= %d),
	CHECK(length(value) <= %d)
)`, s.table("register_labels"), s.table("registers"), maxLabelLength, maxLabelLength)
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create register labels table: %w", err)
	}
	return nil
}

func (s *postgresStore) ensureGrantLabelsTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	grant_id TEXT NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY (grant_id, key),
	FOREIGN KEY(grant_id) REFERENCES %s(id) ON DELETE CASCADE,
	CHECK(length(key) <= %d),
	CHECK(length(value) <= %d)
)`, s.table("grant_labels"), s.table("grants"), maxLabelLength, maxLabelLength)
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create grant labels table: %w", err)
	}
	return nil
}

func (s *postgresStore) ensureSchemaDefinitionLabelsTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	schema_definition_id TEXT NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY (schema_definition_id, key),
	FOREIGN KEY(schema_definition_id) REFERENCES %s(id) ON DELETE CASCADE,
	CHECK(length(key) <= %d),
	CHECK(length(value) <= %d)
)`, s.table("schema_definition_labels"), s.table("schema_definitions"), maxLabelLength, maxLabelLength)
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create schema definition labels table: %w", err)
	}
	return nil
}

func (s *postgresStore) ensureHostExists(ctx context.Context, hostID string) error {
	if hostID == "" {
		return fmt.Errorf("host id is required")
	}

	if _, err := s.GetHost(ctx, hostID); err != nil {
		if errors.Is(err, ErrHostNotFound) {
			return fmt.Errorf("%w: %s", ErrReferencedHostNotFound, hostID)
		}
		return err
	}
	return nil
}

// CreateHost registers a new host with the given labels.
func (s *postgresStore) CreateHost(ctx context.Context, host Host) (Host, error) {
	if s == nil || s.db == nil {
		return Host{}, fmt.Errorf("store not initialized")
	}
	host.ID = generateID()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Host{}, fmt.Errorf("begin host transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback create host transaction")

	s.logDBOperation("hosts", "create", logrus.Fields{
		"host_id":    host.ID,
		"unique_key": host.UniqueKey,
		"labels":     host.Labels,
	})

	stmt := fmt.Sprintf(`INSERT INTO %s (id, unique_key) VALUES ($1, $2)`, s.table("hosts"))
	var uniqueKey any
	if host.UniqueKey != "" {
		uniqueKey = host.UniqueKey
	}
	if _, err := tx.ExecContext(ctx, stmt, host.ID, uniqueKey); err != nil {
		if isUniqueConstraintError(err) {
			if isUniqueHostKeyConstraintError(err) {
				return Host{}, ErrHostUniqueKeyConflict
			}
			return Host{}, ErrHostAlreadyExists
		}
		return Host{}, fmt.Errorf("insert host: %w", err)
	}

	if err := insertLabelsPostgres(ctx, tx, s.table("host_labels"), "host_id", host.ID, host.Labels); err != nil {
		return Host{}, fmt.Errorf("insert host labels: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Host{}, fmt.Errorf("commit host creation: %w", err)
	}

	return host, nil
}

// GetHost returns the host for the given identifier.
func (s *postgresStore) GetHost(ctx context.Context, id string) (Host, error) {
	if s == nil || s.db == nil {
		return Host{}, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("hosts", "get", logrus.Fields{
		"host_id": id,
	})

	query := fmt.Sprintf(`SELECT id, unique_key, created_at FROM %s WHERE id = $1`, s.table("hosts"))
	row := s.db.QueryRowContext(ctx, query, id)
	host, err := scanHost(row)
	if err != nil {
		return Host{}, err
	}
	host.Labels, err = s.loadLabels(ctx, s.table("host_labels"), "host_id", host.ID)
	if err != nil {
		return Host{}, fmt.Errorf("load host labels: %w", err)
	}
	return host, nil
}

// ListHosts returns every host stored in the database ordered by creation.
func (s *postgresStore) ListHosts(ctx context.Context) ([]Host, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("hosts", "list", nil)

	query := fmt.Sprintf(`SELECT id, unique_key, created_at FROM %s ORDER BY created_at ASC`, s.table("hosts"))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query hosts: %w", err)
	}
	defer closeRows(rows, "close hosts rows")

	hosts := make([]Host, 0)
	for rows.Next() {
		host, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan hosts: %w", err)
	}

	for i := range hosts {
		if hosts[i].Labels, err = s.loadLabels(ctx, s.table("host_labels"), "host_id", hosts[i].ID); err != nil {
			return nil, fmt.Errorf("load host labels: %w", err)
		}
	}

	return hosts, nil
}

// DeleteHost removes a host from storage.
func (s *postgresStore) DeleteHost(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("hosts", "delete", logrus.Fields{
		"host_id": id,
	})

	stmt := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, s.table("hosts"))
	res, err := s.db.ExecContext(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("delete host: %w", err)
	}

	count, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete host rows affected: %w", err)
	}
	if count == 0 {
		return ErrHostNotFound
	}

	return nil
}

// UpdateHostLabels replaces the labels stored for a host.
func (s *postgresStore) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("hosts", "update_labels", logrus.Fields{
		"host_id": id,
		"labels":  labels,
	})

	if err := s.ensureHostExists(ctx, id); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin host labels transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback host labels transaction")

	if err := replaceLabelsPostgres(ctx, tx, s.table("host_labels"), "host_id", id, labels); err != nil {
		return fmt.Errorf("replace host labels: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit host labels transaction: %w", err)
	}

	return nil
}

// CreateRequest inserts a new request record into storage.
func (s *postgresStore) CreateRequest(ctx context.Context, req Request) (Request, error) {
	if s == nil || s.db == nil {
		return Request{}, fmt.Errorf("store not initialized")
	}
	if req.HostID == "" {
		return Request{}, fmt.Errorf("host_id is required")
	}
	if err := s.ensureHostExists(ctx, req.HostID); err != nil {
		return Request{}, err
	}

	req.ID = generateID()

	s.logDBOperation("requests", "create", logrus.Fields{
		"request_id":                   req.ID,
		"host_id":                      req.HostID,
		"request_schema_definition_id": req.RequestSchemaDefinitionID,
		"grant_schema_definition_id":   req.GrantSchemaDefinitionID,
		"unique_key":                   req.UniqueKey,
		"mutable":                      req.Mutable,
		"version":                      req.Version,
		"payload":                      req.Payload,
		"labels":                       req.Labels,
	})

	payloadValue, err := encodeJSON(req.Payload)
	if err != nil {
		return Request{}, fmt.Errorf("encode request payload: %w", err)
	}

	if req.Version <= 0 {
		req.Version = 1
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Request{}, fmt.Errorf("begin request transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback create request transaction")

	stmt := fmt.Sprintf(`INSERT INTO %s (id, host_id, request_schema_definition_id, grant_schema_definition_id, unique_key, data, mutable, version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, s.table("requests"))
	var uniqueKey any
	if req.UniqueKey != "" {
		uniqueKey = req.UniqueKey
	}
	var requestSchemaID any
	if req.RequestSchemaDefinitionID != "" {
		requestSchemaID = req.RequestSchemaDefinitionID
	}
	var grantSchemaID any
	if req.GrantSchemaDefinitionID != "" {
		grantSchemaID = req.GrantSchemaDefinitionID
	}
	if _, err := tx.ExecContext(ctx, stmt, req.ID, req.HostID, requestSchemaID, grantSchemaID, uniqueKey, payloadValue, req.Mutable, req.Version); err != nil {
		if isUniqueConstraintError(err) {
			if isUniqueKeyConstraintError(err) {
				return Request{}, fmt.Errorf("%w: %w", ErrRequestUniqueKeyConflict, err)
			}
			return Request{}, fmt.Errorf("%w: %w", ErrRequestAlreadyExists, err)
		}
		return Request{}, fmt.Errorf("insert request: %w", err)
	}

	if err := insertLabelsPostgres(ctx, tx, s.table("request_labels"), "request_id", req.ID, req.Labels); err != nil {
		return Request{}, fmt.Errorf("insert request labels: %w", err)
	}
	if err := insertResourceEventPostgres(ctx, tx, s.table("resource_events"), "request", req.ID, "created", nil, req.Payload, nil, req.Labels); err != nil {
		return Request{}, fmt.Errorf("insert request event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Request{}, fmt.Errorf("commit request creation: %w", err)
	}

	return req, nil
}

// GetRequest fetches a request by its identifier.
func (s *postgresStore) GetRequest(ctx context.Context, id string) (Request, error) {
	if s == nil || s.db == nil {
		return Request{}, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("requests", "get", logrus.Fields{
		"request_id": id,
	})

	query := fmt.Sprintf(`
SELECT id, host_id, request_schema_definition_id, grant_schema_definition_id, unique_key, data,
       CASE WHEN EXISTS (SELECT 1 FROM %s WHERE request_id = %s.id) THEN 1 ELSE 0 END AS has_grant,
       created_at, updated_at, mutable, version
FROM %s
WHERE id = $1
`, s.table("grants"), s.table("requests"), s.table("requests"))

	row := s.db.QueryRowContext(ctx, query, id)

	req, err := scanRequest(row)
	if err != nil {
		return Request{}, err
	}
	req.Labels, err = s.loadLabels(ctx, s.table("request_labels"), "request_id", req.ID)
	if err != nil {
		return Request{}, fmt.Errorf("load request labels: %w", err)
	}
	return req, nil
}

// ListRequests returns stored requests ordered by creation time.
func (s *postgresStore) ListRequests(ctx context.Context, filters *RequestListFilters) ([]Request, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	var logFields logrus.Fields
	if filters != nil {
		if filters.HasGrant != nil {
			logFields = logrus.Fields{"has_grant": *filters.HasGrant}
		}
		if len(filters.Labels) > 0 {
			if logFields == nil {
				logFields = logrus.Fields{}
			}
			logFields["labels"] = filters.Labels
		}
		if len(filters.HostLabels) > 0 {
			if logFields == nil {
				logFields = logrus.Fields{}
			}
			logFields["host_labels"] = filters.HostLabels
		}
	}
	s.logDBOperation("requests", "list", logFields)

	query := strings.Builder{}
	_, _ = fmt.Fprintf(&query, `
SELECT id, host_id, request_schema_definition_id, grant_schema_definition_id, unique_key, data,
       CASE WHEN EXISTS (SELECT 1 FROM %s WHERE request_id = %s.id) THEN 1 ELSE 0 END AS has_grant,
       created_at, updated_at, mutable, version
FROM %s`, s.table("grants"), s.table("requests"), s.table("requests"))

	var args []any
	var where []string
	if filters != nil {
		if filters.HasGrant != nil {
			if *filters.HasGrant {
				where = append(where, fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE request_id = %s.id)", s.table("grants"), s.table("requests")))
			} else {
				where = append(where, fmt.Sprintf("NOT EXISTS (SELECT 1 FROM %s WHERE request_id = %s.id)", s.table("grants"), s.table("requests")))
			}
		}
		for key, value := range filters.Labels {
			where = append(where, fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE request_id = %s.id AND key = $%d AND value = $%d)", s.table("request_labels"), s.table("requests"), len(args)+1, len(args)+2))
			args = append(args, key, value)
		}
		for key, value := range filters.HostLabels {
			where = append(where, fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE host_id = %s.host_id AND key = $%d AND value = $%d)", s.table("host_labels"), s.table("requests"), len(args)+1, len(args)+2))
			args = append(args, key, value)
		}
	}
	if len(where) > 0 {
		query.WriteString(" WHERE ")
		query.WriteString(strings.Join(where, " AND "))
	}
	query.WriteString(" ORDER BY created_at ASC")

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query requests: %w", err)
	}
	defer closeRows(rows, "close requests rows")

	requests := make([]Request, 0)
	for rows.Next() {
		req, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		requests = append(requests, req)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan requests: %w", err)
	}

	for i := range requests {
		if requests[i].Labels, err = s.loadLabels(ctx, s.table("request_labels"), "request_id", requests[i].ID); err != nil {
			return nil, fmt.Errorf("load request labels: %w", err)
		}
	}

	return requests, nil
}

// CountRequestsByGrantPresence returns the number of requests grouped by whether they already have a grant.
func (s *postgresStore) CountRequestsByGrantPresence(ctx context.Context) (map[string]int64, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("requests", "count_by_grant_presence", nil)

	var withGrant, withoutGrant int64
	queryWith := fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE EXISTS (SELECT 1 FROM %s WHERE %s.request_id = %s.id)`, s.table("requests"), s.table("grants"), s.table("grants"), s.table("requests"))
	if err := s.db.QueryRowContext(ctx, queryWith).Scan(&withGrant); err != nil {
		return nil, fmt.Errorf("count requests with grant: %w", err)
	}
	queryWithout := fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE NOT EXISTS (SELECT 1 FROM %s WHERE %s.request_id = %s.id)`, s.table("requests"), s.table("grants"), s.table("grants"), s.table("requests"))
	if err := s.db.QueryRowContext(ctx, queryWithout).Scan(&withoutGrant); err != nil {
		return nil, fmt.Errorf("count requests without grant: %w", err)
	}

	counts := map[string]int64{
		"with_grant":    withGrant,
		"without_grant": withoutGrant,
	}
	return counts, nil
}

func (s *postgresStore) UpdateRequest(ctx context.Context, id string, payload *map[string]any, labels *map[string]string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}
	if payload == nil && labels == nil {
		return fmt.Errorf("payload and/or labels are required")
	}

	fields := logrus.Fields{
		"request_id": id,
		"payload":    payload,
		"labels":     labels,
	}

	s.logDBOperation("requests", "update", fields)

	current, err := s.GetRequest(ctx, id)
	if err != nil {
		return err
	}
	if payload != nil && !current.Mutable {
		return ErrRequestImmutable
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin request update transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback request update transaction")

	if labels != nil {
		if err := replaceLabelsPostgres(ctx, tx, s.table("request_labels"), "request_id", id, *labels); err != nil {
			return fmt.Errorf("replace request labels: %w", err)
		}
	}
	if payload != nil {
		payloadValue, err := encodeJSON(*payload)
		if err != nil {
			return fmt.Errorf("encode request payload: %w", err)
		}
		stmt := fmt.Sprintf(`UPDATE %s SET data = $1, version = version + 1 WHERE id = $2`, s.table("requests"))
		if _, err := tx.ExecContext(ctx, stmt, payloadValue, id); err != nil {
			return fmt.Errorf("update request payload: %w", err)
		}
	}

	if err := setUpdatedAtPostgres(ctx, tx, s.table("requests"), "id", id, "NOW()"); err != nil {
		return fmt.Errorf("refresh request timestamp: %w", err)
	}

	updatedLabels := current.Labels
	if labels != nil {
		updatedLabels = *labels
	}
	updatedPayload := current.Payload
	if payload != nil {
		updatedPayload = *payload
	}
	eventType := "updated"
	if payload != nil && labels == nil {
		eventType = "payload_updated"
	}
	if labels != nil && payload == nil {
		eventType = "labels_updated"
	}
	if err := insertResourceEventPostgres(ctx, tx, s.table("resource_events"), "request", id, eventType, current.Payload, updatedPayload, current.Labels, updatedLabels); err != nil {
		return fmt.Errorf("insert request event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit request update: %w", err)
	}

	return nil
}

func (s *postgresStore) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) error {
	return s.UpdateRequest(ctx, id, nil, &labels)
}

// DeleteRequest removes a request from storage.
func (s *postgresStore) DeleteRequest(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("requests", "delete", logrus.Fields{
		"request_id": id,
	})

	current, err := s.GetRequest(ctx, id)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin request delete transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback request delete transaction")

	stmt := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, s.table("requests"))
	res, err := tx.ExecContext(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("delete request: %w", err)
	}

	count, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete request rows affected: %w", err)
	}
	if count == 0 {
		return ErrRequestNotFound
	}
	if err := insertResourceEventPostgres(ctx, tx, s.table("resource_events"), "request", id, "deleted", current.Payload, nil, current.Labels, nil); err != nil {
		return fmt.Errorf("insert request event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit request delete: %w", err)
	}

	return nil
}

// CreateRegister inserts a new register record into storage.
func (s *postgresStore) CreateRegister(ctx context.Context, reg Register) (Register, error) {
	if s == nil || s.db == nil {
		return Register{}, fmt.Errorf("store not initialized")
	}
	if reg.HostID == "" {
		return Register{}, fmt.Errorf("host_id is required")
	}
	if err := s.ensureHostExists(ctx, reg.HostID); err != nil {
		return Register{}, err
	}

	reg.ID = generateID()

	s.logDBOperation("registers", "create", logrus.Fields{
		"register_id":          reg.ID,
		"host_id":              reg.HostID,
		"schema_definition_id": reg.SchemaDefinitionID,
		"unique_key":           reg.UniqueKey,
		"mutable":              reg.Mutable,
		"payload":              reg.Payload,
		"labels":               reg.Labels,
	})

	payloadValue, err := encodeJSON(reg.Payload)
	if err != nil {
		return Register{}, fmt.Errorf("encode register payload: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Register{}, fmt.Errorf("begin register transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback create register transaction")

	stmt := fmt.Sprintf(`INSERT INTO %s (id, host_id, schema_definition_id, unique_key, data, mutable) VALUES ($1, $2, $3, $4, $5, $6)`, s.table("registers"))
	var uniqueKey any
	if reg.UniqueKey != "" {
		uniqueKey = reg.UniqueKey
	}
	var schemaDefinitionID any
	if reg.SchemaDefinitionID != "" {
		schemaDefinitionID = reg.SchemaDefinitionID
	}
	if _, err := tx.ExecContext(ctx, stmt, reg.ID, reg.HostID, schemaDefinitionID, uniqueKey, payloadValue, reg.Mutable); err != nil {
		if isUniqueConstraintError(err) {
			if isUniqueRegisterKeyConstraintError(err) {
				return Register{}, fmt.Errorf("%w: %w", ErrRegisterUniqueKeyConflict, err)
			}
			return Register{}, fmt.Errorf("%w: %w", ErrRegisterAlreadyExists, err)
		}
		return Register{}, fmt.Errorf("insert register: %w", err)
	}

	if err := insertLabelsPostgres(ctx, tx, s.table("register_labels"), "register_id", reg.ID, reg.Labels); err != nil {
		return Register{}, fmt.Errorf("insert register labels: %w", err)
	}
	if err := insertRegisterEventPostgres(ctx, tx, s.table("resource_events"), RegisterEvent{
		ID:         generateID(),
		RegisterID: reg.ID,
		EventType:  "created",
		NewPayload: reg.Payload,
		NewLabels:  reg.Labels,
	}); err != nil {
		return Register{}, fmt.Errorf("insert register event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Register{}, fmt.Errorf("commit register creation: %w", err)
	}

	return reg, nil
}

// GetRegister fetches a register record by its identifier.
func (s *postgresStore) GetRegister(ctx context.Context, id string) (Register, error) {
	if s == nil || s.db == nil {
		return Register{}, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("registers", "get", logrus.Fields{
		"register_id": id,
	})

	query := fmt.Sprintf(`SELECT id, host_id, schema_definition_id, unique_key, data, created_at, updated_at, mutable FROM %s WHERE id = $1`, s.table("registers"))
	row := s.db.QueryRowContext(ctx, query, id)

	reg, err := scanRegister(row)
	if err != nil {
		return Register{}, err
	}
	reg.Labels, err = s.loadLabels(ctx, s.table("register_labels"), "register_id", reg.ID)
	if err != nil {
		return Register{}, fmt.Errorf("load register labels: %w", err)
	}
	return reg, nil
}

// ListRegisters returns stored registers ordered by creation time.
func (s *postgresStore) ListRegisters(ctx context.Context, filters *RegisterListFilters) ([]Register, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	var logFields logrus.Fields
	if filters != nil {
		if len(filters.Labels) > 0 {
			logFields = logrus.Fields{"labels": filters.Labels}
		}
		if len(filters.HostLabels) > 0 {
			if logFields == nil {
				logFields = logrus.Fields{}
			}
			logFields["host_labels"] = filters.HostLabels
		}
	}
	s.logDBOperation("registers", "list", logFields)

	query := strings.Builder{}
	_, _ = fmt.Fprintf(&query, `SELECT id, host_id, schema_definition_id, unique_key, data, created_at, updated_at, mutable FROM %s`, s.table("registers"))

	var args []any
	var where []string
	if filters != nil {
		for key, value := range filters.Labels {
			where = append(where, fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE register_id = %s.id AND key = $%d AND value = $%d)", s.table("register_labels"), s.table("registers"), len(args)+1, len(args)+2))
			args = append(args, key, value)
		}
		for key, value := range filters.HostLabels {
			where = append(where, fmt.Sprintf("EXISTS (SELECT 1 FROM %s WHERE host_id = %s.host_id AND key = $%d AND value = $%d)", s.table("host_labels"), s.table("registers"), len(args)+1, len(args)+2))
			args = append(args, key, value)
		}
	}
	if len(where) > 0 {
		query.WriteString(" WHERE ")
		query.WriteString(strings.Join(where, " AND "))
	}
	query.WriteString(" ORDER BY created_at ASC")

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query registers: %w", err)
	}
	defer closeRows(rows, "close registers rows")

	registers := make([]Register, 0)
	for rows.Next() {
		reg, err := scanRegister(rows)
		if err != nil {
			return nil, err
		}
		registers = append(registers, reg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan registers: %w", err)
	}

	for i := range registers {
		if registers[i].Labels, err = s.loadLabels(ctx, s.table("register_labels"), "register_id", registers[i].ID); err != nil {
			return nil, fmt.Errorf("load register labels: %w", err)
		}
	}
	return registers, nil
}

// UpdateRegisterLabels replaces the labels stored for a register record.
func (s *postgresStore) UpdateRegister(ctx context.Context, id string, payload *map[string]any, labels *map[string]string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}
	if payload == nil && labels == nil {
		return fmt.Errorf("payload and/or labels are required")
	}

	fields := logrus.Fields{
		"register_id": id,
		"payload":     payload,
		"labels":      labels,
	}
	s.logDBOperation("registers", "update", fields)

	current, err := s.GetRegister(ctx, id)
	if err != nil {
		return err
	}
	if payload != nil && !current.Mutable {
		return ErrRegisterImmutable
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin register update transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback register update transaction")

	if labels != nil {
		if err := replaceLabelsPostgres(ctx, tx, s.table("register_labels"), "register_id", id, *labels); err != nil {
			return fmt.Errorf("replace register labels: %w", err)
		}
	}
	if payload != nil {
		payloadValue, err := encodeJSON(*payload)
		if err != nil {
			return fmt.Errorf("encode register payload: %w", err)
		}
		stmt := fmt.Sprintf(`UPDATE %s SET data = $1 WHERE id = $2`, s.table("registers"))
		if _, err := tx.ExecContext(ctx, stmt, payloadValue, id); err != nil {
			return fmt.Errorf("update register payload: %w", err)
		}
	}

	if err := setUpdatedAtPostgres(ctx, tx, s.table("registers"), "id", id, "NOW()"); err != nil {
		return fmt.Errorf("refresh register timestamp: %w", err)
	}

	updatedLabels := current.Labels
	if labels != nil {
		updatedLabels = *labels
	}
	updatedPayload := current.Payload
	if payload != nil {
		updatedPayload = *payload
	}
	eventType := "updated"
	if payload != nil && labels == nil {
		eventType = "payload_updated"
	}
	if labels != nil && payload == nil {
		eventType = "labels_updated"
	}
	if err := insertRegisterEventPostgres(ctx, tx, s.table("resource_events"), RegisterEvent{
		ID:         generateID(),
		RegisterID: id,
		EventType:  eventType,
		OldPayload: current.Payload,
		NewPayload: updatedPayload,
		OldLabels:  current.Labels,
		NewLabels:  updatedLabels,
	}); err != nil {
		return fmt.Errorf("insert register event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit register update: %w", err)
	}

	return nil
}

// UpdateRegisterLabels replaces the labels stored for a register record.
func (s *postgresStore) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) error {
	return s.UpdateRegister(ctx, id, nil, &labels)
}

func (s *postgresStore) ListRegisterEvents(ctx context.Context, registerID string) ([]RegisterEvent, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}
	if _, err := s.GetRegister(ctx, registerID); err != nil {
		return nil, err
	}
	s.logDBOperation("resource_events", "list", logrus.Fields{"register_id": registerID})

	query := fmt.Sprintf(`
SELECT id, resource_id, event_type, old_payload::text, new_payload::text, old_labels::text, new_labels::text, created_at
FROM %s
WHERE resource_type = 'register' AND resource_id = $1
ORDER BY created_at DESC
`, s.table("resource_events"))
	rows, err := s.db.QueryContext(ctx, query, registerID)
	if err != nil {
		return nil, fmt.Errorf("query register events: %w", err)
	}
	defer closeRows(rows, "close register events rows")

	events := make([]RegisterEvent, 0)
	for rows.Next() {
		event, err := scanRegisterEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan register events: %w", err)
	}
	return events, nil
}

// DeleteRegister removes a register record from storage.
func (s *postgresStore) DeleteRegister(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("registers", "delete", logrus.Fields{
		"register_id": id,
	})

	current, err := s.GetRegister(ctx, id)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin register delete transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback register delete transaction")

	stmt := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, s.table("registers"))
	res, err := tx.ExecContext(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("delete register: %w", err)
	}

	count, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete register rows affected: %w", err)
	}
	if count == 0 {
		return ErrRegisterNotFound
	}
	if err := insertRegisterEventPostgres(ctx, tx, s.table("resource_events"), RegisterEvent{
		ID:         generateID(),
		RegisterID: id,
		EventType:  "deleted",
		OldPayload: current.Payload,
		OldLabels:  current.Labels,
	}); err != nil {
		return fmt.Errorf("insert register event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit register delete: %w", err)
	}

	return nil
}

// CountRegisters returns the total number of registers.
func (s *postgresStore) CountRegisters(ctx context.Context) (map[string]int64, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}
	s.logDBOperation("registers", "count", nil)
	var total int64
	query := fmt.Sprintf(`SELECT COUNT(*) FROM %s`, s.table("registers"))
	if err := s.db.QueryRowContext(ctx, query).Scan(&total); err != nil {
		return nil, fmt.Errorf("count registers: %w", err)
	}
	return map[string]int64{"total": total}, nil
}

// CreateGrant stores a new grant with its payload.
func (s *postgresStore) CreateGrant(ctx context.Context, grant Grant) (Grant, error) {
	if s == nil || s.db == nil {
		return Grant{}, fmt.Errorf("store not initialized")
	}
	if grant.RequestID == "" {
		return Grant{}, fmt.Errorf("request_id is required")
	}
	requestVersionInput := grant.RequestVersion

	grant.ID = generateID()

	s.logDBOperation("grants", "create", logrus.Fields{
		"grant_id":        grant.ID,
		"request_id":      grant.RequestID,
		"request_version_input": requestVersionInput,
		"request_version": grant.RequestVersion,
		"payload":         grant.Payload,
	})

	payloadValue, err := encodeJSON(grant.Payload)
	if err != nil {
		return Grant{}, fmt.Errorf("encode grant payload: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Grant{}, fmt.Errorf("begin grant transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback create grant transaction")

	var insertStmt string
	var insertArgs []any
	if requestVersionInput > 0 {
		insertStmt = fmt.Sprintf(`
INSERT INTO %s (id, request_id, payload, request_version)
SELECT $1, r.id, $2::jsonb, r.version
FROM %s r
WHERE r.id = $3 AND r.version = $4
RETURNING request_version
`, s.table("grants"), s.table("requests"))
		insertArgs = []any{grant.ID, payloadValue, grant.RequestID, requestVersionInput}
	} else {
		insertStmt = fmt.Sprintf(`
INSERT INTO %s (id, request_id, payload, request_version)
SELECT $1, r.id, $2::jsonb, r.version
FROM %s r
WHERE r.id = $3
RETURNING request_version
`, s.table("grants"), s.table("requests"))
		insertArgs = []any{grant.ID, payloadValue, grant.RequestID}
	}
	if err := tx.QueryRowContext(ctx, insertStmt, insertArgs...).Scan(&grant.RequestVersion); err != nil {
		if isUniqueConstraintError(err) {
			return Grant{}, fmt.Errorf("%w: %w", ErrGrantAlreadyExists, err)
		}
		if errors.Is(err, sql.ErrNoRows) {
			if requestVersionInput > 0 {
				existsStmt := fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE id = $1)`, s.table("requests"))
				var exists bool
				if existsErr := tx.QueryRowContext(ctx, existsStmt, grant.RequestID).Scan(&exists); existsErr != nil {
					return Grant{}, fmt.Errorf("verify request exists: %w", existsErr)
				}
				if !exists {
					return Grant{}, ErrReferencedRequestNotFound
				}
				return Grant{}, ErrGrantRequestVersionConflict
			}
			return Grant{}, ErrReferencedRequestNotFound
		}
		return Grant{}, fmt.Errorf("insert grant: %w", err)
	}
	if err := insertResourceEventPostgres(ctx, tx, s.table("resource_events"), "grant", grant.ID, "created", nil, grant.Payload, nil, nil); err != nil {
		return Grant{}, fmt.Errorf("insert grant event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Grant{}, fmt.Errorf("commit grant creation: %w", err)
	}

	return grant, nil
}

// GetGrant retrieves a grant by ID.
func (s *postgresStore) GetGrant(ctx context.Context, id string) (Grant, error) {
	if s == nil || s.db == nil {
		return Grant{}, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "get", logrus.Fields{
		"grant_id": id,
	})

	query := fmt.Sprintf(`SELECT id, request_id, payload::text, created_at, updated_at, request_version FROM %s WHERE id = $1`, s.table("grants"))
	row := s.db.QueryRowContext(ctx, query, id)
	return scanGrant(row)
}

// ListGrants returns every stored grant ordered by creation.
func (s *postgresStore) ListGrants(ctx context.Context) ([]Grant, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "list", nil)

	query := fmt.Sprintf(`SELECT id, request_id, payload::text, created_at, updated_at, request_version FROM %s ORDER BY created_at ASC`, s.table("grants"))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query grants: %w", err)
	}
	defer closeRows(rows, "close grants rows")

	grants := make([]Grant, 0)
	for rows.Next() {
		grant, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan grants: %w", err)
	}

	return grants, nil
}

// CountGrants returns the total number of grants.
func (s *postgresStore) CountGrants(ctx context.Context) (map[string]int64, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "count", nil)

	var total int64
	query := fmt.Sprintf(`SELECT COUNT(*) FROM %s`, s.table("grants"))
	if err := s.db.QueryRowContext(ctx, query).Scan(&total); err != nil {
		return nil, fmt.Errorf("count grants: %w", err)
	}
	return map[string]int64{"total": total}, nil
}

// GetGrantForRequest returns the grant for the request.
func (s *postgresStore) GetGrantForRequest(ctx context.Context, requestID string) (Grant, bool, error) {
	if s == nil || s.db == nil {
		return Grant{}, false, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "get_for_request", logrus.Fields{
		"request_id": requestID,
	})

	query := fmt.Sprintf(`
SELECT id, request_id, payload::text, created_at, updated_at
     , request_version
FROM %s
WHERE request_id = $1
ORDER BY created_at DESC
LIMIT 1
`, s.table("grants"))

	row := s.db.QueryRowContext(ctx, query, requestID)

	grant, err := scanGrant(row)
	if err != nil {
		if errors.Is(err, ErrGrantNotFound) {
			return Grant{}, false, nil
		}
		return Grant{}, false, fmt.Errorf("get grant for request: %w", err)
	}

	return grant, true, nil
}

func (s *postgresStore) UpdateGrant(ctx context.Context, id string, payload map[string]any, requestVersion int) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "update", logrus.Fields{
		"grant_id": id,
		"payload":  payload,
		"request_version_input": requestVersion,
	})

	current, err := s.GetGrant(ctx, id)
	if err != nil {
		return err
	}
	payloadValue, err := encodeJSON(payload)
	if err != nil {
		return fmt.Errorf("encode grant payload: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin grant update transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback grant update transaction")

	var stmt string
	var args []any
	if requestVersion > 0 {
		stmt = fmt.Sprintf(`
UPDATE %s g
SET payload = $1::jsonb, request_version = r.version
FROM %s r
WHERE g.id = $2
  AND r.id = g.request_id
  AND r.version = $3
`, s.table("grants"), s.table("requests"))
		args = []any{payloadValue, id, requestVersion}
	} else {
		stmt = fmt.Sprintf(`
UPDATE %s g
SET payload = $1::jsonb, request_version = r.version
FROM %s r
WHERE g.id = $2
  AND r.id = g.request_id
`, s.table("grants"), s.table("requests"))
		args = []any{payloadValue, id}
	}
	result, err := tx.ExecContext(ctx, stmt, args...)
	if err != nil {
		return fmt.Errorf("update grant payload: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect grant update result: %w", err)
	}
	if rowsAffected == 0 {
		var requestID string
		fallbackGrantStmt := fmt.Sprintf(`SELECT request_id FROM %s WHERE id = $1`, s.table("grants"))
		if err := tx.QueryRowContext(ctx, fallbackGrantStmt, id).Scan(&requestID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrGrantNotFound
			}
			return fmt.Errorf("read grant for update fallback: %w", err)
		}
		if requestVersion > 0 {
			currentVersionStmt := fmt.Sprintf(`
SELECT version
FROM %s
WHERE id = $1
`, s.table("requests"))
			var currentVersion int
			if err := tx.QueryRowContext(ctx, currentVersionStmt, requestID).Scan(&currentVersion); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrGrantNotFound
				}
				return fmt.Errorf("read request version for grant: %w", err)
			}
			if currentVersion != requestVersion {
				return ErrGrantRequestVersionConflict
			}
		}
		return fmt.Errorf("update grant payload: no rows affected")
	}
	if err := setUpdatedAtPostgres(ctx, tx, s.table("grants"), "id", id, "NOW()"); err != nil {
		return fmt.Errorf("refresh grant timestamp: %w", err)
	}
	if err := insertResourceEventPostgres(ctx, tx, s.table("resource_events"), "grant", id, "updated", current.Payload, payload, nil, nil); err != nil {
		return fmt.Errorf("insert grant event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit grant update: %w", err)
	}
	return nil
}

// DeleteGrant removes a grant record.
func (s *postgresStore) DeleteGrant(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "delete", logrus.Fields{
		"grant_id": id,
	})

	current, err := s.GetGrant(ctx, id)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin grant delete transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback grant delete transaction")

	stmt := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, s.table("grants"))
	res, err := tx.ExecContext(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("delete grant: %w", err)
	}

	count, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete grant rows affected: %w", err)
	}
	if count == 0 {
		return ErrGrantNotFound
	}
	if err := insertResourceEventPostgres(ctx, tx, s.table("resource_events"), "grant", id, "deleted", current.Payload, nil, nil, nil); err != nil {
		return fmt.Errorf("insert grant event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit grant delete: %w", err)
	}

	return nil
}

// CreateSchemaDefinition stores a new schema definition.
func (s *postgresStore) CreateSchemaDefinition(ctx context.Context, def SchemaDefinition) (SchemaDefinition, error) {
	if s == nil || s.db == nil {
		return SchemaDefinition{}, fmt.Errorf("store not initialized")
	}
	if len(def.Schema) == 0 {
		return SchemaDefinition{}, fmt.Errorf("schema is required")
	}

	def.ID = generateID()

	s.logDBOperation("schema_definitions", "create", logrus.Fields{
		"schema_definition_id": def.ID,
		"unique_key":           def.UniqueKey,
		"labels":               def.Labels,
	})

	schemaValue, err := encodeJSON(def.Schema)
	if err != nil {
		return SchemaDefinition{}, fmt.Errorf("encode schema: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SchemaDefinition{}, fmt.Errorf("begin schema definition transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback schema definition transaction")

	stmt := fmt.Sprintf(`INSERT INTO %s (id, unique_key, schema) VALUES ($1, $2, $3)`, s.table("schema_definitions"))
	if _, err := tx.ExecContext(ctx, stmt, def.ID, nullableText(def.UniqueKey), schemaValue); err != nil {
		switch {
		case isUniqueSchemaDefinitionKeyConstraintError(err):
			return SchemaDefinition{}, fmt.Errorf("%w: %w", ErrSchemaDefinitionUniqueKeyConflict, err)
		case isUniqueConstraintError(err):
			return SchemaDefinition{}, fmt.Errorf("%w: %w", ErrSchemaDefinitionAlreadyExists, err)
		default:
			return SchemaDefinition{}, fmt.Errorf("insert schema definition: %w", err)
		}
	}
	if err := insertLabelsPostgres(ctx, tx, s.table("schema_definition_labels"), "schema_definition_id", def.ID, def.Labels); err != nil {
		return SchemaDefinition{}, fmt.Errorf("insert schema definition labels: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return SchemaDefinition{}, fmt.Errorf("commit schema definition transaction: %w", err)
	}

	return def, nil
}

// GetSchemaDefinition fetches a schema definition by ID.
func (s *postgresStore) GetSchemaDefinition(ctx context.Context, id string) (SchemaDefinition, error) {
	if s == nil || s.db == nil {
		return SchemaDefinition{}, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("schema_definitions", "get", logrus.Fields{
		"schema_definition_id": id,
	})

	stmt := fmt.Sprintf(`
SELECT id, unique_key, schema, created_at
FROM %s
WHERE id = $1`, s.table("schema_definitions"))
	row := s.db.QueryRowContext(ctx, stmt, id)
	def, err := scanSchemaDefinition(row)
	if err != nil {
		return SchemaDefinition{}, err
	}
	def.Labels, err = s.loadLabels(ctx, s.table("schema_definition_labels"), "schema_definition_id", def.ID)
	if err != nil {
		return SchemaDefinition{}, fmt.Errorf("load schema definition labels: %w", err)
	}
	return def, nil
}

// ListSchemaDefinitions returns stored schema definitions ordered by creation time.
func (s *postgresStore) ListSchemaDefinitions(ctx context.Context) ([]SchemaDefinition, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("schema_definitions", "list", nil)

	stmt := fmt.Sprintf(`
SELECT id, unique_key, schema, created_at
FROM %s
ORDER BY created_at ASC`, s.table("schema_definitions"))
	rows, err := s.db.QueryContext(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("query schema definitions: %w", err)
	}
	defer closeRows(rows, "close schema definitions rows")

	defs := make([]SchemaDefinition, 0)
	for rows.Next() {
		def, err := scanSchemaDefinition(rows)
		if err != nil {
			return nil, err
		}
		defs = append(defs, def)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan schema definitions: %w", err)
	}
	for i := range defs {
		defs[i].Labels, err = s.loadLabels(ctx, s.table("schema_definition_labels"), "schema_definition_id", defs[i].ID)
		if err != nil {
			return nil, fmt.Errorf("load schema definition labels: %w", err)
		}
	}
	return defs, nil
}

// DeleteSchemaDefinition removes a schema definition.
func (s *postgresStore) DeleteSchemaDefinition(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("schema_definitions", "delete", logrus.Fields{
		"schema_definition_id": id,
	})

	stmt := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, s.table("schema_definitions"))
	res, err := s.db.ExecContext(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("delete schema definition: %w", err)
	}

	count, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete schema definition rows affected: %w", err)
	}
	if count == 0 {
		return ErrSchemaDefinitionNotFound
	}

	return nil
}

// UpdateSchemaDefinitionLabels replaces the labels stored for a schema definition.
func (s *postgresStore) UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("schema_definitions", "update_labels", logrus.Fields{
		"schema_definition_id": id,
		"labels":               labels,
	})

	if _, err := s.GetSchemaDefinition(ctx, id); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema definition labels transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback schema definition labels transaction")

	if err := replaceLabelsPostgres(ctx, tx, s.table("schema_definition_labels"), "schema_definition_id", id, labels); err != nil {
		return fmt.Errorf("replace schema definition labels: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema definition labels update: %w", err)
	}
	return nil
}

func (s *postgresStore) loadLabels(ctx context.Context, table, idColumn, id string) (map[string]string, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}
	query := fmt.Sprintf(`SELECT key, value FROM %s WHERE %s = $1 ORDER BY key ASC`, table, idColumn)
	rows, err := s.db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer closeRows(rows, "close labels rows")

	labels := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		labels[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(labels) == 0 {
		return nil, nil
	}
	return labels, nil
}

func insertLabelsPostgres(ctx context.Context, tx *sql.Tx, table, idColumn, id string, labels map[string]string) error {
	if len(labels) == 0 {
		return nil
	}

	stmt := fmt.Sprintf(`INSERT INTO %s (%s, key, value) VALUES ($1, $2, $3)`, table, idColumn)
	for key, value := range labels {
		if len(key) > maxLabelLength {
			return fmt.Errorf("label key %q exceeds %d characters", key, maxLabelLength)
		}
		if len(value) > maxLabelLength {
			return fmt.Errorf("label value for %q exceeds %d characters", key, maxLabelLength)
		}
		if _, err := tx.ExecContext(ctx, stmt, id, key, value); err != nil {
			return fmt.Errorf("insert label %s:%s: %w", key, value, err)
		}
	}
	return nil
}

func replaceLabelsPostgres(ctx context.Context, tx *sql.Tx, table, idColumn, id string, labels map[string]string) error {
	stmt := fmt.Sprintf(`DELETE FROM %s WHERE %s = $1`, table, idColumn)
	if _, err := tx.ExecContext(ctx, stmt, id); err != nil {
		return fmt.Errorf("delete labels: %w", err)
	}
	return insertLabelsPostgres(ctx, tx, table, idColumn, id, labels)
}

func setUpdatedAtPostgres(ctx context.Context, tx *sql.Tx, table, idColumn, id, nowExpr string) error {
	stmt := fmt.Sprintf(`UPDATE %s SET updated_at = %s WHERE %s = $1`, table, nowExpr, idColumn)
	if _, err := tx.ExecContext(ctx, stmt, id); err != nil {
		return fmt.Errorf("update %s timestamp: %w", table, err)
	}
	return nil
}

func insertResourceEventPostgres(
	ctx context.Context,
	tx *sql.Tx,
	table string,
	resourceType string,
	resourceID string,
	eventType string,
	oldPayloadMap map[string]any,
	newPayloadMap map[string]any,
	oldLabelsMap map[string]string,
	newLabelsMap map[string]string,
) error {
	oldPayload, err := encodeJSON(oldPayloadMap)
	if err != nil {
		return fmt.Errorf("encode old_payload: %w", err)
	}
	newPayload, err := encodeJSON(newPayloadMap)
	if err != nil {
		return fmt.Errorf("encode new_payload: %w", err)
	}
	oldLabels, err := encodeJSON(oldLabelsMap)
	if err != nil {
		return fmt.Errorf("encode old_labels: %w", err)
	}
	newLabels, err := encodeJSON(newLabelsMap)
	if err != nil {
		return fmt.Errorf("encode new_labels: %w", err)
	}

	stmt := fmt.Sprintf(`
INSERT INTO %s (id, resource_type, resource_id, event_type, old_payload, new_payload, old_labels, new_labels)
VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb)
`, table)
	if _, err := tx.ExecContext(ctx, stmt, generateID(), resourceType, resourceID, eventType, oldPayload, newPayload, oldLabels, newLabels); err != nil {
		return err
	}
	return nil
}

func insertRegisterEventPostgres(ctx context.Context, tx *sql.Tx, table string, event RegisterEvent) error {
	return insertResourceEventPostgres(ctx, tx, table, "register", event.RegisterID, event.EventType, event.OldPayload, event.NewPayload, event.OldLabels, event.NewLabels)
}

func (s *postgresStore) migratePostgresSchemaDefinitions(ctx context.Context, tx *sql.Tx) error {
	requestExists, err := s.postgresColumnExists(ctx, tx, "schema_definitions", "request_schema")
	if err != nil {
		return fmt.Errorf("check schema_definitions request_schema column: %w", err)
	}
	grantExists, err := s.postgresColumnExists(ctx, tx, "schema_definitions", "grant_schema")
	if err != nil {
		return fmt.Errorf("check schema_definitions grant_schema column: %w", err)
	}
	if !requestExists && !grantExists {
		return nil
	}

	update := fmt.Sprintf(`UPDATE %s SET schema = COALESCE(schema`, s.table("schema_definitions"))
	if requestExists {
		update += `, request_schema`
	}
	if grantExists {
		update += `, grant_schema`
	}
	update += `) WHERE schema IS NULL`

	if _, err := tx.ExecContext(ctx, update); err != nil {
		return fmt.Errorf("backfill schema_definitions schema: %w", err)
	}
	return nil
}

func (s *postgresStore) migratePostgresRequestSchemaDefinitions(ctx context.Context, tx *sql.Tx) error {
	exists, err := s.postgresColumnExists(ctx, tx, "requests", "schema_definition_id")
	if err != nil {
		return fmt.Errorf("check requests schema_definition_id column: %w", err)
	}
	if !exists {
		return nil
	}

	stmt := fmt.Sprintf(`
UPDATE %s
SET request_schema_definition_id = COALESCE(request_schema_definition_id, schema_definition_id),
    grant_schema_definition_id = COALESCE(grant_schema_definition_id, schema_definition_id)
WHERE schema_definition_id IS NOT NULL
`, s.table("requests"))
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("backfill request schema definition ids: %w", err)
	}

	requestSchemaExists, err := s.postgresColumnExists(ctx, tx, "schema_definitions", "request_schema")
	if err != nil {
		return fmt.Errorf("check schema_definitions request_schema column: %w", err)
	}
	grantSchemaExists, err := s.postgresColumnExists(ctx, tx, "schema_definitions", "grant_schema")
	if err != nil {
		return fmt.Errorf("check schema_definitions grant_schema column: %w", err)
	}
	if !requestSchemaExists || !grantSchemaExists {
		return nil
	}

	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT id, request_schema, grant_schema FROM %s`, s.table("schema_definitions")))
	if err != nil {
		return fmt.Errorf("load legacy schema definitions: %w", err)
	}
	defer closeRows(rows, "close legacy schema definitions")

	type legacySchema struct {
		defID      string
		grantValue []byte
	}
	var legacy []legacySchema
	for rows.Next() {
		var (
			defID       string
			reqSchema   []byte
			grantSchema []byte
		)
		if err := rows.Scan(&defID, &reqSchema, &grantSchema); err != nil {
			return fmt.Errorf("scan legacy schema definition: %w", err)
		}
		if len(reqSchema) == 0 || len(grantSchema) == 0 {
			continue
		}
		if string(reqSchema) == string(grantSchema) {
			continue
		}
		legacy = append(legacy, legacySchema{defID: defID, grantValue: grantSchema})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy schema definitions: %w", err)
	}

	for _, entry := range legacy {
		var remaining int
		if err := tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(1) FROM %s WHERE grant_schema_definition_id = $1`, s.table("requests")), entry.defID).Scan(&remaining); err != nil {
			return fmt.Errorf("count grant schema references: %w", err)
		}
		if remaining == 0 {
			continue
		}
		grantDefID := generateID()
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (id, schema) VALUES ($1, $2)`, s.table("schema_definitions")), grantDefID, entry.grantValue); err != nil {
			return fmt.Errorf("create grant schema definition: %w", err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`
UPDATE %s
SET grant_schema_definition_id = $1
WHERE grant_schema_definition_id = $2
`, s.table("requests")), grantDefID, entry.defID); err != nil {
			return fmt.Errorf("update grant schema references: %w", err)
		}
	}
	return nil
}

func (s *postgresStore) postgresColumnExists(ctx context.Context, tx *sql.Tx, table, column string) (bool, error) {
	var exists bool
	stmt := `
SELECT EXISTS (
	SELECT 1
	FROM information_schema.columns
	WHERE table_schema = $1
	  AND table_name = $2
	  AND column_name = $3
)`
	if err := tx.QueryRowContext(ctx, stmt, s.schema, table, column).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func quoteIdent(value string) string {
	escaped := strings.ReplaceAll(value, `"`, `""`)
	return `"` + escaped + `"`
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func isUniqueKeyConstraintError(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName == "requests_unique_key_idx"
	}
	return strings.Contains(err.Error(), "requests.unique_key")
}

func isUniqueRegisterKeyConstraintError(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName == "registers_unique_key_idx"
	}
	return strings.Contains(err.Error(), "registers.unique_key")
}

func isUniqueHostKeyConstraintError(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName == "hosts_unique_key_idx"
	}
	return strings.Contains(err.Error(), "hosts.unique_key")
}

func isUniqueSchemaDefinitionKeyConstraintError(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName == "schema_definitions_unique_key_idx"
	}
	return strings.Contains(err.Error(), "schema_definitions.unique_key")
}
