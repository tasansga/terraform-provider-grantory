package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	_ "github.com/mattn/go-sqlite3"
)

// sqliteStore wraps an sqlite database connection for the provisioner server.
type sqliteStore struct {
	db        *sql.DB
	namespace string
}

const unknownNamespace = "(unknown)"

// SetNamespace records the namespace associated with this store for logging.
func (s *sqliteStore) SetNamespace(namespace string) {
	if s == nil {
		return
	}
	if ns := strings.TrimSpace(namespace); ns != "" {
		s.namespace = ns
		return
	}
	s.namespace = unknownNamespace
}

func (s *sqliteStore) namespaceForLog() string {
	if s == nil {
		return unknownNamespace
	}
	if ns := strings.TrimSpace(s.namespace); ns != "" {
		return ns
	}
	return unknownNamespace
}

func (s *sqliteStore) logDBOperation(table, operation string, params logrus.Fields) {
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

func rollbackTx(tx *sql.Tx, operation string) {
	if tx == nil {
		return
	}
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		logrus.WithError(err).Warn(operation)
	}
}

func closeRows(rows *sql.Rows, operation string) {
	if rows == nil {
		return
	}
	if err := rows.Close(); err != nil {
		logrus.WithError(err).Warn(operation)
	}
}

func (s *sqliteStore) ensureHostExists(ctx context.Context, hostID string) error {
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

func (s *sqliteStore) ensureRequestExists(ctx context.Context, requestID string) error {
	if requestID == "" {
		return fmt.Errorf("request id is required")
	}

	if _, err := s.GetRequest(ctx, requestID); err != nil {
		if errors.Is(err, ErrRequestNotFound) {
			return fmt.Errorf("%w: %s", ErrReferencedRequestNotFound, requestID)
		}
		return err
	}
	return nil
}

const createdAtLayout = "2006-01-02 15:04:05"

const (
	hostsTableStatement = `
CREATE TABLE IF NOT EXISTS hosts (
	id TEXT PRIMARY KEY,
	unique_key TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)`
	requestsTableStatement = `
CREATE TABLE IF NOT EXISTS requests (
	id TEXT PRIMARY KEY,
	host_id TEXT NOT NULL,
	request_schema_definition_id TEXT,
	grant_schema_definition_id TEXT,
	unique_key TEXT,
	data TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
	FOREIGN KEY(request_schema_definition_id) REFERENCES schema_definitions(id) ON DELETE SET NULL,
	FOREIGN KEY(grant_schema_definition_id) REFERENCES schema_definitions(id) ON DELETE SET NULL
)`
	schemaDefinitionsTableStatement = `
CREATE TABLE IF NOT EXISTS schema_definitions (
	id TEXT PRIMARY KEY,
	unique_key TEXT,
	schema TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)`
	registersTableStatement = `
CREATE TABLE IF NOT EXISTS registers (
	id TEXT PRIMARY KEY,
	host_id TEXT NOT NULL,
	schema_definition_id TEXT,
	unique_key TEXT,
	data TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
	FOREIGN KEY(schema_definition_id) REFERENCES schema_definitions(id) ON DELETE SET NULL
)`
	grantsTableStatement = `
CREATE TABLE IF NOT EXISTS grants (
	id TEXT PRIMARY KEY,
	request_id TEXT NOT NULL,
	payload TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE,
	UNIQUE(request_id)
)`
	hostLabelsTableStatement = `
CREATE TABLE IF NOT EXISTS host_labels (
	host_id TEXT NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY (host_id, key),
	FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
	CHECK(length(key) <= 256),
	CHECK(length(value) <= 256)
)`
	requestLabelsTableStatement = `
CREATE TABLE IF NOT EXISTS request_labels (
	request_id TEXT NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY (request_id, key),
	FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE,
	CHECK(length(key) <= 256),
	CHECK(length(value) <= 256)
)`
	registerLabelsTableStatement = `
CREATE TABLE IF NOT EXISTS register_labels (
	register_id TEXT NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY (register_id, key),
	FOREIGN KEY(register_id) REFERENCES registers(id) ON DELETE CASCADE,
	CHECK(length(key) <= 256),
	CHECK(length(value) <= 256)
)`
	grantLabelsTableStatement = `
CREATE TABLE IF NOT EXISTS grant_labels (
	grant_id TEXT NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY (grant_id, key),
	FOREIGN KEY(grant_id) REFERENCES grants(id) ON DELETE CASCADE,
	CHECK(length(key) <= 256),
	CHECK(length(value) <= 256)
)`
	schemaDefinitionLabelsTableStatement = `
CREATE TABLE IF NOT EXISTS schema_definition_labels (
	schema_definition_id TEXT NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY (schema_definition_id, key),
	FOREIGN KEY(schema_definition_id) REFERENCES schema_definitions(id) ON DELETE CASCADE,
	CHECK(length(key) <= 256),
	CHECK(length(value) <= 256)
)`
)
const (
	hostLabelsTable             = "host_labels"
	requestLabelsTable          = "request_labels"
	registerLabelsTable         = "register_labels"
	grantLabelsTable            = "grant_labels"
	schemaDefinitionLabelsTable = "schema_definition_labels"
)
const maxLabelLength = 256

// New opens or creates the sqlite database at the given path and prepares it
// for use by the server.
func New(ctx context.Context, path string) (Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1)

	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		if cerr := db.Close(); cerr != nil {
			logrus.WithError(cerr).Warn("close sqlite database after foreign key setup failure")
		}
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	return &sqliteStore{db: db, namespace: unknownNamespace}, nil
}

// Close tears down the underlying database connection.
func (s *sqliteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// DB exposes the underlying *sql.DB for helpers and tests.
func (s *sqliteStore) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

// Migrate ensures the schema for hosts, requests, and grants exists.
func (s *sqliteStore) Migrate(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
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

func (s *sqliteStore) ensureHostsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, hostsTableStatement); err != nil {
		return fmt.Errorf("create hosts table: %w", err)
	}
	if err := ensureSQLiteColumn(ctx, tx, "hosts", "unique_key", "TEXT"); err != nil {
		return fmt.Errorf("add hosts unique_key column: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS hosts_unique_key_idx ON hosts(unique_key) WHERE unique_key IS NOT NULL`); err != nil {
		return fmt.Errorf("create hosts unique_key index: %w", err)
	}
	return nil
}

func (s *sqliteStore) ensureRequestsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, requestsTableStatement); err != nil {
		return fmt.Errorf("create requests table: %w", err)
	}
	if err := ensureSQLiteColumn(ctx, tx, "requests", "request_schema_definition_id", "TEXT"); err != nil {
		return fmt.Errorf("add requests request_schema_definition_id column: %w", err)
	}
	if err := ensureSQLiteColumn(ctx, tx, "requests", "grant_schema_definition_id", "TEXT"); err != nil {
		return fmt.Errorf("add requests grant_schema_definition_id column: %w", err)
	}
	if err := ensureSQLiteColumn(ctx, tx, "requests", "unique_key", "TEXT"); err != nil {
		return fmt.Errorf("add requests unique_key column: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS requests_unique_key_idx ON requests(unique_key) WHERE unique_key IS NOT NULL`); err != nil {
		return fmt.Errorf("create requests unique_key index: %w", err)
	}
	if err := migrateSQLiteRequestSchemaDefinitions(ctx, tx); err != nil {
		return err
	}
	return nil
}

func (s *sqliteStore) ensureSchemaDefinitionsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, schemaDefinitionsTableStatement); err != nil {
		return fmt.Errorf("create schema definitions table: %w", err)
	}
	if err := ensureSQLiteColumn(ctx, tx, "schema_definitions", "unique_key", "TEXT"); err != nil {
		return fmt.Errorf("add schema_definitions unique_key column: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS schema_definitions_unique_key_idx ON schema_definitions(unique_key) WHERE unique_key IS NOT NULL`); err != nil {
		return fmt.Errorf("create schema_definitions unique_key index: %w", err)
	}
	if err := ensureSQLiteColumn(ctx, tx, "schema_definitions", "schema", "TEXT"); err != nil {
		return fmt.Errorf("add schema_definitions schema column: %w", err)
	}
	if err := migrateSQLiteSchemaDefinitions(ctx, tx); err != nil {
		return err
	}
	return nil
}

func (s *sqliteStore) ensureRegistersTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, registersTableStatement); err != nil {
		return fmt.Errorf("create registers table: %w", err)
	}
	if err := ensureSQLiteColumn(ctx, tx, "registers", "schema_definition_id", "TEXT"); err != nil {
		return fmt.Errorf("add registers schema_definition_id column: %w", err)
	}
	if err := ensureSQLiteColumn(ctx, tx, "registers", "unique_key", "TEXT"); err != nil {
		return fmt.Errorf("add registers unique_key column: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS registers_unique_key_idx ON registers(unique_key) WHERE unique_key IS NOT NULL`); err != nil {
		return fmt.Errorf("create registers unique_key index: %w", err)
	}
	return nil
}

func (s *sqliteStore) ensureGrantsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, grantsTableStatement); err != nil {
		return fmt.Errorf("create grants table: %w", err)
	}
	return nil
}

func (s *sqliteStore) ensureHostLabelsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, hostLabelsTableStatement); err != nil {
		return fmt.Errorf("create host labels table: %w", err)
	}
	return nil
}

func (s *sqliteStore) ensureRequestLabelsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, requestLabelsTableStatement); err != nil {
		return fmt.Errorf("create request labels table: %w", err)
	}
	return nil
}

func (s *sqliteStore) ensureRegisterLabelsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, registerLabelsTableStatement); err != nil {
		return fmt.Errorf("create register labels table: %w", err)
	}
	return nil
}

func (s *sqliteStore) ensureGrantLabelsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, grantLabelsTableStatement); err != nil {
		return fmt.Errorf("create grant labels table: %w", err)
	}
	return nil
}

func (s *sqliteStore) ensureSchemaDefinitionLabelsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, schemaDefinitionLabelsTableStatement); err != nil {
		return fmt.Errorf("create schema definition labels table: %w", err)
	}
	return nil
}

func ensureSQLiteColumn(ctx context.Context, tx *sql.Tx, table, column, columnType string) error {
	exists, err := sqliteColumnExists(ctx, tx, table, column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, columnType))
	return err
}

func sqliteColumnExists(ctx context.Context, tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false, err
	}
	defer closeRows(rows, "close table_info rows")

	for rows.Next() {
		var (
			cid        int
			name       string
			colType    string
			notNull    int
			defaultV   any
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultV, &primaryKey); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func migrateSQLiteSchemaDefinitions(ctx context.Context, tx *sql.Tx) error {
	requestExists, err := sqliteColumnExists(ctx, tx, "schema_definitions", "request_schema")
	if err != nil {
		return fmt.Errorf("check schema_definitions request_schema column: %w", err)
	}
	grantExists, err := sqliteColumnExists(ctx, tx, "schema_definitions", "grant_schema")
	if err != nil {
		return fmt.Errorf("check schema_definitions grant_schema column: %w", err)
	}
	if !requestExists && !grantExists {
		return nil
	}

	update := `UPDATE schema_definitions SET schema = COALESCE(schema`
	if requestExists {
		update += `, request_schema`
	}
	if grantExists {
		update += `, grant_schema`
	}
	update += `) WHERE (schema IS NULL OR schema = '')`

	if _, err := tx.ExecContext(ctx, update); err != nil {
		return fmt.Errorf("backfill schema_definitions schema: %w", err)
	}
	return nil
}

func migrateSQLiteRequestSchemaDefinitions(ctx context.Context, tx *sql.Tx) error {
	exists, err := sqliteColumnExists(ctx, tx, "requests", "schema_definition_id")
	if err != nil {
		return fmt.Errorf("check requests schema_definition_id column: %w", err)
	}
	if !exists {
		return nil
	}

	if _, err := tx.ExecContext(ctx, `
UPDATE requests
SET request_schema_definition_id = COALESCE(request_schema_definition_id, schema_definition_id),
    grant_schema_definition_id = COALESCE(grant_schema_definition_id, schema_definition_id)
WHERE schema_definition_id IS NOT NULL
`); err != nil {
		return fmt.Errorf("backfill request schema definition ids: %w", err)
	}

	requestSchemaExists, err := sqliteColumnExists(ctx, tx, "schema_definitions", "request_schema")
	if err != nil {
		return fmt.Errorf("check schema_definitions request_schema column: %w", err)
	}
	grantSchemaExists, err := sqliteColumnExists(ctx, tx, "schema_definitions", "grant_schema")
	if err != nil {
		return fmt.Errorf("check schema_definitions grant_schema column: %w", err)
	}
	if !requestSchemaExists || !grantSchemaExists {
		return nil
	}

	rows, err := tx.QueryContext(ctx, `SELECT id, request_schema, grant_schema FROM schema_definitions`)
	if err != nil {
		return fmt.Errorf("load legacy schema definitions: %w", err)
	}
	defer closeRows(rows, "close legacy schema definitions")

	type legacySchema struct {
		defID      string
		grantValue string
	}
	var legacy []legacySchema
	for rows.Next() {
		var (
			defID       string
			reqSchema   sql.NullString
			grantSchema sql.NullString
		)
		if err := rows.Scan(&defID, &reqSchema, &grantSchema); err != nil {
			return fmt.Errorf("scan legacy schema definition: %w", err)
		}
		if !reqSchema.Valid || !grantSchema.Valid {
			continue
		}
		reqValue := strings.TrimSpace(reqSchema.String)
		grantValue := strings.TrimSpace(grantSchema.String)
		if reqValue == "" || grantValue == "" || reqValue == grantValue {
			continue
		}
		legacy = append(legacy, legacySchema{defID: defID, grantValue: grantValue})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy schema definitions: %w", err)
	}

	for _, entry := range legacy {
		var remaining int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM requests WHERE grant_schema_definition_id = ?`, entry.defID).Scan(&remaining); err != nil {
			return fmt.Errorf("count grant schema references: %w", err)
		}
		if remaining == 0 {
			continue
		}
		grantDefID := generateID()
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_definitions (id, schema) VALUES (?, ?)`, grantDefID, entry.grantValue); err != nil {
			return fmt.Errorf("create grant schema definition: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE requests
SET grant_schema_definition_id = ?
WHERE grant_schema_definition_id = ?
`, grantDefID, entry.defID); err != nil {
			return fmt.Errorf("update grant schema references: %w", err)
		}
	}
	return nil
}

// CreateHost registers a new host with the given labels.
func (s *sqliteStore) CreateHost(ctx context.Context, host Host) (Host, error) {
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

	var uniqueKey any
	if host.UniqueKey != "" {
		uniqueKey = host.UniqueKey
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO hosts (id, unique_key)
VALUES (?, ?)
`, host.ID, uniqueKey); err != nil {
		if isUniqueConstraintError(err) {
			if isUniqueHostKeyConstraintError(err) {
				return Host{}, ErrHostUniqueKeyConflict
			}
			return Host{}, ErrHostAlreadyExists
		}
		return Host{}, fmt.Errorf("insert host: %w", err)
	}

	if err := insertLabels(ctx, tx, hostLabelsTable, "host_id", host.ID, host.Labels); err != nil {
		return Host{}, fmt.Errorf("insert host labels: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Host{}, fmt.Errorf("commit host creation: %w", err)
	}

	return host, nil
}

// GetHost returns the host for the given identifier.
func (s *sqliteStore) GetHost(ctx context.Context, id string) (Host, error) {
	if s == nil || s.db == nil {
		return Host{}, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("hosts", "get", logrus.Fields{
		"host_id": id,
	})

	row := s.db.QueryRowContext(ctx, `
SELECT id, unique_key, created_at
FROM hosts
WHERE id = ?
`, id)
	host, err := scanHost(row)
	if err != nil {
		return Host{}, err
	}
	host.Labels, err = s.loadLabels(ctx, hostLabelsTable, "host_id", host.ID)
	if err != nil {
		return Host{}, fmt.Errorf("load host labels: %w", err)
	}
	return host, nil
}

// ListHosts returns every host stored in the database ordered by creation.
func (s *sqliteStore) ListHosts(ctx context.Context) ([]Host, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("hosts", "list", nil)

	rows, err := s.db.QueryContext(ctx, `
SELECT id, unique_key, created_at
FROM hosts
ORDER BY created_at ASC
`)
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
		if hosts[i].Labels, err = s.loadLabels(ctx, hostLabelsTable, "host_id", hosts[i].ID); err != nil {
			return nil, fmt.Errorf("load host labels: %w", err)
		}
	}

	return hosts, nil
}

// DeleteHost removes a host from storage.
func (s *sqliteStore) DeleteHost(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("hosts", "delete", logrus.Fields{
		"host_id": id,
	})

	res, err := s.db.ExecContext(ctx, `DELETE FROM hosts WHERE id = ?`, id)
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
func (s *sqliteStore) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) error {
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

	if err := replaceLabels(ctx, tx, hostLabelsTable, "host_id", id, labels); err != nil {
		return fmt.Errorf("replace host labels: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit host labels transaction: %w", err)
	}

	return nil
}

// CreateRequest inserts a new request record into storage.
func (s *sqliteStore) CreateRequest(ctx context.Context, req Request) (Request, error) {
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
		"payload":                      req.Payload,
		"labels":                       req.Labels,
	})

	payloadValue, err := encodeJSON(req.Payload)
	if err != nil {
		return Request{}, fmt.Errorf("encode request payload: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Request{}, fmt.Errorf("begin request transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback create request transaction")

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
	if _, err := tx.ExecContext(ctx, `
INSERT INTO requests (id, host_id, request_schema_definition_id, grant_schema_definition_id, unique_key, data)
VALUES (?, ?, ?, ?, ?, ?)
`, req.ID, req.HostID, requestSchemaID, grantSchemaID, uniqueKey, payloadValue); err != nil {
		if isUniqueConstraintError(err) {
			if isUniqueKeyConstraintError(err) {
				return Request{}, fmt.Errorf("%w: %w", ErrRequestUniqueKeyConflict, err)
			}
			return Request{}, fmt.Errorf("%w: %w", ErrRequestAlreadyExists, err)
		}
		return Request{}, fmt.Errorf("insert request: %w", err)
	}

	if err := insertLabels(ctx, tx, requestLabelsTable, "request_id", req.ID, req.Labels); err != nil {
		return Request{}, fmt.Errorf("insert request labels: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Request{}, fmt.Errorf("commit request creation: %w", err)
	}

	return req, nil
}

// GetRequest fetches a request by its identifier.
func (s *sqliteStore) GetRequest(ctx context.Context, id string) (Request, error) {
	if s == nil || s.db == nil {
		return Request{}, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("requests", "get", logrus.Fields{
		"request_id": id,
	})

	row := s.db.QueryRowContext(ctx, `
SELECT id, host_id, request_schema_definition_id, grant_schema_definition_id, unique_key, data,
       CASE WHEN EXISTS (SELECT 1 FROM grants WHERE request_id = requests.id) THEN 1 ELSE 0 END AS has_grant,
       created_at, updated_at
FROM requests
WHERE id = ?
`, id)

	req, err := scanRequest(row)
	if err != nil {
		return Request{}, err
	}
	req.Labels, err = s.loadLabels(ctx, requestLabelsTable, "request_id", req.ID)
	if err != nil {
		return Request{}, fmt.Errorf("load request labels: %w", err)
	}
	return req, nil
}

// ListRequests returns stored requests ordered by creation time.
func (s *sqliteStore) ListRequests(ctx context.Context, filters *RequestListFilters) ([]Request, error) {
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
	query.WriteString(`
SELECT id, host_id, request_schema_definition_id, grant_schema_definition_id, unique_key, data,
       CASE WHEN EXISTS (SELECT 1 FROM grants WHERE request_id = requests.id) THEN 1 ELSE 0 END AS has_grant,
       created_at, updated_at
FROM requests`)

	var args []any
	var where []string
	if filters != nil {
		if filters.HasGrant != nil {
			if *filters.HasGrant {
				where = append(where, "EXISTS (SELECT 1 FROM grants WHERE request_id = requests.id)")
			} else {
				where = append(where, "NOT EXISTS (SELECT 1 FROM grants WHERE request_id = requests.id)")
			}
		}
		for key, value := range filters.Labels {
			where = append(where, "EXISTS (SELECT 1 FROM request_labels WHERE request_id = requests.id AND key = ? AND value = ?)")
			args = append(args, key, value)
		}
		for key, value := range filters.HostLabels {
			where = append(where, "EXISTS (SELECT 1 FROM host_labels WHERE host_id = requests.host_id AND key = ? AND value = ?)")
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
		if requests[i].Labels, err = s.loadLabels(ctx, requestLabelsTable, "request_id", requests[i].ID); err != nil {
			return nil, fmt.Errorf("load request labels: %w", err)
		}
	}

	return requests, nil
}

// CountRequestsByGrantPresence returns the number of requests grouped by whether they already have a grant.
func (s *sqliteStore) CountRequestsByGrantPresence(ctx context.Context) (map[string]int64, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("requests", "count_by_grant_presence", nil)

	var withGrant, withoutGrant int64
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM requests
WHERE EXISTS (SELECT 1 FROM grants WHERE grants.request_id = requests.id)
`).Scan(&withGrant); err != nil {
		return nil, fmt.Errorf("count requests with grant: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM requests
WHERE NOT EXISTS (SELECT 1 FROM grants WHERE grants.request_id = requests.id)
`).Scan(&withoutGrant); err != nil {
		return nil, fmt.Errorf("count requests without grant: %w", err)
	}

	counts := map[string]int64{
		"with_grant":    withGrant,
		"without_grant": withoutGrant,
	}
	return counts, nil
}

func (s *sqliteStore) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	fields := logrus.Fields{
		"request_id": id,
		"labels":     labels,
	}

	s.logDBOperation("requests", "update_labels", fields)

	if _, err := s.GetRequest(ctx, id); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin request labels transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback request labels transaction")

	if err := replaceLabels(ctx, tx, requestLabelsTable, "request_id", id, labels); err != nil {
		return fmt.Errorf("replace request labels: %w", err)
	}

	if err := setUpdatedAt(ctx, tx, "requests", "id", id, "strftime('%Y-%m-%d %H:%M:%f', 'now')"); err != nil {
		return fmt.Errorf("refresh request timestamp: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit request labels update: %w", err)
	}

	return nil
}

// DeleteRequest removes a request from storage.
func (s *sqliteStore) DeleteRequest(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("requests", "delete", logrus.Fields{
		"request_id": id,
	})

	res, err := s.db.ExecContext(ctx, `DELETE FROM requests WHERE id = ?`, id)
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

	return nil
}

// CreateRegister inserts a new register record into storage.
func (s *sqliteStore) CreateRegister(ctx context.Context, reg Register) (Register, error) {
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

	var uniqueKey any
	if reg.UniqueKey != "" {
		uniqueKey = reg.UniqueKey
	}
	var schemaDefinitionID any
	if reg.SchemaDefinitionID != "" {
		schemaDefinitionID = reg.SchemaDefinitionID
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO registers (id, host_id, schema_definition_id, unique_key, data)
VALUES (?, ?, ?, ?, ?)
`, reg.ID, reg.HostID, schemaDefinitionID, uniqueKey, payloadValue); err != nil {
		if isUniqueConstraintError(err) {
			if isUniqueRegisterKeyConstraintError(err) {
				return Register{}, fmt.Errorf("%w: %w", ErrRegisterUniqueKeyConflict, err)
			}
			return Register{}, fmt.Errorf("%w: %w", ErrRegisterAlreadyExists, err)
		}
		return Register{}, fmt.Errorf("insert register: %w", err)
	}

	if err := insertLabels(ctx, tx, registerLabelsTable, "register_id", reg.ID, reg.Labels); err != nil {
		return Register{}, fmt.Errorf("insert register labels: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Register{}, fmt.Errorf("commit register creation: %w", err)
	}

	return reg, nil
}

// GetRegister fetches a register record by its identifier.
func (s *sqliteStore) GetRegister(ctx context.Context, id string) (Register, error) {
	if s == nil || s.db == nil {
		return Register{}, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("registers", "get", logrus.Fields{
		"register_id": id,
	})

	row := s.db.QueryRowContext(ctx, `
SELECT id, host_id, schema_definition_id, unique_key, data, created_at, updated_at
FROM registers
WHERE id = ?
`, id)

	reg, err := scanRegister(row)
	if err != nil {
		return Register{}, err
	}
	reg.Labels, err = s.loadLabels(ctx, registerLabelsTable, "register_id", reg.ID)
	if err != nil {
		return Register{}, fmt.Errorf("load register labels: %w", err)
	}
	return reg, nil
}

// ListRegisters returns stored registers ordered by creation time.
func (s *sqliteStore) ListRegisters(ctx context.Context, filters *RegisterListFilters) ([]Register, error) {
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
	query.WriteString(`
SELECT id, host_id, schema_definition_id, unique_key, data, created_at, updated_at
FROM registers`)

	var args []any
	var where []string
	if filters != nil {
		for key, value := range filters.Labels {
			where = append(where, "EXISTS (SELECT 1 FROM register_labels WHERE register_id = registers.id AND key = ? AND value = ?)")
			args = append(args, key, value)
		}
		for key, value := range filters.HostLabels {
			where = append(where, "EXISTS (SELECT 1 FROM host_labels WHERE host_id = registers.host_id AND key = ? AND value = ?)")
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
		if registers[i].Labels, err = s.loadLabels(ctx, registerLabelsTable, "register_id", registers[i].ID); err != nil {
			return nil, fmt.Errorf("load register labels: %w", err)
		}
	}
	return registers, nil
}

// UpdateRegisterLabels replaces the labels stored for a register record.
func (s *sqliteStore) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	fields := logrus.Fields{
		"register_id": id,
		"labels":      labels,
	}
	s.logDBOperation("registers", "update_labels", fields)
	if _, err := s.GetRegister(ctx, id); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin register labels transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback register labels transaction")

	if err := replaceLabels(ctx, tx, registerLabelsTable, "register_id", id, labels); err != nil {
		return fmt.Errorf("replace register labels: %w", err)
	}

	if err := setUpdatedAt(ctx, tx, "registers", "id", id, "strftime('%Y-%m-%d %H:%M:%f', 'now')"); err != nil {
		return fmt.Errorf("refresh register timestamp: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit register labels update: %w", err)
	}

	return nil
}

// DeleteRegister removes a register record from storage.
func (s *sqliteStore) DeleteRegister(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("registers", "delete", logrus.Fields{
		"register_id": id,
	})

	res, err := s.db.ExecContext(ctx, `DELETE FROM registers WHERE id = ?`, id)
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

	return nil
}

// CountRegisters returns the total number of registers.
func (s *sqliteStore) CountRegisters(ctx context.Context) (map[string]int64, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}
	s.logDBOperation("registers", "count", nil)
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registers`).Scan(&total); err != nil {
		return nil, fmt.Errorf("count registers: %w", err)
	}
	return map[string]int64{"total": total}, nil
}

// CreateGrant stores a new grant with its payload.
func (s *sqliteStore) CreateGrant(ctx context.Context, grant Grant) (Grant, error) {
	if s == nil || s.db == nil {
		return Grant{}, fmt.Errorf("store not initialized")
	}
	if grant.RequestID == "" {
		return Grant{}, fmt.Errorf("request_id is required")
	}
	if err := s.ensureRequestExists(ctx, grant.RequestID); err != nil {
		return Grant{}, err
	}

	grant.ID = generateID()

	s.logDBOperation("grants", "create", logrus.Fields{
		"grant_id":   grant.ID,
		"request_id": grant.RequestID,
		"payload":    grant.Payload,
	})

	payloadValue, err := encodeJSON(grant.Payload)
	if err != nil {
		return Grant{}, fmt.Errorf("encode grant payload: %w", err)
	}

	if _, err := s.db.ExecContext(ctx, `
INSERT INTO grants (id, request_id, payload)
VALUES (?, ?, ?)
`, grant.ID, grant.RequestID, payloadValue); err != nil {
		if isUniqueConstraintError(err) {
			return Grant{}, fmt.Errorf("%w: %w", ErrGrantAlreadyExists, err)
		}
		return Grant{}, fmt.Errorf("insert grant: %w", err)
	}

	return grant, nil
}

// GetGrant retrieves a grant by ID.
func (s *sqliteStore) GetGrant(ctx context.Context, id string) (Grant, error) {
	if s == nil || s.db == nil {
		return Grant{}, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "get", logrus.Fields{
		"grant_id": id,
	})

	row := s.db.QueryRowContext(ctx, `
SELECT id, request_id, payload, created_at, updated_at
FROM grants
WHERE id = ?
`, id)
	return scanGrant(row)
}

// ListGrants returns every stored grant ordered by creation.
func (s *sqliteStore) ListGrants(ctx context.Context) ([]Grant, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "list", nil)

	rows, err := s.db.QueryContext(ctx, `
SELECT id, request_id, payload, created_at, updated_at
FROM grants
ORDER BY created_at ASC
`)
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
func (s *sqliteStore) CountGrants(ctx context.Context) (map[string]int64, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "count", nil)

	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM grants`).Scan(&total); err != nil {
		return nil, fmt.Errorf("count grants: %w", err)
	}
	return map[string]int64{"total": total}, nil
}

// GetGrantForRequest returns the grant for the request.
func (s *sqliteStore) GetGrantForRequest(ctx context.Context, requestID string) (Grant, bool, error) {
	if s == nil || s.db == nil {
		return Grant{}, false, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "get_for_request", logrus.Fields{
		"request_id": requestID,
	})

	row := s.db.QueryRowContext(ctx, `
SELECT id, request_id, payload, created_at, updated_at
FROM grants
WHERE request_id = ?
ORDER BY created_at DESC
LIMIT 1
`, requestID)

	grant, err := scanGrant(row)
	if err != nil {
		if errors.Is(err, ErrGrantNotFound) {
			return Grant{}, false, nil
		}
		return Grant{}, false, fmt.Errorf("get grant for request: %w", err)
	}

	return grant, true, nil
}

// DeleteGrant removes a grant record.
func (s *sqliteStore) DeleteGrant(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "delete", logrus.Fields{
		"grant_id": id,
	})

	res, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE id = ?`, id)
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

	return nil
}

// CreateSchemaDefinition stores a new schema definition.
func (s *sqliteStore) CreateSchemaDefinition(ctx context.Context, def SchemaDefinition) (SchemaDefinition, error) {
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

	if _, err := tx.ExecContext(ctx, `
INSERT INTO schema_definitions (id, unique_key, schema)
VALUES (?, ?, ?)
`, def.ID, nullableText(def.UniqueKey), schemaValue); err != nil {
		switch {
		case isUniqueSchemaDefinitionKeyConstraintError(err):
			return SchemaDefinition{}, fmt.Errorf("%w: %w", ErrSchemaDefinitionUniqueKeyConflict, err)
		case isUniqueConstraintError(err):
			return SchemaDefinition{}, fmt.Errorf("%w: %w", ErrSchemaDefinitionAlreadyExists, err)
		default:
			return SchemaDefinition{}, fmt.Errorf("insert schema definition: %w", err)
		}
	}
	if err := insertLabels(ctx, tx, schemaDefinitionLabelsTable, "schema_definition_id", def.ID, def.Labels); err != nil {
		return SchemaDefinition{}, fmt.Errorf("insert schema definition labels: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return SchemaDefinition{}, fmt.Errorf("commit schema definition transaction: %w", err)
	}

	return def, nil
}

// GetSchemaDefinition returns a schema definition by ID.
func (s *sqliteStore) GetSchemaDefinition(ctx context.Context, id string) (SchemaDefinition, error) {
	if s == nil || s.db == nil {
		return SchemaDefinition{}, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("schema_definitions", "get", logrus.Fields{
		"schema_definition_id": id,
	})

	row := s.db.QueryRowContext(ctx, `
SELECT id, unique_key, schema, created_at
FROM schema_definitions
WHERE id = ?
`, id)
	def, err := scanSchemaDefinition(row)
	if err != nil {
		return SchemaDefinition{}, err
	}
	def.Labels, err = s.loadLabels(ctx, schemaDefinitionLabelsTable, "schema_definition_id", def.ID)
	if err != nil {
		return SchemaDefinition{}, fmt.Errorf("load schema definition labels: %w", err)
	}
	return def, nil
}

// ListSchemaDefinitions returns stored schema definitions ordered by creation time.
func (s *sqliteStore) ListSchemaDefinitions(ctx context.Context) ([]SchemaDefinition, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("schema_definitions", "list", nil)

	rows, err := s.db.QueryContext(ctx, `
SELECT id, unique_key, schema, created_at
FROM schema_definitions
ORDER BY created_at ASC
`)
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
		defs[i].Labels, err = s.loadLabels(ctx, schemaDefinitionLabelsTable, "schema_definition_id", defs[i].ID)
		if err != nil {
			return nil, fmt.Errorf("load schema definition labels: %w", err)
		}
	}
	return defs, nil
}

// DeleteSchemaDefinition removes a schema definition.
func (s *sqliteStore) DeleteSchemaDefinition(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("schema_definitions", "delete", logrus.Fields{
		"schema_definition_id": id,
	})

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema definition delete transaction: %w", err)
	}
	defer rollbackTx(tx, "rollback schema definition delete transaction")

	if _, err := tx.ExecContext(ctx, `
UPDATE requests
SET request_schema_definition_id = NULL,
    grant_schema_definition_id = NULL
WHERE request_schema_definition_id = ?
   OR grant_schema_definition_id = ?
`, id, id); err != nil {
		return fmt.Errorf("null request schema definition references: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
UPDATE registers
SET schema_definition_id = NULL
WHERE schema_definition_id = ?
`, id); err != nil {
		return fmt.Errorf("null register schema definition references: %w", err)
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM schema_definitions WHERE id = ?`, id)
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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema definition delete transaction: %w", err)
	}

	return nil
}

// UpdateSchemaDefinitionLabels replaces the labels stored for a schema definition.
func (s *sqliteStore) UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) error {
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

	if err := replaceLabels(ctx, tx, schemaDefinitionLabelsTable, "schema_definition_id", id, labels); err != nil {
		return fmt.Errorf("replace schema definition labels: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema definition labels transaction: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanHost(scanner rowScanner) (Host, error) {
	var (
		host      Host
		uniqueKey sql.NullString
		createdAt any
	)

	if err := scanner.Scan(&host.ID, &uniqueKey, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Host{}, ErrHostNotFound
		}
		return Host{}, err
	}

	if uniqueKey.Valid {
		host.UniqueKey = uniqueKey.String
	}

	t, err := parseDBTime(createdAt)
	if err != nil {
		return Host{}, err
	}
	host.CreatedAt = t

	return host, nil
}

func scanRequest(scanner rowScanner) (Request, error) {
	var (
		req             Request
		requestSchemaID sql.NullString
		grantSchemaID   sql.NullString
		uniqueKey       sql.NullString
		payloadValue    sql.NullString
		hasGrant        sql.NullInt64
		createdAt       any
		updatedAt       any
	)

	if err := scanner.Scan(&req.ID, &req.HostID, &requestSchemaID, &grantSchemaID, &uniqueKey, &payloadValue, &hasGrant, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Request{}, ErrRequestNotFound
		}
		return Request{}, err
	}

	if requestSchemaID.Valid {
		req.RequestSchemaDefinitionID = requestSchemaID.String
	}
	if grantSchemaID.Valid {
		req.GrantSchemaDefinitionID = grantSchemaID.String
	}
	if uniqueKey.Valid {
		req.UniqueKey = uniqueKey.String
	}

	var err error
	req.Payload, err = decodeAnyMap(payloadValue)
	if err != nil {
		return Request{}, fmt.Errorf("decode request payload: %w", err)
	}

	if req.CreatedAt, err = parseDBTime(createdAt); err != nil {
		return Request{}, err
	}
	if req.UpdatedAt, err = parseDBTime(updatedAt); err != nil {
		return Request{}, err
	}

	req.HasGrant = hasGrant.Valid && hasGrant.Int64 > 0

	return req, nil
}

func scanSchemaDefinition(scanner rowScanner) (SchemaDefinition, error) {
	var (
		def       SchemaDefinition
		uniqueKey sql.NullString
		schemaVal sql.NullString
		createdAt any
	)

	if err := scanner.Scan(&def.ID, &uniqueKey, &schemaVal, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SchemaDefinition{}, ErrSchemaDefinitionNotFound
		}
		return SchemaDefinition{}, err
	}
	if uniqueKey.Valid {
		def.UniqueKey = uniqueKey.String
	}

	var err error
	def.Schema, err = decodeRawJSON(schemaVal)
	if err != nil {
		return SchemaDefinition{}, fmt.Errorf("decode schema: %w", err)
	}

	if def.CreatedAt, err = parseDBTime(createdAt); err != nil {
		return SchemaDefinition{}, err
	}

	return def, nil
}

func scanRegister(scanner rowScanner) (Register, error) {
	var (
		reg          Register
		schemaID     sql.NullString
		uniqueKey    sql.NullString
		payloadValue sql.NullString
		createdAt    any
		updatedAt    any
	)

	if err := scanner.Scan(&reg.ID, &reg.HostID, &schemaID, &uniqueKey, &payloadValue, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Register{}, ErrRegisterNotFound
		}
		return Register{}, err
	}

	if schemaID.Valid {
		reg.SchemaDefinitionID = schemaID.String
	}
	if uniqueKey.Valid {
		reg.UniqueKey = uniqueKey.String
	}

	var err error
	reg.Payload, err = decodeAnyMap(payloadValue)
	if err != nil {
		return Register{}, fmt.Errorf("decode register payload: %w", err)
	}

	if reg.CreatedAt, err = parseDBTime(createdAt); err != nil {
		return Register{}, err
	}
	if reg.UpdatedAt, err = parseDBTime(updatedAt); err != nil {
		return Register{}, err
	}

	return reg, nil
}

func scanGrant(scanner rowScanner) (Grant, error) {
	var (
		grant     Grant
		payload   sql.NullString
		createdAt any
		updatedAt any
	)

	if err := scanner.Scan(&grant.ID, &grant.RequestID, &payload, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Grant{}, ErrGrantNotFound
		}
		return Grant{}, err
	}

	var err error
	grant.Payload, err = decodeAnyMap(payload)
	if err != nil {
		return Grant{}, fmt.Errorf("decode grant payload: %w", err)
	}

	if grant.CreatedAt, err = parseDBTime(createdAt); err != nil {
		return Grant{}, err
	}
	if grant.UpdatedAt, err = parseDBTime(updatedAt); err != nil {
		return Grant{}, err
	}

	return grant, nil
}

func parseCreatedAt(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}

	layouts := []string{
		createdAtLayout,
		time.RFC3339Nano,
		time.RFC3339,
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, value); err == nil {
			return ts, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid timestamp %q", value)
}

func parseDBTime(value any) (time.Time, error) {
	switch v := value.(type) {
	case time.Time:
		return v, nil
	case string:
		return parseCreatedAt(v)
	case []byte:
		return parseCreatedAt(string(v))
	case nil:
		return time.Time{}, nil
	default:
		return time.Time{}, fmt.Errorf("invalid timestamp %v", value)
	}
}

func generateID() string {
	return uuid.NewString()
}

func encodeJSON(value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func decodeAnyMap(value sql.NullString) (map[string]any, error) {
	if !value.Valid || value.String == "" {
		return nil, nil
	}
	var dest map[string]any
	if err := json.Unmarshal([]byte(value.String), &dest); err != nil {
		return nil, err
	}
	return dest, nil
}

func decodeRawJSON(value sql.NullString) (json.RawMessage, error) {
	if !value.Valid || value.String == "" {
		return nil, nil
	}
	if !json.Valid([]byte(value.String)) {
		return nil, fmt.Errorf("invalid JSON payload")
	}
	return json.RawMessage([]byte(value.String)), nil
}

func nullableText(value string) any {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return trimmed
}

func insertLabels(ctx context.Context, tx *sql.Tx, table, idColumn, id string, labels map[string]string) error {
	if len(labels) == 0 {
		return nil
	}

	stmt := fmt.Sprintf(`INSERT INTO %s (%s, key, value) VALUES (?, ?, ?)`, table, idColumn)
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

func replaceLabels(ctx context.Context, tx *sql.Tx, table, idColumn, id string, labels map[string]string) error {
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE %s = ?`, table, idColumn), id); err != nil {
		return fmt.Errorf("delete labels: %w", err)
	}
	return insertLabels(ctx, tx, table, idColumn, id, labels)
}

func setUpdatedAt(ctx context.Context, tx *sql.Tx, table, idColumn, id, nowExpr string) error {
	stmt := fmt.Sprintf(`UPDATE %s SET updated_at = %s WHERE %s = ?`, table, nowExpr, idColumn)
	if _, err := tx.ExecContext(ctx, stmt, id); err != nil {
		return fmt.Errorf("update %s timestamp: %w", table, err)
	}
	return nil
}

func (s *sqliteStore) loadLabels(ctx context.Context, table, idColumn, id string) (map[string]string, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`SELECT key, value FROM %s WHERE %s = ? ORDER BY key ASC`, table, idColumn), id)
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
