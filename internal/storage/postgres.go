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
		{"requests", s.ensureRequestsTable},
		{"registers", s.ensureRegistersTable},
		{"grants", s.ensureGrantsTable},
		{"host labels", s.ensureHostLabelsTable},
		{"request labels", s.ensureRequestLabelsTable},
		{"register labels", s.ensureRegisterLabelsTable},
		{"grant labels", s.ensureGrantLabelsTable},
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
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`, s.table("hosts"))
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create hosts table: %w", err)
	}
	return nil
}

func (s *postgresStore) ensureRequestsTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	id TEXT PRIMARY KEY,
	host_id TEXT NOT NULL,
	data JSONB,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	FOREIGN KEY(host_id) REFERENCES %s(id) ON DELETE CASCADE
)`, s.table("requests"), s.table("hosts"))
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create requests table: %w", err)
	}
	return nil
}

func (s *postgresStore) ensureRegistersTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	id TEXT PRIMARY KEY,
	host_id TEXT NOT NULL,
	data JSONB,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	FOREIGN KEY(host_id) REFERENCES %s(id) ON DELETE CASCADE
)`, s.table("registers"), s.table("hosts"))
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create registers table: %w", err)
	}
	return nil
}

func (s *postgresStore) ensureGrantsTable(ctx context.Context, tx *sql.Tx) error {
	stmt := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s (
	id TEXT PRIMARY KEY,
	request_id TEXT NOT NULL,
	payload JSONB,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	FOREIGN KEY(request_id) REFERENCES %s(id) ON DELETE CASCADE,
	UNIQUE(request_id)
)`, s.table("grants"), s.table("requests"))
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create grants table: %w", err)
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

func (s *postgresStore) ensureRequestExists(ctx context.Context, requestID string) error {
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
		"host_id": host.ID,
		"labels":  host.Labels,
	})

	stmt := fmt.Sprintf(`INSERT INTO %s (id) VALUES ($1)`, s.table("hosts"))
	if _, err := tx.ExecContext(ctx, stmt, host.ID); err != nil {
		if isUniqueConstraintError(err) {
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

	query := fmt.Sprintf(`SELECT id, created_at FROM %s WHERE id = $1`, s.table("hosts"))
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

	query := fmt.Sprintf(`SELECT id, created_at FROM %s ORDER BY created_at ASC`, s.table("hosts"))
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
		"request_id": req.ID,
		"host_id":    req.HostID,
		"payload":    req.Payload,
		"labels":     req.Labels,
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

	stmt := fmt.Sprintf(`INSERT INTO %s (id, host_id, data) VALUES ($1, $2, $3)`, s.table("requests"))
	if _, err := tx.ExecContext(ctx, stmt, req.ID, req.HostID, payloadValue); err != nil {
		if isUniqueConstraintError(err) {
			return Request{}, fmt.Errorf("%w: %w", ErrRequestAlreadyExists, err)
		}
		return Request{}, fmt.Errorf("insert request: %w", err)
	}

	if err := insertLabelsPostgres(ctx, tx, s.table("request_labels"), "request_id", req.ID, req.Labels); err != nil {
		return Request{}, fmt.Errorf("insert request labels: %w", err)
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
SELECT id, host_id, data,
       CASE WHEN EXISTS (SELECT 1 FROM %s WHERE request_id = %s.id) THEN 1 ELSE 0 END AS has_grant,
       created_at, updated_at
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
SELECT id, host_id, data,
       CASE WHEN EXISTS (SELECT 1 FROM %s WHERE request_id = %s.id) THEN 1 ELSE 0 END AS has_grant,
       created_at, updated_at
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

func (s *postgresStore) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) error {
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

	if err := replaceLabelsPostgres(ctx, tx, s.table("request_labels"), "request_id", id, labels); err != nil {
		return fmt.Errorf("replace request labels: %w", err)
	}

	if err := setUpdatedAtPostgres(ctx, tx, s.table("requests"), "id", id, "NOW()"); err != nil {
		return fmt.Errorf("refresh request timestamp: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit request labels update: %w", err)
	}

	return nil
}

// DeleteRequest removes a request from storage.
func (s *postgresStore) DeleteRequest(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("requests", "delete", logrus.Fields{
		"request_id": id,
	})

	stmt := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, s.table("requests"))
	res, err := s.db.ExecContext(ctx, stmt, id)
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
		"register_id": reg.ID,
		"host_id":     reg.HostID,
		"payload":     reg.Payload,
		"labels":      reg.Labels,
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

	stmt := fmt.Sprintf(`INSERT INTO %s (id, host_id, data) VALUES ($1, $2, $3)`, s.table("registers"))
	if _, err := tx.ExecContext(ctx, stmt, reg.ID, reg.HostID, payloadValue); err != nil {
		if isUniqueConstraintError(err) {
			return Register{}, fmt.Errorf("%w: %w", ErrRegisterAlreadyExists, err)
		}
		return Register{}, fmt.Errorf("insert register: %w", err)
	}

	if err := insertLabelsPostgres(ctx, tx, s.table("register_labels"), "register_id", reg.ID, reg.Labels); err != nil {
		return Register{}, fmt.Errorf("insert register labels: %w", err)
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

	query := fmt.Sprintf(`SELECT id, host_id, data, created_at, updated_at FROM %s WHERE id = $1`, s.table("registers"))
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
	_, _ = fmt.Fprintf(&query, `SELECT id, host_id, data, created_at, updated_at FROM %s`, s.table("registers"))

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
func (s *postgresStore) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) error {
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

	if err := replaceLabelsPostgres(ctx, tx, s.table("register_labels"), "register_id", id, labels); err != nil {
		return fmt.Errorf("replace register labels: %w", err)
	}

	if err := setUpdatedAtPostgres(ctx, tx, s.table("registers"), "id", id, "NOW()"); err != nil {
		return fmt.Errorf("refresh register timestamp: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit register labels update: %w", err)
	}

	return nil
}

// DeleteRegister removes a register record from storage.
func (s *postgresStore) DeleteRegister(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("registers", "delete", logrus.Fields{
		"register_id": id,
	})

	stmt := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, s.table("registers"))
	res, err := s.db.ExecContext(ctx, stmt, id)
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

	stmt := fmt.Sprintf(`INSERT INTO %s (id, request_id, payload) VALUES ($1, $2, $3::jsonb)`, s.table("grants"))
	if _, err := s.db.ExecContext(ctx, stmt, grant.ID, grant.RequestID, payloadValue); err != nil {
		if isUniqueConstraintError(err) {
			return Grant{}, fmt.Errorf("%w: %w", ErrGrantAlreadyExists, err)
		}
		return Grant{}, fmt.Errorf("insert grant: %w", err)
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

	query := fmt.Sprintf(`SELECT id, request_id, payload::text, created_at, updated_at FROM %s WHERE id = $1`, s.table("grants"))
	row := s.db.QueryRowContext(ctx, query, id)
	return scanGrant(row)
}

// ListGrants returns every stored grant ordered by creation.
func (s *postgresStore) ListGrants(ctx context.Context) ([]Grant, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "list", nil)

	query := fmt.Sprintf(`SELECT id, request_id, payload::text, created_at, updated_at FROM %s ORDER BY created_at ASC`, s.table("grants"))
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

// GetLatestGrantForRequest returns the most recently created grant for the request.
func (s *postgresStore) GetLatestGrantForRequest(ctx context.Context, requestID string) (Grant, bool, error) {
	if s == nil || s.db == nil {
		return Grant{}, false, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "get_latest_for_request", logrus.Fields{
		"request_id": requestID,
	})

	query := fmt.Sprintf(`
SELECT id, request_id, payload::text, created_at, updated_at
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
		return Grant{}, false, fmt.Errorf("get latest grant for request: %w", err)
	}

	return grant, true, nil
}

// DeleteGrant removes a grant record.
func (s *postgresStore) DeleteGrant(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "delete", logrus.Fields{
		"grant_id": id,
	})

	stmt := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, s.table("grants"))
	res, err := s.db.ExecContext(ctx, stmt, id)
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
