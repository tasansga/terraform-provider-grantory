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

// Store wraps an sqlite database connection for the provisioner server.
type Store struct {
	db        *sql.DB
	namespace string
}

const unknownNamespace = "(unknown)"

// SetNamespace records the namespace associated with this store for logging.
func (s *Store) SetNamespace(namespace string) {
	if s == nil {
		return
	}
	if ns := strings.TrimSpace(namespace); ns != "" {
		s.namespace = ns
		return
	}
	s.namespace = unknownNamespace
}

func (s *Store) namespaceForLog() string {
	if s == nil {
		return unknownNamespace
	}
	if ns := strings.TrimSpace(s.namespace); ns != "" {
		return ns
	}
	return unknownNamespace
}

func (s *Store) logDBOperation(table, operation string, params logrus.Fields) {
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

func (s *Store) ensureHostExists(ctx context.Context, hostID string) error {
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

func (s *Store) ensureRequestExists(ctx context.Context, requestID string) error {
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

// Host describes the persisted labels for a registered host.
type Host struct {
	ID        string            `json:"id"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

var (
	// ErrHostNotFound is returned when a host cannot be located in storage.
	ErrHostNotFound = errors.New("host not found")
	// ErrHostAlreadyExists is returned when a host with the given ID exists.
	ErrHostAlreadyExists = errors.New("host already exists")
	// ErrRequestAlreadyExists is returned when a request with the given ID exists.
	ErrRequestAlreadyExists = errors.New("request already exists")
	// ErrGrantAlreadyExists is returned when a grant with the given ID exists.
	ErrGrantAlreadyExists = errors.New("grant already exists")
	// ErrRegisterAlreadyExists is returned when a register entry with the given ID exists.
	ErrRegisterAlreadyExists = errors.New("register already exists")
	// ErrRequestNotFound is returned when a request cannot be located.
	ErrRequestNotFound = errors.New("request not found")
	// ErrGrantNotFound is returned when a grant cannot be located.
	ErrGrantNotFound = errors.New("grant not found")
	// ErrRegisterNotFound is returned when a register entry cannot be located.
	ErrRegisterNotFound = errors.New("register not found")
	// ErrReferencedHostNotFound is returned when a request/register refers to a host that does not exist.
	ErrReferencedHostNotFound    = errors.New("referenced host not found")
	ErrReferencedRequestNotFound = errors.New("referenced request not found")
)

const createdAtLayout = "2006-01-02 15:04:05"

const (
	hostsTableStatement = `
CREATE TABLE IF NOT EXISTS hosts (
	id TEXT PRIMARY KEY,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)`
	requestsTableStatement = `
CREATE TABLE IF NOT EXISTS requests (
	id TEXT PRIMARY KEY,
	host_id TEXT NOT NULL,
	data TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
)`
	registersTableStatement = `
CREATE TABLE IF NOT EXISTS registers (
	id TEXT PRIMARY KEY,
	host_id TEXT NOT NULL,
	data TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
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
)
const (
	hostLabelsTable     = "host_labels"
	requestLabelsTable  = "request_labels"
	registerLabelsTable = "register_labels"
	grantLabelsTable    = "grant_labels"
)
const maxLabelLength = 256

// New opens or creates the sqlite database at the given path and prepares it
// for use by the server.
func New(ctx context.Context, path string) (*Store, error) {
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

	return &Store{db: db, namespace: unknownNamespace}, nil
}

// Close tears down the underlying database connection.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// DB exposes the underlying *sql.DB for helpers and tests.
func (s *Store) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

// Migrate ensures the schema for hosts, requests, and grants exists.
func (s *Store) Migrate(ctx context.Context) error {
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

func (s *Store) ensureHostsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, hostsTableStatement); err != nil {
		return fmt.Errorf("create hosts table: %w", err)
	}
	return nil
}

func (s *Store) ensureRequestsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, requestsTableStatement); err != nil {
		return fmt.Errorf("create requests table: %w", err)
	}
	return nil
}

func (s *Store) ensureRegistersTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, registersTableStatement); err != nil {
		return fmt.Errorf("create registers table: %w", err)
	}
	return nil
}

func (s *Store) ensureGrantsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, grantsTableStatement); err != nil {
		return fmt.Errorf("create grants table: %w", err)
	}
	return nil
}

func (s *Store) ensureHostLabelsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, hostLabelsTableStatement); err != nil {
		return fmt.Errorf("create host labels table: %w", err)
	}
	return nil
}

func (s *Store) ensureRequestLabelsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, requestLabelsTableStatement); err != nil {
		return fmt.Errorf("create request labels table: %w", err)
	}
	return nil
}

func (s *Store) ensureRegisterLabelsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, registerLabelsTableStatement); err != nil {
		return fmt.Errorf("create register labels table: %w", err)
	}
	return nil
}

func (s *Store) ensureGrantLabelsTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, grantLabelsTableStatement); err != nil {
		return fmt.Errorf("create grant labels table: %w", err)
	}
	return nil
}

// CreateHost registers a new host with the given labels.
func (s *Store) CreateHost(ctx context.Context, host Host) (Host, error) {
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

	if _, err := tx.ExecContext(ctx, `
INSERT INTO hosts (id)
VALUES (?)
`, host.ID); err != nil {
		if isUniqueConstraintError(err) {
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
func (s *Store) GetHost(ctx context.Context, id string) (Host, error) {
	if s == nil || s.db == nil {
		return Host{}, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("hosts", "get", logrus.Fields{
		"host_id": id,
	})

	row := s.db.QueryRowContext(ctx, `
SELECT id, created_at
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
func (s *Store) ListHosts(ctx context.Context) ([]Host, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("hosts", "list", nil)

	rows, err := s.db.QueryContext(ctx, `
SELECT id, created_at
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
func (s *Store) DeleteHost(ctx context.Context, id string) error {
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
func (s *Store) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) error {
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

// Request describes the persisted state for a resource request.
type Request struct {
	ID        string            `json:"id"`
	HostID    string            `json:"host_id"`
	Payload   map[string]any    `json:"payload,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	HasGrant  bool              `json:"has_grant"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// RequestListFilters describes optional filters for listing requests.
type RequestListFilters struct {
	HasGrant   *bool
	Labels     map[string]string
	HostLabels map[string]string
}

// Register describes the persisted state for register entries.
type Register struct {
	ID        string            `json:"id"`
	HostID    string            `json:"host_id"`
	Payload   map[string]any    `json:"payload,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// RegisterListFilters describes optional filters for listing registers.
type RegisterListFilters struct {
	Labels     map[string]string
	HostLabels map[string]string
}

// CreateRequest inserts a new request record into storage.
func (s *Store) CreateRequest(ctx context.Context, req Request) (Request, error) {
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

	if _, err := tx.ExecContext(ctx, `
INSERT INTO requests (id, host_id, data)
VALUES (?, ?, ?)
`, req.ID, req.HostID, payloadValue); err != nil {
		if isUniqueConstraintError(err) {
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
func (s *Store) GetRequest(ctx context.Context, id string) (Request, error) {
	if s == nil || s.db == nil {
		return Request{}, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("requests", "get", logrus.Fields{
		"request_id": id,
	})

	row := s.db.QueryRowContext(ctx, `
SELECT id, host_id, data,
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
func (s *Store) ListRequests(ctx context.Context, filters *RequestListFilters) ([]Request, error) {
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
SELECT id, host_id, data,
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
func (s *Store) CountRequestsByGrantPresence(ctx context.Context) (map[string]int64, error) {
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

func (s *Store) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) error {
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

	if err := setUpdatedAt(ctx, tx, "requests", "id", id); err != nil {
		return fmt.Errorf("refresh request timestamp: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit request labels update: %w", err)
	}

	return nil
}

// DeleteRequest removes a request from storage.
func (s *Store) DeleteRequest(ctx context.Context, id string) error {
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
func (s *Store) CreateRegister(ctx context.Context, reg Register) (Register, error) {
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

	if _, err := tx.ExecContext(ctx, `
INSERT INTO registers (id, host_id, data)
VALUES (?, ?, ?)
`, reg.ID, reg.HostID, payloadValue); err != nil {
		if isUniqueConstraintError(err) {
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
func (s *Store) GetRegister(ctx context.Context, id string) (Register, error) {
	if s == nil || s.db == nil {
		return Register{}, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("registers", "get", logrus.Fields{
		"register_id": id,
	})

	row := s.db.QueryRowContext(ctx, `
SELECT id, host_id, data, created_at, updated_at
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
func (s *Store) ListRegisters(ctx context.Context, filters *RegisterListFilters) ([]Register, error) {
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
SELECT id, host_id, data, created_at, updated_at
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
func (s *Store) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) error {
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

	if err := setUpdatedAt(ctx, tx, "registers", "id", id); err != nil {
		return fmt.Errorf("refresh register timestamp: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit register labels update: %w", err)
	}

	return nil
}

// DeleteRegister removes a register record from storage.
func (s *Store) DeleteRegister(ctx context.Context, id string) error {
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
func (s *Store) CountRegisters(ctx context.Context) (map[string]int64, error) {
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

// Grant models payloads returned for resource requests.
type Grant struct {
	ID        string    `json:"id"`
	RequestID string    `json:"request_id"`
	Payload   []byte    `json:"payload"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateGrant stores a new grant with its payload.
func (s *Store) CreateGrant(ctx context.Context, grant Grant) (Grant, error) {
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
		"grant_id":     grant.ID,
		"request_id":   grant.RequestID,
		"payload_size": len(grant.Payload),
	})

	if _, err := s.db.ExecContext(ctx, `
INSERT INTO grants (id, request_id, payload)
VALUES (?, ?, ?)
`, grant.ID, grant.RequestID, grant.Payload); err != nil {
		if isUniqueConstraintError(err) {
			return Grant{}, fmt.Errorf("%w: %w", ErrGrantAlreadyExists, err)
		}
		return Grant{}, fmt.Errorf("insert grant: %w", err)
	}

	return grant, nil
}

// GetGrant retrieves a grant by ID.
func (s *Store) GetGrant(ctx context.Context, id string) (Grant, error) {
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
func (s *Store) ListGrants(ctx context.Context) ([]Grant, error) {
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
func (s *Store) CountGrants(ctx context.Context) (map[string]int64, error) {
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

// GetLatestGrantForRequest returns the most recently created grant for the request.
func (s *Store) GetLatestGrantForRequest(ctx context.Context, requestID string) (Grant, bool, error) {
	if s == nil || s.db == nil {
		return Grant{}, false, fmt.Errorf("store not initialized")
	}

	s.logDBOperation("grants", "get_latest_for_request", logrus.Fields{
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
		return Grant{}, false, fmt.Errorf("get latest grant for request: %w", err)
	}

	return grant, true, nil
}

// DeleteGrant removes a grant record.
func (s *Store) DeleteGrant(ctx context.Context, id string) error {
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

type rowScanner interface {
	Scan(dest ...any) error
}

func scanHost(scanner rowScanner) (Host, error) {
	var (
		host      Host
		createdAt string
	)

	if err := scanner.Scan(&host.ID, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Host{}, ErrHostNotFound
		}
		return Host{}, err
	}

	t, err := parseCreatedAt(createdAt)
	if err != nil {
		return Host{}, err
	}
	host.CreatedAt = t

	return host, nil
}

func scanRequest(scanner rowScanner) (Request, error) {
	var (
		req          Request
		payloadValue sql.NullString
		hasGrant     sql.NullInt64
		createdAt    string
		updatedAt    string
	)

	if err := scanner.Scan(&req.ID, &req.HostID, &payloadValue, &hasGrant, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Request{}, ErrRequestNotFound
		}
		return Request{}, err
	}

	var err error
	req.Payload, err = decodeAnyMap(payloadValue)
	if err != nil {
		return Request{}, fmt.Errorf("decode request payload: %w", err)
	}

	if req.CreatedAt, err = parseCreatedAt(createdAt); err != nil {
		return Request{}, err
	}
	if req.UpdatedAt, err = parseCreatedAt(updatedAt); err != nil {
		return Request{}, err
	}

	req.HasGrant = hasGrant.Valid && hasGrant.Int64 > 0

	return req, nil
}

func scanRegister(scanner rowScanner) (Register, error) {
	var (
		reg          Register
		payloadValue sql.NullString
		createdAt    string
		updatedAt    string
	)

	if err := scanner.Scan(&reg.ID, &reg.HostID, &payloadValue, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Register{}, ErrRegisterNotFound
		}
		return Register{}, err
	}

	var err error
	reg.Payload, err = decodeAnyMap(payloadValue)
	if err != nil {
		return Register{}, fmt.Errorf("decode register payload: %w", err)
	}

	if reg.CreatedAt, err = parseCreatedAt(createdAt); err != nil {
		return Register{}, err
	}
	if reg.UpdatedAt, err = parseCreatedAt(updatedAt); err != nil {
		return Register{}, err
	}

	return reg, nil
}

func scanGrant(scanner rowScanner) (Grant, error) {
	var (
		grant     Grant
		payload   []byte
		createdAt string
		updatedAt string
	)

	if err := scanner.Scan(&grant.ID, &grant.RequestID, &payload, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Grant{}, ErrGrantNotFound
		}
		return Grant{}, err
	}

	grant.Payload = payload

	var err error
	if grant.CreatedAt, err = parseCreatedAt(createdAt); err != nil {
		return Grant{}, err
	}
	if grant.UpdatedAt, err = parseCreatedAt(updatedAt); err != nil {
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

func setUpdatedAt(ctx context.Context, tx *sql.Tx, table, idColumn, id string) error {
	stmt := fmt.Sprintf(`UPDATE %s SET updated_at = strftime('%%Y-%%m-%%d %%H:%%M:%%f', 'now') WHERE %s = ?`, table, idColumn)
	if _, err := tx.ExecContext(ctx, stmt, id); err != nil {
		return fmt.Errorf("update %s timestamp: %w", table, err)
	}
	return nil
}

func (s *Store) loadLabels(ctx context.Context, table, idColumn, id string) (map[string]string, error) {
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

func isUniqueConstraintError(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
