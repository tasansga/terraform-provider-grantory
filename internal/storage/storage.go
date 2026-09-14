package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Store defines the persistence API used by the server.
type Store interface {
	Close() error
	DB() *sql.DB
	// SetNamespace configures the active tenant namespace for subsequent operations.
	// Implementation note:
	// - SQLite backend uses isolated database files per namespace (e.g. data/<ns>.db);
	//   SetNamespace updates internal tracking/logging without affecting underlying isolation.
	// - PostgreSQL backend uses a single shared database with dedicated schemas per namespace;
	//   SetNamespace mutates the search path / qualified table names for subsequent SQL queries.
	SetNamespace(namespace string)
	Migrate(ctx context.Context) error

	CreateHost(ctx context.Context, host Host) (Host, error)
	GetHost(ctx context.Context, id string) (Host, error)
	ListHosts(ctx context.Context) ([]Host, error)
	DeleteHost(ctx context.Context, id string) error
	UpdateHostLabels(ctx context.Context, id string, labels map[string]string) error

	CreateRequest(ctx context.Context, req Request) (Request, error)
	GetRequest(ctx context.Context, id string) (Request, error)
	ListRequests(ctx context.Context, filters *RequestListFilters) ([]Request, error)
	CountRequestsByGrantPresence(ctx context.Context) (map[string]int64, error)
	UpdateRequest(ctx context.Context, id string, payload *map[string]any, labels *map[string]string) error
	UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) error
	DeleteRequest(ctx context.Context, id string) error

	CreateRegister(ctx context.Context, reg Register) (Register, error)
	GetRegister(ctx context.Context, id string) (Register, error)
	ListRegisters(ctx context.Context, filters *RegisterListFilters) ([]Register, error)
	UpdateRegister(ctx context.Context, id string, payload *map[string]any, labels *map[string]string) error
	UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) error
	ListRegisterEvents(ctx context.Context, registerID string) ([]RegisterEvent, error)
	DeleteRegister(ctx context.Context, id string) error
	CountRegisters(ctx context.Context) (map[string]int64, error)

	CreateGrant(ctx context.Context, grant Grant) (Grant, error)
	GetGrant(ctx context.Context, id string) (Grant, error)
	ListGrants(ctx context.Context) ([]Grant, error)
	UpdateGrant(ctx context.Context, id string, payload map[string]any, requestVersion int) error
	CountGrants(ctx context.Context) (map[string]int64, error)
	GetGrantForRequest(ctx context.Context, requestID string) (Grant, bool, error)
	DeleteGrant(ctx context.Context, id string) error

	CreateSchemaDefinition(ctx context.Context, def SchemaDefinition) (SchemaDefinition, error)
	GetSchemaDefinition(ctx context.Context, id string) (SchemaDefinition, error)
	ListSchemaDefinitions(ctx context.Context) ([]SchemaDefinition, error)
	UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) error
	DeleteSchemaDefinition(ctx context.Context, id string) error

	// RecordSignature records a signature timestamp and nonce to prevent replay attacks.
	RecordSignature(ctx context.Context, hostID string, timestamp int64, nonce string, expiresAt time.Time) error
}

// Host describes the persisted labels for a registered host.
type Host struct {
	ID                     string            `json:"id"`
	UniqueKey              string            `json:"unique_key,omitempty"`
	PublicKey              string            `json:"public_key,omitempty"`
	LastSignatureTimestamp int64             `json:"last_signature_timestamp,omitempty"`
	Labels                 map[string]string `json:"labels,omitempty"`
	CreatedAt              time.Time         `json:"created_at"`
}

// Request describes the persisted state for a resource request.
type Request struct {
	ID                        string            `json:"id"`
	HostID                    string            `json:"host_id"`
	RequestSchemaDefinitionID string            `json:"request_schema_definition_id,omitempty"`
	GrantSchemaDefinitionID   string            `json:"grant_schema_definition_id,omitempty"`
	UniqueKey                 string            `json:"unique_key,omitempty"`
	Payload                   map[string]any    `json:"payload,omitempty"`
	Mutable                   bool              `json:"mutable"`
	Version                   int               `json:"version"`
	Labels                    map[string]string `json:"labels,omitempty"`
	HasGrant                  bool              `json:"has_grant"`
	CreatedAt                 time.Time         `json:"created_at"`
	UpdatedAt                 time.Time         `json:"updated_at"`
}

// RequestListFilters describes optional filters for listing requests.
type RequestListFilters struct {
	HasGrant   *bool
	Labels     map[string]string
	HostLabels map[string]string
}

// Register describes the persisted state for register entries.
type Register struct {
	ID                 string            `json:"id"`
	HostID             string            `json:"host_id"`
	SchemaDefinitionID string            `json:"schema_definition_id,omitempty"`
	UniqueKey          string            `json:"unique_key,omitempty"`
	Payload            map[string]any    `json:"payload,omitempty"`
	Mutable            bool              `json:"mutable"`
	Labels             map[string]string `json:"labels,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

type RegisterEvent struct {
	ID         string            `json:"id"`
	RegisterID string            `json:"register_id"`
	EventType  string            `json:"event_type"`
	OldPayload map[string]any    `json:"old_payload,omitempty"`
	NewPayload map[string]any    `json:"new_payload,omitempty"`
	OldLabels  map[string]string `json:"old_labels,omitempty"`
	NewLabels  map[string]string `json:"new_labels,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}

// RegisterListFilters describes optional filters for listing registers.
type RegisterListFilters struct {
	Labels     map[string]string
	HostLabels map[string]string
}

// Grant models payloads returned for resource requests.
type Grant struct {
	ID             string         `json:"id"`
	RequestID      string         `json:"request_id"`
	Payload        map[string]any `json:"payload,omitempty"`
	RequestVersion int            `json:"request_version"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// SchemaDefinition stores request and grant JSON schema payloads.
type SchemaDefinition struct {
	ID        string            `json:"id"`
	UniqueKey string            `json:"unique_key,omitempty"`
	Schema    json.RawMessage   `json:"schema"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

var (
	// ErrHostNotFound is returned when a host cannot be located in storage.
	ErrHostNotFound = errors.New("host not found")
	// ErrHostAlreadyExists is returned when a host with the given ID exists.
	ErrHostAlreadyExists = errors.New("host already exists")
	// ErrHostUniqueKeyConflict is returned when a host with the same unique key exists.
	ErrHostUniqueKeyConflict = errors.New("host unique key already exists")
	// ErrRequestAlreadyExists is returned when a request with the given ID exists.
	ErrRequestAlreadyExists = errors.New("request already exists")
	// ErrGrantAlreadyExists is returned when a grant with the given ID exists.
	ErrGrantAlreadyExists = errors.New("grant already exists")
	// ErrRegisterAlreadyExists is returned when a register entry with the given ID exists.
	ErrRegisterAlreadyExists = errors.New("register already exists")
	// ErrRequestNotFound is returned when a request cannot be located.
	ErrRequestNotFound = errors.New("request not found")
	// ErrRequestUniqueKeyConflict is returned when a request with the same unique key exists.
	ErrRequestUniqueKeyConflict = errors.New("request unique key already exists")
	// ErrRequestImmutable is returned when payload updates are attempted on immutable requests.
	ErrRequestImmutable = errors.New("request is immutable")
	// ErrGrantNotFound is returned when a grant cannot be located.
	ErrGrantNotFound = errors.New("grant not found")
	// ErrGrantRequestVersionConflict is returned when provided request version does not match current request version.
	ErrGrantRequestVersionConflict = errors.New("request version conflict")
	// ErrRegisterNotFound is returned when a register entry cannot be located.
	ErrRegisterNotFound = errors.New("register not found")
	// ErrRegisterUniqueKeyConflict is returned when a register with the same unique key exists.
	ErrRegisterUniqueKeyConflict = errors.New("register unique key already exists")
	// ErrRegisterImmutable is returned when payload updates are attempted on immutable registers.
	ErrRegisterImmutable = errors.New("register is immutable")
	// ErrSchemaDefinitionNotFound is returned when a schema definition cannot be located.
	ErrSchemaDefinitionNotFound = errors.New("schema definition not found")
	// ErrSchemaDefinitionAlreadyExists is returned when a schema definition with the given ID exists.
	ErrSchemaDefinitionAlreadyExists = errors.New("schema definition already exists")
	// ErrSchemaDefinitionUniqueKeyConflict is returned when a schema definition with the same unique key exists.
	ErrSchemaDefinitionUniqueKeyConflict = errors.New("schema definition unique key already exists")
	// ErrReferencedHostNotFound is returned when a request/register refers to a host that does not exist.
	ErrReferencedHostNotFound    = errors.New("referenced host not found")
	ErrReferencedRequestNotFound = errors.New("referenced request not found")

	// ErrReplayDetected is returned when a nonce is reused for the same host.
	ErrReplayDetected = errors.New("replay detected")
	// ErrTimestampRegressed is returned when a signature timestamp is older than the last recorded one.
	ErrTimestampRegressed = errors.New("timestamp regressed")

	// ErrNotLeader is returned when a write operation is attempted on a node that is not the cluster leader.
	ErrNotLeader = errors.New("not cluster leader")
	// ErrLeadershipLost is returned when leadership changes while a replicated operation is in flight.
	ErrLeadershipLost = errors.New("cluster leader changed during operation")
)

const (
	// SignatureTimestampGracePeriodSeconds defines the grace period (in seconds) allowed
	// for out-of-order request timestamps from the same host to accommodate concurrency and network jitter.
	SignatureTimestampGracePeriodSeconds int64 = 30
)

type contextKey int

const deterministicTimeKey contextKey = 1

// WithDeterministicTime attaches a deterministic timestamp to the context.
// Storage backends that support deterministic mutation will use this timestamp
// for created_at, updated_at, and resource_events instead of the system clock.
func WithDeterministicTime(ctx context.Context, t time.Time) context.Context {
	return context.WithValue(ctx, deterministicTimeKey, t)
}

// DeterministicTimeFromContext extracts a deterministic timestamp from the context if present.
func DeterministicTimeFromContext(ctx context.Context) (time.Time, bool) {
	if ctx == nil {
		return time.Time{}, false
	}
	t, ok := ctx.Value(deterministicTimeKey).(time.Time)
	return t, ok && !t.IsZero()
}

// GenerateID returns a new unique identifier (UUID v4).
func GenerateID() string {
	return uuid.NewString()
}

func normalizeEntityIDAndTimestamps(ctx context.Context, id *string, createdAt *time.Time, updatedAt *time.Time) {
	if id != nil && *id == "" {
		*id = GenerateID()
	}
	now := time.Now().UTC()
	if t, ok := DeterministicTimeFromContext(ctx); ok {
		now = t
	}
	if createdAt != nil && createdAt.IsZero() {
		*createdAt = now
	}
	if updatedAt != nil && updatedAt.IsZero() {
		if createdAt != nil && !createdAt.IsZero() {
			*updatedAt = *createdAt
		} else {
			*updatedAt = now
		}
	}
}

func sortedMapKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func encodeJSON(value any) (*string, error) {
	if value == nil {
		return nil, nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	s := string(b)
	return &s, nil
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

func decodeStringMap(value sql.NullString) (map[string]string, error) {
	if !value.Valid || value.String == "" {
		return nil, nil
	}
	var dest map[string]string
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

// ResourceEventParams encapsulates parameters for inserting an audit event.
type ResourceEventParams struct {
	ResourceType  string
	ResourceID    string
	EventType     string
	OldPayloadMap map[string]any
	NewPayloadMap map[string]any
	OldLabelsMap  map[string]string
	NewLabelsMap  map[string]string
	Timestamp     time.Time
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// DeterministicResourceEventID computes a deterministic SHA-1 UUID for a resource event.
func DeterministicResourceEventID(params ResourceEventParams, ts time.Time, oldPayload, newPayload, oldLabels, newLabels *string) string {
	ts = ts.Truncate(time.Millisecond)
	hashInput := fmt.Sprintf("%s:%s:%s:%d:%s:%s:%s:%s",
		params.ResourceType,
		params.ResourceID,
		params.EventType,
		ts.UnixNano(),
		derefString(oldPayload),
		derefString(newPayload),
		derefString(oldLabels),
		derefString(newLabels),
	)
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(hashInput)).String()
}
