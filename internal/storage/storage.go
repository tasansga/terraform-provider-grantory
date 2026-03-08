package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Store defines the persistence API used by the server.
type Store interface {
	Close() error
	DB() *sql.DB
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
	UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) error
	DeleteRequest(ctx context.Context, id string) error

	CreateRegister(ctx context.Context, reg Register) (Register, error)
	GetRegister(ctx context.Context, id string) (Register, error)
	ListRegisters(ctx context.Context, filters *RegisterListFilters) ([]Register, error)
	UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) error
	DeleteRegister(ctx context.Context, id string) error
	CountRegisters(ctx context.Context) (map[string]int64, error)

	CreateGrant(ctx context.Context, grant Grant) (Grant, error)
	GetGrant(ctx context.Context, id string) (Grant, error)
	ListGrants(ctx context.Context) ([]Grant, error)
	CountGrants(ctx context.Context) (map[string]int64, error)
	GetGrantForRequest(ctx context.Context, requestID string) (Grant, bool, error)
	DeleteGrant(ctx context.Context, id string) error

	CreateSchemaDefinition(ctx context.Context, def SchemaDefinition) (SchemaDefinition, error)
	GetSchemaDefinition(ctx context.Context, id string) (SchemaDefinition, error)
	ListSchemaDefinitions(ctx context.Context) ([]SchemaDefinition, error)
	DeleteSchemaDefinition(ctx context.Context, id string) error
}

// Host describes the persisted labels for a registered host.
type Host struct {
	ID        string            `json:"id"`
	UniqueKey string            `json:"unique_key,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// Request describes the persisted state for a resource request.
type Request struct {
	ID                        string            `json:"id"`
	HostID                    string            `json:"host_id"`
	RequestSchemaDefinitionID string            `json:"request_schema_definition_id,omitempty"`
	GrantSchemaDefinitionID   string            `json:"grant_schema_definition_id,omitempty"`
	UniqueKey                 string            `json:"unique_key,omitempty"`
	Payload                   map[string]any    `json:"payload,omitempty"`
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
	Labels             map[string]string `json:"labels,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// RegisterListFilters describes optional filters for listing registers.
type RegisterListFilters struct {
	Labels     map[string]string
	HostLabels map[string]string
}

// Grant models payloads returned for resource requests.
type Grant struct {
	ID        string         `json:"id"`
	RequestID string         `json:"request_id"`
	Payload   map[string]any `json:"payload,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// SchemaDefinition stores request and grant JSON schema payloads.
type SchemaDefinition struct {
	ID        string          `json:"id"`
	Schema    json.RawMessage `json:"schema"`
	CreatedAt time.Time       `json:"created_at"`
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
	// ErrGrantNotFound is returned when a grant cannot be located.
	ErrGrantNotFound = errors.New("grant not found")
	// ErrRegisterNotFound is returned when a register entry cannot be located.
	ErrRegisterNotFound = errors.New("register not found")
	// ErrRegisterUniqueKeyConflict is returned when a register with the same unique key exists.
	ErrRegisterUniqueKeyConflict = errors.New("register unique key already exists")
	// ErrSchemaDefinitionNotFound is returned when a schema definition cannot be located.
	ErrSchemaDefinitionNotFound = errors.New("schema definition not found")
	// ErrSchemaDefinitionAlreadyExists is returned when a schema definition with the given ID exists.
	ErrSchemaDefinitionAlreadyExists = errors.New("schema definition already exists")
	// ErrReferencedHostNotFound is returned when a request/register refers to a host that does not exist.
	ErrReferencedHostNotFound    = errors.New("referenced host not found")
	ErrReferencedRequestNotFound = errors.New("referenced request not found")
)
