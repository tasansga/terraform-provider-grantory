package client

import (
	"encoding/json"
	"time"
)

// Host represents a host resource.
type Host struct {
	// ID is the server-generated host identifier.
	ID string `json:"id"`
	// UniqueKey is a caller-provided idempotency key.
	UniqueKey string `json:"unique_key,omitempty"`
	// Labels stores arbitrary host labels.
	Labels map[string]string `json:"labels,omitempty"`
	// CreatedAt is the resource creation timestamp.
	CreatedAt time.Time `json:"created_at"`
}

// Request represents a request resource.
type Request struct {
	ID                        string            `json:"id"`
	HostID                    string            `json:"host_id"`
	RequestSchemaDefinitionID string            `json:"request_schema_definition_id,omitempty"`
	GrantSchemaDefinitionID   string            `json:"grant_schema_definition_id,omitempty"`
	UniqueKey                 string            `json:"unique_key,omitempty"`
	Payload                   map[string]any    `json:"payload,omitempty"`
	Labels                    map[string]string `json:"labels,omitempty"`
	// HasGrant reports whether this request already has an attached grant.
	HasGrant bool `json:"has_grant"`
	// Grant is the embedded grant payload when available.
	Grant     map[string]any `json:"grant"`
	GrantID   string         `json:"grant_id,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// Register represents a register resource.
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

// Grant represents a grant resource.
type Grant struct {
	ID        string         `json:"id"`
	RequestID string         `json:"request_id"`
	Payload   map[string]any `json:"payload,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// SchemaDefinition represents a stored JSON schema definition.
type SchemaDefinition struct {
	ID        string            `json:"id"`
	UniqueKey string            `json:"unique_key,omitempty"`
	Schema    json.RawMessage   `json:"schema"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// HostCreatePayload is the request body for creating a host.
type HostCreatePayload struct {
	UniqueKey string            `json:"unique_key"`
	Labels    map[string]string `json:"labels"`
}

// RequestCreatePayload is the request body for creating a request.
type RequestCreatePayload struct {
	HostID                    string            `json:"host_id"`
	RequestSchemaDefinitionID string            `json:"request_schema_definition_id"`
	GrantSchemaDefinitionID   string            `json:"grant_schema_definition_id"`
	UniqueKey                 string            `json:"unique_key"`
	Payload                   map[string]any    `json:"payload"`
	Labels                    map[string]string `json:"labels"`
}

// RequestUpdatePayload is the request body for updating a request.
type RequestUpdatePayload struct {
	Payload map[string]any    `json:"payload,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// RegisterCreatePayload is the request body for creating a register.
type RegisterCreatePayload struct {
	HostID             string            `json:"host_id"`
	SchemaDefinitionID string            `json:"schema_definition_id"`
	UniqueKey          string            `json:"unique_key"`
	Payload            map[string]any    `json:"payload"`
	Labels             map[string]string `json:"labels"`
}

// RegisterUpdatePayload is the request body for updating a register.
type RegisterUpdatePayload struct {
	Labels map[string]string `json:"labels,omitempty"`
}

// GrantCreatePayload is the request body for creating a grant.
type GrantCreatePayload struct {
	RequestID string         `json:"request_id"`
	Payload   map[string]any `json:"payload,omitempty"`
}

// SchemaDefinitionCreatePayload is the request body for creating a schema definition.
type SchemaDefinitionCreatePayload struct {
	UniqueKey string            `json:"unique_key,omitempty"`
	Schema    json.RawMessage   `json:"schema"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// LabelsPayload is a shared payload for label update endpoints.
type LabelsPayload struct {
	Labels map[string]string `json:"labels"`
}

// RequestListOptions configures request list filtering.
type RequestListOptions struct {
	// Labels filters by request labels.
	Labels map[string]string
	// HostLabels filters by labels on the linked host.
	HostLabels map[string]string
	// HasGrant optionally filters by grant presence.
	HasGrant *bool
}

// RegisterListOptions configures register list filtering.
type RegisterListOptions struct {
	// Labels filters by register labels.
	Labels map[string]string
	// HostLabels filters by labels on the linked host.
	HostLabels map[string]string
}
