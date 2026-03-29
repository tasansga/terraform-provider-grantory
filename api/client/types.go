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
	Mutable                   bool              `json:"mutable"`
	Version                   int               `json:"version"`
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
	Mutable            bool              `json:"mutable"`
	Labels             map[string]string `json:"labels,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// RegisterEvent represents a register change event.
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

// Grant represents a grant resource.
type Grant struct {
	ID             string         `json:"id"`
	RequestID      string         `json:"request_id"`
	RequestVersion int            `json:"request_version"`
	Payload        map[string]any `json:"payload,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
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
	Mutable                   bool              `json:"mutable"`
	Labels                    map[string]string `json:"labels"`
}

// RequestUpdatePayload is the request body for updating a request.
type RequestUpdatePayload struct {
	Payload map[string]any
	Labels  map[string]string
}

// RegisterCreatePayload is the request body for creating a register.
type RegisterCreatePayload struct {
	HostID             string            `json:"host_id"`
	SchemaDefinitionID string            `json:"schema_definition_id"`
	UniqueKey          string            `json:"unique_key"`
	Payload            map[string]any    `json:"payload"`
	Mutable            bool              `json:"mutable"`
	Labels             map[string]string `json:"labels"`
}

// RegisterUpdatePayload is the request body for updating a register.
type RegisterUpdatePayload struct {
	Payload map[string]any    `json:"payload,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// MarshalJSON preserves non-nil empty maps so callers can intentionally send
// `payload: {}` or `labels: {}` in partial updates.
func (p RegisterUpdatePayload) MarshalJSON() ([]byte, error) {
	body := map[string]any{}
	if p.Payload != nil {
		body["payload"] = p.Payload
	}
	if p.Labels != nil {
		body["labels"] = p.Labels
	}
	return json.Marshal(body)
}

// GrantCreatePayload is the request body for creating a grant.
type GrantCreatePayload struct {
	RequestID      string         `json:"request_id"`
	RequestVersion int            `json:"request_version"`
	Payload        map[string]any `json:"payload,omitempty"`
}

// GrantUpdatePayload is the request body for updating a grant payload.
type GrantUpdatePayload struct {
	RequestVersion int
	Payload        map[string]any
}

// MarshalJSON preserves non-nil empty maps so callers can intentionally send
// `payload: {}` in partial updates.
func (p RequestUpdatePayload) MarshalJSON() ([]byte, error) {
	body := map[string]any{}
	if p.Payload != nil {
		body["payload"] = p.Payload
	}
	if p.Labels != nil {
		body["labels"] = p.Labels
	}
	return json.Marshal(body)
}

// MarshalJSON preserves non-nil empty maps so callers can intentionally send
// `payload: {}` in updates.
func (p GrantUpdatePayload) MarshalJSON() ([]byte, error) {
	body := map[string]any{}
	if p.RequestVersion > 0 {
		body["request_version"] = p.RequestVersion
	}
	if p.Payload != nil {
		body["payload"] = p.Payload
	}
	return json.Marshal(body)
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
