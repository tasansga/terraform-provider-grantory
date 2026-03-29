package service

import (
	"encoding/json"
	"time"
)

type Host struct {
	ID        string            `json:"id"`
	UniqueKey string            `json:"unique_key,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

type Request struct {
	ID                        string            `json:"id"`
	HostID                    string            `json:"host_id"`
	RequestSchemaDefinitionID string            `json:"request_schema_definition_id,omitempty"`
	GrantSchemaDefinitionID   string            `json:"grant_schema_definition_id,omitempty"`
	UniqueKey                 string            `json:"unique_key,omitempty"`
	Payload                   map[string]any    `json:"payload,omitempty"`
	Labels                    map[string]string `json:"labels,omitempty"`
	HasGrant                  bool              `json:"has_grant"`
	Grant                     map[string]any    `json:"grant"`
	GrantID                   string            `json:"grant_id,omitempty"`
	CreatedAt                 time.Time         `json:"created_at"`
	UpdatedAt                 time.Time         `json:"updated_at"`
}

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

type Grant struct {
	ID        string         `json:"id"`
	RequestID string         `json:"request_id"`
	Payload   map[string]any `json:"payload,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type SchemaDefinition struct {
	ID        string            `json:"id"`
	UniqueKey string            `json:"unique_key,omitempty"`
	Schema    json.RawMessage   `json:"schema"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

type HostCreatePayload struct {
	UniqueKey string            `json:"unique_key"`
	Labels    map[string]string `json:"labels"`
}

type RequestCreatePayload struct {
	HostID                    string            `json:"host_id"`
	RequestSchemaDefinitionID string            `json:"request_schema_definition_id"`
	GrantSchemaDefinitionID   string            `json:"grant_schema_definition_id"`
	UniqueKey                 string            `json:"unique_key"`
	Payload                   map[string]any    `json:"payload"`
	Labels                    map[string]string `json:"labels"`
}

type RequestUpdatePayload struct {
	Labels map[string]string `json:"labels"`
}

type RegisterCreatePayload struct {
	HostID             string            `json:"host_id"`
	SchemaDefinitionID string            `json:"schema_definition_id"`
	UniqueKey          string            `json:"unique_key"`
	Payload            map[string]any    `json:"payload"`
	Mutable            bool              `json:"mutable"`
	Labels             map[string]string `json:"labels"`
}

type RegisterUpdatePayload struct {
	Payload *map[string]any    `json:"payload,omitempty"`
	Labels  *map[string]string `json:"labels,omitempty"`
}

type GrantCreatePayload struct {
	RequestID string         `json:"request_id"`
	Payload   map[string]any `json:"payload,omitempty"`
}

type SchemaDefinitionCreatePayload struct {
	UniqueKey string            `json:"unique_key,omitempty"`
	Schema    json.RawMessage   `json:"schema"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type RequestListOptions struct {
	Labels     map[string]string
	HostLabels map[string]string
	HasGrant   *bool
}

type RegisterListOptions struct {
	Labels     map[string]string
	HostLabels map[string]string
}
