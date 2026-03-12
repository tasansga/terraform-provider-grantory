package client

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
	Labels             map[string]string `json:"labels,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

type Grant struct {
	ID        string         `json:"id"`
	RequestID string         `json:"request_id"`
	Payload   map[string]any `json:"payload,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type SchemaDefinition struct {
	ID        string          `json:"id"`
	Schema    json.RawMessage `json:"schema"`
	CreatedAt time.Time       `json:"created_at"`
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
	Payload map[string]any    `json:"payload,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
}

type RegisterCreatePayload struct {
	HostID             string            `json:"host_id"`
	SchemaDefinitionID string            `json:"schema_definition_id"`
	UniqueKey          string            `json:"unique_key"`
	Payload            map[string]any    `json:"payload"`
	Labels             map[string]string `json:"labels"`
}

type RegisterUpdatePayload struct {
	Labels map[string]string `json:"labels,omitempty"`
}

type GrantCreatePayload struct {
	RequestID string         `json:"request_id"`
	Payload   map[string]any `json:"payload,omitempty"`
}

type SchemaDefinitionCreatePayload struct {
	Schema json.RawMessage `json:"schema"`
}

type LabelsPayload struct {
	Labels map[string]string `json:"labels"`
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
