package raft

import (
	"encoding/json"
	"fmt"
	"time"
)

// CommandType represents the type of a replicated state machine mutation command.
type CommandType string

const (
	CmdCreateHost             CommandType = "CREATE_HOST"
	CmdDeleteHost             CommandType = "DELETE_HOST"
	CmdUpdateHostLabels       CommandType = "UPDATE_HOST_LABELS"
	CmdRecordSignature        CommandType = "RECORD_SIGNATURE"
	CmdCreateRequest          CommandType = "CREATE_REQUEST"
	CmdUpdateRequest          CommandType = "UPDATE_REQUEST"
	CmdUpdateRequestLabels    CommandType = "UPDATE_REQUEST_LABELS"
	CmdDeleteRequest          CommandType = "DELETE_REQUEST"
	CmdCreateRegister         CommandType = "CREATE_REGISTER"
	CmdUpdateRegister         CommandType = "UPDATE_REGISTER"
	CmdUpdateRegisterLabels   CommandType = "UPDATE_REGISTER_LABELS"
	CmdDeleteRegister         CommandType = "DELETE_REGISTER"
	CmdCreateGrant            CommandType = "CREATE_GRANT"
	CmdUpdateGrant            CommandType = "UPDATE_GRANT"
	CmdDeleteGrant            CommandType = "DELETE_GRANT"
	CmdCreateSchemaDefinition       CommandType = "CREATE_SCHEMA_DEFINITION"
	CmdUpdateSchemaDefinitionLabels CommandType = "UPDATE_SCHEMA_DEFINITION_LABELS"
	CmdDeleteSchemaDefinition       CommandType = "DELETE_SCHEMA_DEFINITION"
	CmdRegisterNodeHTTPAddr   CommandType = "REGISTER_NODE_HTTP_ADDR"
	CmdDeregisterNodeHTTPAddr CommandType = "DEREGISTER_NODE_HTTP_ADDR"
)

// RaftCommand represents a strongly-typed command replicated through Raft consensus.
type RaftCommand struct {
	Namespace string                  `json:"namespace"`
	Type      CommandType             `json:"type"`
	Timestamp time.Time               `json:"timestamp"`
	Payload   json.RawMessage         `json:"payload"`
	Signature *RecordSignaturePayload `json:"signature,omitempty"`
}

// NewCommand constructs a RaftCommand with the provided namespace, command type, timestamp (converted to UTC), and payload.
func NewCommand(namespace string, cmdType CommandType, timestamp time.Time, payload any) (RaftCommand, error) {
	return NewCommandWithSignature(namespace, cmdType, timestamp, payload, nil)
}

// NewCommandWithSignature constructs a RaftCommand with the provided namespace, command type, timestamp (converted to UTC), payload, and signature payload.
func NewCommandWithSignature(namespace string, cmdType CommandType, timestamp time.Time, payload any, sig *RecordSignaturePayload) (RaftCommand, error) {
	bytes, err := json.Marshal(payload)
	if err != nil {
		return RaftCommand{}, fmt.Errorf("marshal raft command payload: %w", err)
	}
	return RaftCommand{
		Namespace: namespace,
		Type:      cmdType,
		Timestamp: timestamp.UTC(),
		Payload:   bytes,
		Signature: sig,
	}, nil
}

// Encode serializes the RaftCommand to JSON bytes for replication through Raft log.
func (c RaftCommand) Encode() ([]byte, error) {
	return json.Marshal(c)
}

// DecodeCommand deserializes a Raft log entry into a RaftCommand.
func DecodeCommand(data []byte) (RaftCommand, error) {
	var cmd RaftCommand
	if err := json.Unmarshal(data, &cmd); err != nil {
		return RaftCommand{}, fmt.Errorf("decode raft command: %w", err)
	}
	return cmd, nil
}

// ApplyResponse encapsulates the result or error returned when applying a Raft command to the state machine.
// It is strictly an in-memory transport struct passed between FSM.Apply and future.Response(), not serialized to the Raft log.
type ApplyResponse struct {
	Data  any
	Error error
}

// DeletePayload models the payload for single-ID deletion operations.
type DeletePayload struct {
	ID string `json:"id"`
}

// UpdateLabelsPayload models the payload for updating label maps on an entity.
type UpdateLabelsPayload struct {
	ID     string            `json:"id"`
	Labels map[string]string `json:"labels"`
}

// UpdateRequestPayload models the payload for updating request payloads and/or labels.
type UpdateRequestPayload struct {
	ID      string             `json:"id"`
	Payload *map[string]any    `json:"payload,omitempty"`
	Labels  *map[string]string `json:"labels,omitempty"`
}

// UpdateRegisterPayload models the payload for updating register payloads and/or labels.
type UpdateRegisterPayload struct {
	ID      string             `json:"id"`
	Payload *map[string]any    `json:"payload,omitempty"`
	Labels  *map[string]string `json:"labels,omitempty"`
}

// UpdateGrantPayload models the payload for updating grant payloads.
type UpdateGrantPayload struct {
	ID             string         `json:"id"`
	Payload        map[string]any `json:"payload"`
	RequestVersion int            `json:"request_version"`
}

// RecordSignaturePayload models the payload for recording a host signature to prevent replay attacks.
type RecordSignaturePayload struct {
	HostID    string    `json:"host_id"`
	Timestamp int64     `json:"timestamp"`
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RegisterNodeHTTPAddrPayload models the payload for replicating a node's HTTP address across the cluster.
type RegisterNodeHTTPAddrPayload struct {
	ServerID string `json:"server_id"`
	Address  string `json:"address"`
	HTTPAddr string `json:"http_addr"`
}

// DeregisterNodeHTTPAddrPayload models the payload for deregistering a node's HTTP address across the cluster.
type DeregisterNodeHTTPAddrPayload struct {
	ServerID string `json:"server_id"`
	Address  string `json:"address,omitempty"`
}
