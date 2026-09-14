package raft

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

// Mutator executes deterministic mutations against a storage.Store backend.
// Non-deterministic values (IDs, timestamps, nonces) are validated and supplied explicitly
// by the Raft leader before delegating to the unified storage engine.
type Mutator struct {
	store storage.Store
}

// NewMutator returns a new Mutator wrapping the given Store.
func NewMutator(store storage.Store) *Mutator {
	return &Mutator{
		store: store,
	}
}

// Dispatch unmarshals the RaftCommand payload according to cmd.Type and executes the corresponding Apply* method.
func (m *Mutator) Dispatch(ctx context.Context, cmd RaftCommand) ApplyResponse {
	if !cmd.Timestamp.IsZero() {
		ctx = storage.WithDeterministicTime(ctx, cmd.Timestamp)
	}

	if cmd.Signature != nil {
		ctx = storage.WithSignatureParams(ctx, storage.SignatureParams{
			HostID:    cmd.Signature.HostID,
			Timestamp: cmd.Signature.Timestamp,
			Nonce:     cmd.Signature.Nonce,
			ExpiresAt: cmd.Signature.ExpiresAt,
		})
	}

	switch cmd.Type {
	case CmdCreateHost:
		var host storage.Host
		if err := json.Unmarshal(cmd.Payload, &host); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal create host payload: %w", err)}
		}
		if host.CreatedAt.IsZero() {
			host.CreatedAt = cmd.Timestamp
		}
		res, err := m.ApplyCreateHost(ctx, host)
		return ApplyResponse{Data: res, Error: err}

	case CmdDeleteHost:
		var p DeletePayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal delete host payload: %w", err)}
		}
		err := m.ApplyDeleteHost(ctx, p.ID)
		return ApplyResponse{Error: err}

	case CmdUpdateHostLabels:
		var p UpdateLabelsPayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal update host labels payload: %w", err)}
		}
		err := m.ApplyUpdateHostLabels(ctx, p.ID, p.Labels)
		return ApplyResponse{Error: err}

	case CmdRecordSignature:
		var p RecordSignaturePayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal record signature payload: %w", err)}
		}
		err := m.ApplyRecordSignature(ctx, p.HostID, p.Timestamp, p.Nonce, p.ExpiresAt)
		return ApplyResponse{Error: err}

	case CmdCreateRequest:
		var req storage.Request
		if err := json.Unmarshal(cmd.Payload, &req); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal create request payload: %w", err)}
		}
		if req.CreatedAt.IsZero() {
			req.CreatedAt = cmd.Timestamp
		}
		if req.UpdatedAt.IsZero() {
			req.UpdatedAt = cmd.Timestamp
		}
		res, err := m.ApplyCreateRequest(ctx, req)
		return ApplyResponse{Data: res, Error: err}

	case CmdUpdateRequest:
		var p UpdateRequestPayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal update request payload: %w", err)}
		}
		err := m.ApplyUpdateRequest(ctx, p.ID, p.Payload, p.Labels, cmd.Timestamp)
		return ApplyResponse{Error: err}

	case CmdUpdateRequestLabels:
		var p UpdateLabelsPayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal update request labels payload: %w", err)}
		}
		err := m.ApplyUpdateRequestLabels(ctx, p.ID, p.Labels, cmd.Timestamp)
		return ApplyResponse{Error: err}

	case CmdDeleteRequest:
		var p DeletePayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal delete request payload: %w", err)}
		}
		err := m.ApplyDeleteRequest(ctx, p.ID)
		return ApplyResponse{Error: err}

	case CmdCreateRegister:
		var reg storage.Register
		if err := json.Unmarshal(cmd.Payload, &reg); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal create register payload: %w", err)}
		}
		if reg.CreatedAt.IsZero() {
			reg.CreatedAt = cmd.Timestamp
		}
		if reg.UpdatedAt.IsZero() {
			reg.UpdatedAt = cmd.Timestamp
		}
		res, err := m.ApplyCreateRegister(ctx, reg)
		return ApplyResponse{Data: res, Error: err}

	case CmdUpdateRegister:
		var p UpdateRegisterPayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal update register payload: %w", err)}
		}
		err := m.ApplyUpdateRegister(ctx, p.ID, p.Payload, p.Labels, cmd.Timestamp)
		return ApplyResponse{Error: err}

	case CmdUpdateRegisterLabels:
		var p UpdateLabelsPayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal update register labels payload: %w", err)}
		}
		err := m.ApplyUpdateRegisterLabels(ctx, p.ID, p.Labels, cmd.Timestamp)
		return ApplyResponse{Error: err}

	case CmdDeleteRegister:
		var p DeletePayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal delete register payload: %w", err)}
		}
		err := m.ApplyDeleteRegister(ctx, p.ID)
		return ApplyResponse{Error: err}

	case CmdCreateGrant:
		var grant storage.Grant
		if err := json.Unmarshal(cmd.Payload, &grant); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal create grant payload: %w", err)}
		}
		if grant.CreatedAt.IsZero() {
			grant.CreatedAt = cmd.Timestamp
		}
		if grant.UpdatedAt.IsZero() {
			grant.UpdatedAt = cmd.Timestamp
		}
		res, err := m.ApplyCreateGrant(ctx, grant)
		return ApplyResponse{Data: res, Error: err}

	case CmdUpdateGrant:
		var p UpdateGrantPayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal update grant payload: %w", err)}
		}
		err := m.ApplyUpdateGrant(ctx, p.ID, p.Payload, p.RequestVersion, cmd.Timestamp)
		return ApplyResponse{Error: err}

	case CmdDeleteGrant:
		var p DeletePayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal delete grant payload: %w", err)}
		}
		err := m.ApplyDeleteGrant(ctx, p.ID)
		return ApplyResponse{Error: err}

	case CmdCreateSchemaDefinition:
		var def storage.SchemaDefinition
		if err := json.Unmarshal(cmd.Payload, &def); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal create schema definition payload: %w", err)}
		}
		if def.CreatedAt.IsZero() {
			def.CreatedAt = cmd.Timestamp
		}
		res, err := m.ApplyCreateSchemaDefinition(ctx, def)
		return ApplyResponse{Data: res, Error: err}

	case CmdUpdateSchemaDefinitionLabels:
		var p UpdateLabelsPayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal update schema labels payload: %w", err)}
		}
		err := m.ApplyUpdateSchemaLabels(ctx, p.ID, p.Labels)
		return ApplyResponse{Error: err}

	case CmdDeleteSchemaDefinition:
		var p DeletePayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return ApplyResponse{Error: fmt.Errorf("unmarshal delete schema definition payload: %w", err)}
		}
		err := m.ApplyDeleteSchemaDefinition(ctx, p.ID)
		return ApplyResponse{Error: err}

	default:
		return ApplyResponse{Error: fmt.Errorf("unknown command type: %s", cmd.Type)}
	}
}

// ApplyCreateHost deterministically registers a host with provided ID and creation timestamp.
func (m *Mutator) ApplyCreateHost(ctx context.Context, host storage.Host) (storage.Host, error) {
	if m == nil || m.store == nil {
		return storage.Host{}, fmt.Errorf("store not initialized")
	}
	if host.ID == "" {
		return storage.Host{}, errors.New("id is required")
	}
	if host.CreatedAt.IsZero() {
		return storage.Host{}, errors.New("timestamp is required")
	}
	ctx = storage.WithDeterministicTime(ctx, host.CreatedAt)
	return m.store.CreateHost(ctx, host)
}

// ApplyDeleteHost removes a host by ID.
func (m *Mutator) ApplyDeleteHost(ctx context.Context, id string) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("store not initialized")
	}
	if id == "" {
		return errors.New("id is required")
	}
	return m.store.DeleteHost(ctx, id)
}

// ApplyUpdateHostLabels replaces labels for a host.
func (m *Mutator) ApplyUpdateHostLabels(ctx context.Context, id string, labels map[string]string) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("store not initialized")
	}
	if id == "" {
		return errors.New("id is required")
	}
	return m.store.UpdateHostLabels(ctx, id, labels)
}

// ApplyRecordSignature deterministically records a signature nonce and updates the host's monotonic signature timestamp.
func (m *Mutator) ApplyRecordSignature(ctx context.Context, hostID string, timestamp int64, nonce string, expiresAt time.Time) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("store not initialized")
	}
	if hostID == "" {
		return errors.New("id is required")
	}
	if timestamp <= 0 || expiresAt.IsZero() {
		return errors.New("timestamp is required")
	}
	ctx = storage.WithDeterministicTime(ctx, time.Unix(timestamp, 0).UTC())
	return m.store.RecordSignature(ctx, hostID, timestamp, nonce, expiresAt)
}

// ApplyCreateRequest deterministically creates a request with explicit ID and timestamps.
func (m *Mutator) ApplyCreateRequest(ctx context.Context, req storage.Request) (storage.Request, error) {
	if m == nil || m.store == nil {
		return storage.Request{}, fmt.Errorf("store not initialized")
	}
	if req.ID == "" {
		return storage.Request{}, errors.New("id is required")
	}
	if req.CreatedAt.IsZero() || req.UpdatedAt.IsZero() {
		return storage.Request{}, errors.New("timestamp is required")
	}
	ctx = storage.WithDeterministicTime(ctx, req.CreatedAt)
	return m.store.CreateRequest(ctx, req)
}

// ApplyUpdateRequest updates payload and/or labels on a request with a deterministic updated_at timestamp.
func (m *Mutator) ApplyUpdateRequest(ctx context.Context, id string, payload *map[string]any, labels *map[string]string, updatedAt time.Time) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("store not initialized")
	}
	if id == "" {
		return errors.New("id is required")
	}
	if updatedAt.IsZero() {
		return errors.New("timestamp is required")
	}
	ctx = storage.WithDeterministicTime(ctx, updatedAt)
	return m.store.UpdateRequest(ctx, id, payload, labels)
}

// ApplyUpdateRequestLabels updates the labels for a request.
func (m *Mutator) ApplyUpdateRequestLabels(ctx context.Context, id string, labels map[string]string, updatedAt time.Time) error {
	return m.ApplyUpdateRequest(ctx, id, nil, &labels, updatedAt)
}

// ApplyDeleteRequest removes a request by ID.
func (m *Mutator) ApplyDeleteRequest(ctx context.Context, id string) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("store not initialized")
	}
	if id == "" {
		return errors.New("id is required")
	}
	return m.store.DeleteRequest(ctx, id)
}

// ApplyCreateRegister deterministically creates a register record.
func (m *Mutator) ApplyCreateRegister(ctx context.Context, reg storage.Register) (storage.Register, error) {
	if m == nil || m.store == nil {
		return storage.Register{}, fmt.Errorf("store not initialized")
	}
	if reg.ID == "" {
		return storage.Register{}, errors.New("id is required")
	}
	if reg.CreatedAt.IsZero() || reg.UpdatedAt.IsZero() {
		return storage.Register{}, errors.New("timestamp is required")
	}
	ctx = storage.WithDeterministicTime(ctx, reg.CreatedAt)
	return m.store.CreateRegister(ctx, reg)
}

// ApplyUpdateRegister updates payload and/or labels on a register with a deterministic updated_at timestamp.
func (m *Mutator) ApplyUpdateRegister(ctx context.Context, id string, payload *map[string]any, labels *map[string]string, updatedAt time.Time) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("store not initialized")
	}
	if id == "" {
		return errors.New("id is required")
	}
	if updatedAt.IsZero() {
		return errors.New("timestamp is required")
	}
	ctx = storage.WithDeterministicTime(ctx, updatedAt)
	return m.store.UpdateRegister(ctx, id, payload, labels)
}

// ApplyUpdateRegisterLabels replaces the labels stored for a register record.
func (m *Mutator) ApplyUpdateRegisterLabels(ctx context.Context, id string, labels map[string]string, updatedAt time.Time) error {
	return m.ApplyUpdateRegister(ctx, id, nil, &labels, updatedAt)
}

// ApplyDeleteRegister removes a register record by ID.
func (m *Mutator) ApplyDeleteRegister(ctx context.Context, id string) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("store not initialized")
	}
	if id == "" {
		return errors.New("id is required")
	}
	return m.store.DeleteRegister(ctx, id)
}

// ApplyCreateGrant deterministically creates a grant record.
func (m *Mutator) ApplyCreateGrant(ctx context.Context, grant storage.Grant) (storage.Grant, error) {
	if m == nil || m.store == nil {
		return storage.Grant{}, fmt.Errorf("store not initialized")
	}
	if grant.ID == "" {
		return storage.Grant{}, errors.New("id is required")
	}
	if grant.CreatedAt.IsZero() || grant.UpdatedAt.IsZero() {
		return storage.Grant{}, errors.New("timestamp is required")
	}
	ctx = storage.WithDeterministicTime(ctx, grant.CreatedAt)
	return m.store.CreateGrant(ctx, grant)
}

// ApplyUpdateGrant updates a grant with deterministic updated_at timestamp.
func (m *Mutator) ApplyUpdateGrant(ctx context.Context, id string, payload map[string]any, requestVersion int, updatedAt time.Time) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("store not initialized")
	}
	if id == "" {
		return errors.New("id is required")
	}
	if updatedAt.IsZero() {
		return errors.New("timestamp is required")
	}
	ctx = storage.WithDeterministicTime(ctx, updatedAt)
	return m.store.UpdateGrant(ctx, id, payload, requestVersion)
}

// ApplyDeleteGrant removes a grant record by ID.
func (m *Mutator) ApplyDeleteGrant(ctx context.Context, id string) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("store not initialized")
	}
	if id == "" {
		return errors.New("id is required")
	}
	return m.store.DeleteGrant(ctx, id)
}

// ApplyCreateSchemaDefinition deterministically creates a schema definition.
func (m *Mutator) ApplyCreateSchemaDefinition(ctx context.Context, def storage.SchemaDefinition) (storage.SchemaDefinition, error) {
	if m == nil || m.store == nil {
		return storage.SchemaDefinition{}, fmt.Errorf("store not initialized")
	}
	if def.ID == "" {
		return storage.SchemaDefinition{}, errors.New("id is required")
	}
	if def.CreatedAt.IsZero() {
		return storage.SchemaDefinition{}, errors.New("timestamp is required")
	}
	ctx = storage.WithDeterministicTime(ctx, def.CreatedAt)
	return m.store.CreateSchemaDefinition(ctx, def)
}

// ApplyUpdateSchemaLabels replaces labels for a schema definition.
func (m *Mutator) ApplyUpdateSchemaLabels(ctx context.Context, id string, labels map[string]string) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("store not initialized")
	}
	if id == "" {
		return errors.New("id is required")
	}
	return m.store.UpdateSchemaDefinitionLabels(ctx, id, labels)
}

// ApplyDeleteSchemaDefinition removes a schema definition by ID after clearing references in requests and registers.
func (m *Mutator) ApplyDeleteSchemaDefinition(ctx context.Context, id string) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("store not initialized")
	}
	if id == "" {
		return errors.New("id is required")
	}
	return m.store.DeleteSchemaDefinition(ctx, id)
}
