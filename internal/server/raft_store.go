package server

import (
	"context"
	"database/sql"
	"errors"
	"time"

	hashiraft "github.com/hashicorp/raft"
	"github.com/tasansga/terraform-provider-grantory/internal/cluster/raft"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

type raftProposer interface {
	Propose(ctx context.Context, cmd raft.RaftCommand) (raft.ApplyResponse, error)
}

// RaftStore wraps an underlying storage.Store and replicates all write operations
// through Raft consensus before applying them to the state machine. Read operations
// are served directly from the underlying local store (protected by linearizable barrier checks).
type RaftStore struct {
	underlying storage.Store
	proposer   raftProposer
	namespace  string
}

var _ storage.Store = (*RaftStore)(nil)

func newRaftStore(underlying storage.Store, proposer raftProposer, namespace string) *RaftStore {
	return &RaftStore{
		underlying: underlying,
		proposer:   proposer,
		namespace:  namespace,
	}
}

// Unwrap returns the underlying local storage engine.
func (s *RaftStore) Unwrap() storage.Store {
	if s == nil {
		return nil
	}
	return s.underlying
}

// SupportsSignatureBundling indicates that RaftStore bundles anti-replay signature
// parameters directly into consensus mutation commands.
func (s *RaftStore) SupportsSignatureBundling() bool {
	return true
}

func sigPayload(ctx context.Context) *raft.RecordSignaturePayload {
	if sp, ok := storage.SignatureParamsFromContext(ctx); ok && sp.HostID != "" {
		return &raft.RecordSignaturePayload{
			HostID:    sp.HostID,
			Timestamp: sp.Timestamp,
			Nonce:     sp.Nonce,
			ExpiresAt: sp.ExpiresAt,
		}
	}
	return nil
}

func (s *RaftStore) currentTime(ctx context.Context) time.Time {
	if t, ok := storage.DeterministicTimeFromContext(ctx); ok {
		return t
	}
	return time.Now().UTC()
}

func mapRaftError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, hashiraft.ErrNotLeader) {
		return storage.ErrNotLeader
	}
	if errors.Is(err, hashiraft.ErrLeadershipLost) {
		return storage.ErrLeadershipLost
	}
	return err
}

func (s *RaftStore) propose(ctx context.Context, cmd raft.RaftCommand) (raft.ApplyResponse, error) {
	resp, err := s.proposer.Propose(ctx, cmd)
	if err != nil {
		return resp, mapRaftError(err)
	}
	if resp.Error != nil {
		return resp, mapRaftError(resp.Error)
	}
	return resp, nil
}

// proposeDelete is the centralized helper for proposing resource deletion commands to Raft.
// It captures client signature parameters from context via sigPayload(ctx); for resource types
// that do not utilize cryptographic client approvals (such as grants and schemas), sigPayload(ctx)
// safely returns nil, generating a standard unsigned deletion command.
func (s *RaftStore) proposeDelete(ctx context.Context, cmdType raft.CommandType, id string) error {
	now := s.currentTime(ctx)
	cmd, err := raft.NewCommandWithSignature(s.namespace, cmdType, now, raft.DeletePayload{ID: id}, sigPayload(ctx))
	if err != nil {
		return err
	}
	_, err = s.propose(ctx, cmd)
	return err
}

// Close is a no-op to satisfy storage.Store while preventing fasthttp request recycling
// from closing the shared database connection pool managed by NamespaceStore.
func (s *RaftStore) Close() error {
	return nil
}

// DB returns the underlying sql.DB connection pool.
func (s *RaftStore) DB() *sql.DB {
	return s.underlying.DB()
}

// SetNamespace updates the active namespace in RaftStore.
func (s *RaftStore) SetNamespace(namespace string) {
	s.namespace = namespace
	if s.underlying != nil {
		s.underlying.SetNamespace(namespace)
	}
}

// Migrate runs schema migrations against the underlying store.
func (s *RaftStore) Migrate(ctx context.Context) error {
	return s.underlying.Migrate(ctx)
}

// ---------------------------------------------------------------------------
// Host Operations
// ---------------------------------------------------------------------------

func (s *RaftStore) CreateHost(ctx context.Context, host storage.Host) (storage.Host, error) {
	if host.ID == "" {
		host.ID = storage.GenerateID()
	}
	now := s.currentTime(ctx)
	if host.CreatedAt.IsZero() {
		host.CreatedAt = now
	}
	cmd, err := raft.NewCommandWithSignature(s.namespace, raft.CmdCreateHost, now, host, sigPayload(ctx))
	if err != nil {
		return storage.Host{}, err
	}
	resp, err := s.propose(ctx, cmd)
	if err != nil {
		return storage.Host{}, err
	}
	if res, ok := resp.Data.(storage.Host); ok {
		return res, nil
	}
	return host, nil
}

func (s *RaftStore) GetHost(ctx context.Context, id string) (storage.Host, error) {
	return s.underlying.GetHost(ctx, id)
}

func (s *RaftStore) ListHosts(ctx context.Context) ([]storage.Host, error) {
	return s.underlying.ListHosts(ctx)
}

func (s *RaftStore) DeleteHost(ctx context.Context, id string) error {
	return s.proposeDelete(ctx, raft.CmdDeleteHost, id)
}

func (s *RaftStore) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) error {
	now := s.currentTime(ctx)
	cmd, err := raft.NewCommandWithSignature(s.namespace, raft.CmdUpdateHostLabels, now, raft.UpdateLabelsPayload{
		ID:     id,
		Labels: labels,
	}, sigPayload(ctx))
	if err != nil {
		return err
	}
	_, err = s.propose(ctx, cmd)
	return err
}

// ---------------------------------------------------------------------------
// Request Operations
// ---------------------------------------------------------------------------

func (s *RaftStore) CreateRequest(ctx context.Context, req storage.Request) (storage.Request, error) {
	if req.ID == "" {
		req.ID = storage.GenerateID()
	}
	now := s.currentTime(ctx)
	if req.CreatedAt.IsZero() {
		req.CreatedAt = now
	}
	if req.UpdatedAt.IsZero() {
		req.UpdatedAt = now
	}
	if req.Version <= 0 {
		req.Version = 1
	}
	cmd, err := raft.NewCommandWithSignature(s.namespace, raft.CmdCreateRequest, now, req, sigPayload(ctx))
	if err != nil {
		return storage.Request{}, err
	}
	resp, err := s.propose(ctx, cmd)
	if err != nil {
		return storage.Request{}, err
	}
	if res, ok := resp.Data.(storage.Request); ok {
		return res, nil
	}
	return req, nil
}

func (s *RaftStore) GetRequest(ctx context.Context, id string) (storage.Request, error) {
	return s.underlying.GetRequest(ctx, id)
}

func (s *RaftStore) ListRequests(ctx context.Context, filters *storage.RequestListFilters) ([]storage.Request, error) {
	return s.underlying.ListRequests(ctx, filters)
}

func (s *RaftStore) CountRequestsByGrantPresence(ctx context.Context) (map[string]int64, error) {
	return s.underlying.CountRequestsByGrantPresence(ctx)
}

func (s *RaftStore) UpdateRequest(ctx context.Context, id string, payload *map[string]any, labels *map[string]string) error {
	now := s.currentTime(ctx)
	cmd, err := raft.NewCommandWithSignature(s.namespace, raft.CmdUpdateRequest, now, raft.UpdateRequestPayload{
		ID:      id,
		Payload: payload,
		Labels:  labels,
	}, sigPayload(ctx))
	if err != nil {
		return err
	}
	_, err = s.propose(ctx, cmd)
	return err
}

func (s *RaftStore) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) error {
	now := s.currentTime(ctx)
	cmd, err := raft.NewCommandWithSignature(s.namespace, raft.CmdUpdateRequestLabels, now, raft.UpdateLabelsPayload{
		ID:     id,
		Labels: labels,
	}, sigPayload(ctx))
	if err != nil {
		return err
	}
	_, err = s.propose(ctx, cmd)
	return err
}

func (s *RaftStore) DeleteRequest(ctx context.Context, id string) error {
	return s.proposeDelete(ctx, raft.CmdDeleteRequest, id)
}

// ---------------------------------------------------------------------------
// Register Operations
// ---------------------------------------------------------------------------

func (s *RaftStore) CreateRegister(ctx context.Context, reg storage.Register) (storage.Register, error) {
	if reg.ID == "" {
		reg.ID = storage.GenerateID()
	}
	now := s.currentTime(ctx)
	if reg.CreatedAt.IsZero() {
		reg.CreatedAt = now
	}
	if reg.UpdatedAt.IsZero() {
		reg.UpdatedAt = now
	}
	cmd, err := raft.NewCommandWithSignature(s.namespace, raft.CmdCreateRegister, now, reg, sigPayload(ctx))
	if err != nil {
		return storage.Register{}, err
	}
	resp, err := s.propose(ctx, cmd)
	if err != nil {
		return storage.Register{}, err
	}
	if res, ok := resp.Data.(storage.Register); ok {
		return res, nil
	}
	return reg, nil
}

func (s *RaftStore) GetRegister(ctx context.Context, id string) (storage.Register, error) {
	return s.underlying.GetRegister(ctx, id)
}

func (s *RaftStore) ListRegisters(ctx context.Context, filters *storage.RegisterListFilters) ([]storage.Register, error) {
	return s.underlying.ListRegisters(ctx, filters)
}

func (s *RaftStore) UpdateRegister(ctx context.Context, id string, payload *map[string]any, labels *map[string]string) error {
	now := s.currentTime(ctx)
	cmd, err := raft.NewCommandWithSignature(s.namespace, raft.CmdUpdateRegister, now, raft.UpdateRegisterPayload{
		ID:      id,
		Payload: payload,
		Labels:  labels,
	}, sigPayload(ctx))
	if err != nil {
		return err
	}
	_, err = s.propose(ctx, cmd)
	return err
}

func (s *RaftStore) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) error {
	now := s.currentTime(ctx)
	cmd, err := raft.NewCommandWithSignature(s.namespace, raft.CmdUpdateRegisterLabels, now, raft.UpdateLabelsPayload{
		ID:     id,
		Labels: labels,
	}, sigPayload(ctx))
	if err != nil {
		return err
	}
	_, err = s.propose(ctx, cmd)
	return err
}

func (s *RaftStore) ListRegisterEvents(ctx context.Context, registerID string) ([]storage.RegisterEvent, error) {
	return s.underlying.ListRegisterEvents(ctx, registerID)
}

func (s *RaftStore) DeleteRegister(ctx context.Context, id string) error {
	return s.proposeDelete(ctx, raft.CmdDeleteRegister, id)
}

func (s *RaftStore) CountRegisters(ctx context.Context) (map[string]int64, error) {
	return s.underlying.CountRegisters(ctx)
}

// ---------------------------------------------------------------------------
// Grant Operations
// ---------------------------------------------------------------------------

func (s *RaftStore) CreateGrant(ctx context.Context, grant storage.Grant) (storage.Grant, error) {
	if grant.ID == "" {
		grant.ID = storage.GenerateID()
	}
	now := s.currentTime(ctx)
	if grant.CreatedAt.IsZero() {
		grant.CreatedAt = now
	}
	if grant.UpdatedAt.IsZero() {
		grant.UpdatedAt = now
	}
	cmd, err := raft.NewCommand(s.namespace, raft.CmdCreateGrant, now, grant)
	if err != nil {
		return storage.Grant{}, err
	}
	resp, err := s.propose(ctx, cmd)
	if err != nil {
		return storage.Grant{}, err
	}
	if res, ok := resp.Data.(storage.Grant); ok {
		return res, nil
	}
	return grant, nil
}

func (s *RaftStore) GetGrant(ctx context.Context, id string) (storage.Grant, error) {
	return s.underlying.GetGrant(ctx, id)
}

func (s *RaftStore) ListGrants(ctx context.Context) ([]storage.Grant, error) {
	return s.underlying.ListGrants(ctx)
}

func (s *RaftStore) UpdateGrant(ctx context.Context, id string, payload map[string]any, requestVersion int) error {
	now := s.currentTime(ctx)
	cmd, err := raft.NewCommand(s.namespace, raft.CmdUpdateGrant, now, raft.UpdateGrantPayload{
		ID:             id,
		Payload:        payload,
		RequestVersion: requestVersion,
	})
	if err != nil {
		return err
	}
	_, err = s.propose(ctx, cmd)
	return err
}

func (s *RaftStore) CountGrants(ctx context.Context) (map[string]int64, error) {
	return s.underlying.CountGrants(ctx)
}

func (s *RaftStore) GetGrantForRequest(ctx context.Context, requestID string) (storage.Grant, bool, error) {
	return s.underlying.GetGrantForRequest(ctx, requestID)
}

func (s *RaftStore) DeleteGrant(ctx context.Context, id string) error {
	return s.proposeDelete(ctx, raft.CmdDeleteGrant, id)
}

// ---------------------------------------------------------------------------
// Schema Definition Operations
// ---------------------------------------------------------------------------

func (s *RaftStore) CreateSchemaDefinition(ctx context.Context, def storage.SchemaDefinition) (storage.SchemaDefinition, error) {
	if def.ID == "" {
		def.ID = storage.GenerateID()
	}
	now := s.currentTime(ctx)
	if def.CreatedAt.IsZero() {
		def.CreatedAt = now
	}
	cmd, err := raft.NewCommand(s.namespace, raft.CmdCreateSchemaDefinition, now, def)
	if err != nil {
		return storage.SchemaDefinition{}, err
	}
	resp, err := s.propose(ctx, cmd)
	if err != nil {
		return storage.SchemaDefinition{}, err
	}
	if res, ok := resp.Data.(storage.SchemaDefinition); ok {
		return res, nil
	}
	return def, nil
}

func (s *RaftStore) GetSchemaDefinition(ctx context.Context, id string) (storage.SchemaDefinition, error) {
	return s.underlying.GetSchemaDefinition(ctx, id)
}

func (s *RaftStore) ListSchemaDefinitions(ctx context.Context) ([]storage.SchemaDefinition, error) {
	return s.underlying.ListSchemaDefinitions(ctx)
}

func (s *RaftStore) UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) error {
	now := s.currentTime(ctx)
	cmd, err := raft.NewCommand(s.namespace, raft.CmdUpdateSchemaDefinitionLabels, now, raft.UpdateLabelsPayload{
		ID:     id,
		Labels: labels,
	})
	if err != nil {
		return err
	}
	_, err = s.propose(ctx, cmd)
	return err
}

func (s *RaftStore) DeleteSchemaDefinition(ctx context.Context, id string) error {
	return s.proposeDelete(ctx, raft.CmdDeleteSchemaDefinition, id)
}

// ---------------------------------------------------------------------------
// Signature Operations
// ---------------------------------------------------------------------------

func (s *RaftStore) RecordSignature(ctx context.Context, hostID string, timestamp int64, nonce string, expiresAt time.Time) error {
	now := s.currentTime(ctx)
	cmd, err := raft.NewCommand(s.namespace, raft.CmdRecordSignature, now, raft.RecordSignaturePayload{
		HostID:    hostID,
		Timestamp: timestamp,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return err
	}
	_, err = s.propose(ctx, cmd)
	return err
}
