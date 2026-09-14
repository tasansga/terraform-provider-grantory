package raft

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	hashiraft "github.com/hashicorp/raft"
	"github.com/sirupsen/logrus"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
	"github.com/tasansga/terraform-provider-grantory/internal/store"
)

var _ hashiraft.FSM = (*FSM)(nil)

// HTTPAddrRegistrar is an interface for registering node HTTP addresses.
type HTTPAddrRegistrar interface {
	RegisterHTTPAddr(raftAddrOrID, httpAddr string)
	DeregisterHTTPAddr(raftAddrOrID string)
}

// FSM implements hashicorp/raft.FSM to replicate and apply state machine mutations
// across multiple isolated tenant SQLite databases managed by NamespaceStore.
type FSM struct {
	ctx       context.Context
	nsStore   *store.NamespaceStore
	registrar HTTPAddrRegistrar
}

// NewFSM constructs a new multi-tenant Raft Finite State Machine.
func NewFSM(ctx context.Context, nsStore *store.NamespaceStore) *FSM {
	if ctx == nil {
		ctx = context.Background()
	}
	return &FSM{
		ctx:     ctx,
		nsStore: nsStore,
	}
}

// SetRegistrar sets the HTTPAddrRegistrar used to store cluster node HTTP addresses.
func (f *FSM) SetRegistrar(reg HTTPAddrRegistrar) {
	if f != nil {
		f.registrar = reg
	}
}

// Apply is called once a log entry is committed by a majority of the cluster.
// It decodes the RaftCommand, resolves the isolated tenant SQLite store from the NamespaceStore,
// and executes deterministic mutations via Mutator.Dispatch.
func (f *FSM) Apply(l *hashiraft.Log) interface{} {
	if l == nil {
		return ApplyResponse{Error: errors.New("log entry is nil")}
	}

	cmd, err := DecodeCommand(l.Data)
	if err != nil {
		err = fmt.Errorf("decode command at index %d: %w", l.Index, err)
		logrus.WithError(err).
			WithField("index", l.Index).
			WithField("term", l.Term).
			Error("failed to apply raft log entry")
		return ApplyResponse{Error: err}
	}

	if cmd.Type == CmdRegisterNodeHTTPAddr {
		var payload RegisterNodeHTTPAddrPayload
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			err = fmt.Errorf("unmarshal register node http addr payload at index %d: %w", l.Index, err)
			logrus.WithError(err).
				WithField("index", l.Index).
				WithField("term", l.Term).
				Error("failed to apply raft log entry")
			return ApplyResponse{Error: err}
		}
		if f.registrar != nil {
			if payload.Address != "" {
				f.registrar.RegisterHTTPAddr(payload.Address, payload.HTTPAddr)
			}
			if payload.ServerID != "" {
				f.registrar.RegisterHTTPAddr(payload.ServerID, payload.HTTPAddr)
			}
		}
		return ApplyResponse{}
	}

	if cmd.Type == CmdDeregisterNodeHTTPAddr {
		var payload DeregisterNodeHTTPAddrPayload
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			err = fmt.Errorf("unmarshal deregister node http addr payload at index %d: %w", l.Index, err)
			logrus.WithError(err).
				WithField("index", l.Index).
				WithField("term", l.Term).
				Error("failed to apply raft log entry")
			return ApplyResponse{Error: err}
		}
		if f.registrar != nil {
			if payload.ServerID != "" {
				f.registrar.DeregisterHTTPAddr(payload.ServerID)
			}
			if payload.Address != "" {
				f.registrar.DeregisterHTTPAddr(payload.Address)
			}
		}
		return ApplyResponse{}
	}

	if f.nsStore == nil {
		err = errors.New("namespace store not initialized")
		logrus.WithError(err).
			WithField("index", l.Index).
			WithField("term", l.Term).
			WithField("namespace", cmd.Namespace).
			WithField("cmd_type", cmd.Type).
			Error("failed to apply raft log entry")
		return ApplyResponse{Error: err}
	}

	store, err := f.nsStore.StoreFor(f.ctx, cmd.Namespace)
	if err != nil {
		err = fmt.Errorf("resolve namespace store %q: %w", cmd.Namespace, err)
		logrus.WithError(err).
			WithField("index", l.Index).
			WithField("term", l.Term).
			WithField("namespace", cmd.Namespace).
			WithField("cmd_type", cmd.Type).
			Error("failed to apply raft log entry")
		return ApplyResponse{Error: err}
	}

	mutator := NewMutator(store)
	resp := mutator.Dispatch(f.ctx, cmd)
	if resp.Error != nil {
		entry := logrus.WithError(resp.Error).
			WithField("index", l.Index).
			WithField("term", l.Term).
			WithField("namespace", cmd.Namespace).
			WithField("cmd_type", cmd.Type)
		if isDomainConflictOrExpectedError(resp.Error) {
			entry.Debug("failed to apply raft log entry")
		} else {
			entry.Error("failed to apply raft log entry")
		}
	}
	return resp
}

func isDomainConflictOrExpectedError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, storage.ErrHostUniqueKeyConflict) ||
		errors.Is(err, storage.ErrRequestUniqueKeyConflict) ||
		errors.Is(err, storage.ErrRegisterUniqueKeyConflict) ||
		errors.Is(err, storage.ErrSchemaDefinitionUniqueKeyConflict) ||
		errors.Is(err, storage.ErrHostAlreadyExists) ||
		errors.Is(err, storage.ErrRequestAlreadyExists) ||
		errors.Is(err, storage.ErrRegisterAlreadyExists) ||
		errors.Is(err, storage.ErrGrantAlreadyExists) ||
		errors.Is(err, storage.ErrSchemaDefinitionAlreadyExists) ||
		errors.Is(err, storage.ErrReplayDetected) ||
		errors.Is(err, storage.ErrTimestampRegressed) ||
		errors.Is(err, storage.ErrHostNotFound) ||
		errors.Is(err, storage.ErrRequestNotFound) ||
		errors.Is(err, storage.ErrRegisterNotFound) ||
		errors.Is(err, storage.ErrGrantNotFound) ||
		errors.Is(err, storage.ErrSchemaDefinitionNotFound) ||
		errors.Is(err, storage.ErrGrantRequestVersionConflict) ||
		errors.Is(err, storage.ErrRequestImmutable) ||
		errors.Is(err, storage.ErrRegisterImmutable) ||
		errors.Is(err, storage.ErrReferencedHostNotFound) ||
		errors.Is(err, storage.ErrReferencedRequestNotFound)
}

// Snapshot returns an FSMSnapshot used for log compaction and state restoration.
func (f *FSM) Snapshot() (hashiraft.FSMSnapshot, error) {
	if f == nil || f.nsStore == nil {
		return nil, errors.New("namespace store not initialized")
	}
	var httpAddrs map[string]string
	if provider, ok := f.registrar.(interface{ HTTPAddrs() map[string]string }); ok && provider != nil {
		httpAddrs = provider.HTTPAddrs()
	}
	return NewFSMSnapshotWithHTTPAddrs(f.ctx, f.nsStore, httpAddrs)
}

// Restore resets the FSM state from a snapshot stream.
func (f *FSM) Restore(rc io.ReadCloser) error {
	if f == nil || f.nsStore == nil {
		if rc != nil {
			_ = rc.Close()
		}
		return errors.New("namespace store not initialized")
	}
	return RestoreSnapshotWithRegistrar(rc, f.nsStore, f.registrar)
}
