package raft

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

func setupTestStore(t *testing.T) (context.Context, storage.Store) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	store, err := storage.New(ctx, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.Migrate(ctx))
	return ctx, store
}

func TestMutatorCreateRequestDeterministic(t *testing.T) {
	ctx, store := setupTestStore(t)

	mutator := NewMutator(store)

	// Create host first
	fixedTime := time.Date(2026, 9, 6, 15, 0, 0, 0, time.UTC)
	_, err := mutator.ApplyCreateHost(ctx, storage.Host{ID: "host-1", CreatedAt: fixedTime})
	require.NoError(t, err)

	req := storage.Request{
		ID:        "req-fixed-id",
		HostID:    "host-1",
		UniqueKey: "uk-1",
		Payload:   map[string]any{"hello": "world"},
		Labels:    map[string]string{"tier": "web"},
		CreatedAt: fixedTime,
		UpdatedAt: fixedTime,
	}

	result, err := mutator.ApplyCreateRequest(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "req-fixed-id", result.ID)

	// Verify persistence in SQLite
	fetched, err := store.GetRequest(ctx, "req-fixed-id")
	require.NoError(t, err)
	assert.Equal(t, "req-fixed-id", fetched.ID)
	assert.Equal(t, "host-1", fetched.HostID)
	assert.Equal(t, "web", fetched.Labels["tier"])
	assert.True(t, fixedTime.Equal(fetched.CreatedAt))
	assert.True(t, fixedTime.Equal(fetched.UpdatedAt))
}

func TestMutatorRequestLifecycleDeterministic(t *testing.T) {
	ctx, store := setupTestStore(t)
	mutator := NewMutator(store)

	fixedTime := time.Date(2026, 9, 6, 15, 0, 0, 0, time.UTC)
	_, err := mutator.ApplyCreateHost(ctx, storage.Host{ID: "host-req-1", CreatedAt: fixedTime})
	require.NoError(t, err)

	req := storage.Request{
		ID:        "req-fixed-lifecycle",
		HostID:    "host-req-1",
		UniqueKey: "uk-req-lifecycle",
		Payload:   map[string]any{"task": "build"},
		Labels:    map[string]string{"tier": "web"},
		Mutable:   true,
		CreatedAt: fixedTime,
		UpdatedAt: fixedTime,
	}

	result, err := mutator.ApplyCreateRequest(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "req-fixed-lifecycle", result.ID)

	// Verify persistence in store
	fetched, err := store.GetRequest(ctx, "req-fixed-lifecycle")
	require.NoError(t, err)
	assert.Equal(t, "build", fetched.Payload["task"])
	assert.True(t, fixedTime.Equal(fetched.CreatedAt))
	assert.True(t, fixedTime.Equal(fetched.UpdatedAt))

	// Update request payload
	updateTime := fixedTime.Add(time.Hour)
	newPayload := map[string]any{"task": "deploy"}
	err = mutator.ApplyUpdateRequest(ctx, "req-fixed-lifecycle", &newPayload, nil, updateTime)
	require.NoError(t, err)

	fetched, err = store.GetRequest(ctx, "req-fixed-lifecycle")
	require.NoError(t, err)
	assert.Equal(t, "deploy", fetched.Payload["task"])
	assert.True(t, updateTime.Equal(fetched.UpdatedAt))

	// Update request labels
	labelUpdateTime := updateTime.Add(10 * time.Minute)
	err = mutator.ApplyUpdateRequestLabels(ctx, "req-fixed-lifecycle", map[string]string{"tier": "worker"}, labelUpdateTime)
	require.NoError(t, err)

	fetched, err = store.GetRequest(ctx, "req-fixed-lifecycle")
	require.NoError(t, err)
	assert.Equal(t, "worker", fetched.Labels["tier"])
	assert.True(t, labelUpdateTime.Equal(fetched.UpdatedAt))

	// Delete request
	deleteTime := labelUpdateTime.Add(10 * time.Minute)
	err = mutator.ApplyDeleteRequest(storage.WithDeterministicTime(ctx, deleteTime), "req-fixed-lifecycle")
	require.NoError(t, err)

	_, err = store.GetRequest(ctx, "req-fixed-lifecycle")
	assert.ErrorIs(t, err, storage.ErrRequestNotFound)
}

func TestMutatorHostLifecycleDeterministic(t *testing.T) {
	ctx, store := setupTestStore(t)
	mutator := NewMutator(store)

	fixedTime := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	host := storage.Host{
		ID:        "host-deterministic-1",
		UniqueKey: "host-uk-1",
		PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...",
		Labels:    map[string]string{"env": "staging"},
		CreatedAt: fixedTime,
	}

	res, err := mutator.ApplyCreateHost(ctx, host)
	require.NoError(t, err)
	assert.Equal(t, host.ID, res.ID)

	fetched, err := store.GetHost(ctx, host.ID)
	require.NoError(t, err)
	assert.Equal(t, host.ID, fetched.ID)
	assert.Equal(t, host.UniqueKey, fetched.UniqueKey)
	assert.Equal(t, "staging", fetched.Labels["env"])
	assert.True(t, fixedTime.Equal(fetched.CreatedAt))

	// Test conflict on unique key
	conflictHost := storage.Host{
		ID:        "host-deterministic-2",
		UniqueKey: "host-uk-1",
		CreatedAt: fixedTime,
	}
	_, err = mutator.ApplyCreateHost(ctx, conflictHost)
	assert.ErrorIs(t, err, storage.ErrHostUniqueKeyConflict)

	// Update host labels
	err = mutator.ApplyUpdateHostLabels(ctx, host.ID, map[string]string{"env": "prod"})
	require.NoError(t, err)
	fetched, err = store.GetHost(ctx, host.ID)
	require.NoError(t, err)
	assert.Equal(t, "prod", fetched.Labels["env"])

	// Delete host
	err = mutator.ApplyDeleteHost(ctx, host.ID)
	require.NoError(t, err)
	_, err = store.GetHost(ctx, host.ID)
	assert.ErrorIs(t, err, storage.ErrHostNotFound)
}

func TestMutatorRegisterLifecycleDeterministic(t *testing.T) {
	ctx, store := setupTestStore(t)
	mutator := NewMutator(store)

	fixedTime := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	_, err := mutator.ApplyCreateHost(ctx, storage.Host{ID: "host-r1", CreatedAt: fixedTime})
	require.NoError(t, err)

	reg := storage.Register{
		ID:        "reg-fixed-1",
		HostID:    "host-r1",
		UniqueKey: "reg-uk-1",
		Payload:   map[string]any{"service": "auth"},
		Mutable:   true,
		Labels:    map[string]string{"zone": "us-east"},
		CreatedAt: fixedTime,
		UpdatedAt: fixedTime,
	}

	created, err := mutator.ApplyCreateRegister(ctx, reg)
	require.NoError(t, err)
	assert.Equal(t, "reg-fixed-1", created.ID)

	fetched, err := store.GetRegister(ctx, "reg-fixed-1")
	require.NoError(t, err)
	assert.Equal(t, "reg-fixed-1", fetched.ID)
	assert.Equal(t, "auth", fetched.Payload["service"])
	assert.Equal(t, "us-east", fetched.Labels["zone"])
	assert.True(t, fixedTime.Equal(fetched.CreatedAt))

	// Update register
	updateTime := fixedTime.Add(time.Hour)
	newPayload := map[string]any{"service": "auth-v2"}
	err = mutator.ApplyUpdateRegister(ctx, "reg-fixed-1", &newPayload, nil, updateTime)
	require.NoError(t, err)

	fetched, err = store.GetRegister(ctx, "reg-fixed-1")
	require.NoError(t, err)
	assert.Equal(t, "auth-v2", fetched.Payload["service"])
	assert.True(t, updateTime.Equal(fetched.UpdatedAt))

	// Update register labels
	err = mutator.ApplyUpdateRegisterLabels(ctx, "reg-fixed-1", map[string]string{"zone": "us-west"}, updateTime)
	require.NoError(t, err)
	fetched, err = store.GetRegister(ctx, "reg-fixed-1")
	require.NoError(t, err)
	assert.Equal(t, "us-west", fetched.Labels["zone"])

	// Check register events were recorded
	events, err := store.ListRegisterEvents(ctx, "reg-fixed-1")
	require.NoError(t, err)
	assert.Len(t, events, 3) // created, payload_updated, labels_updated

	// Delete register
	err = mutator.ApplyDeleteRegister(storage.WithDeterministicTime(ctx, updateTime.Add(time.Minute)), "reg-fixed-1")
	require.NoError(t, err)
	_, err = store.GetRegister(ctx, "reg-fixed-1")
	assert.ErrorIs(t, err, storage.ErrRegisterNotFound)
}

func TestMutatorGrantLifecycleDeterministic(t *testing.T) {
	ctx, store := setupTestStore(t)
	mutator := NewMutator(store)

	reqTime := time.Date(2026, 9, 6, 14, 0, 0, 0, time.UTC)
	_, err := mutator.ApplyCreateHost(ctx, storage.Host{ID: "host-g1", CreatedAt: reqTime})
	require.NoError(t, err)

	_, err = mutator.ApplyCreateRequest(ctx, storage.Request{
		ID:        "req-g1",
		HostID:    "host-g1",
		Version:   1,
		CreatedAt: reqTime,
		UpdatedAt: reqTime,
	})
	require.NoError(t, err)

	grantTime := reqTime.Add(10 * time.Minute)
	grant := storage.Grant{
		ID:             "grant-fixed-1",
		RequestID:      "req-g1",
		Payload:        map[string]any{"role": "admin"},
		RequestVersion: 1,
		CreatedAt:      grantTime,
		UpdatedAt:      grantTime,
	}

	created, err := mutator.ApplyCreateGrant(ctx, grant)
	require.NoError(t, err)
	assert.Equal(t, "grant-fixed-1", created.ID)

	fetched, err := store.GetGrant(ctx, "grant-fixed-1")
	require.NoError(t, err)
	assert.Equal(t, "grant-fixed-1", fetched.ID)
	assert.Equal(t, "admin", fetched.Payload["role"])
	assert.True(t, grantTime.Equal(fetched.CreatedAt))

	// Update grant
	updateGrantTime := grantTime.Add(5 * time.Minute)
	err = mutator.ApplyUpdateGrant(ctx, "grant-fixed-1", map[string]any{"role": "superadmin"}, 1, updateGrantTime)
	require.NoError(t, err)

	fetched, err = store.GetGrant(ctx, "grant-fixed-1")
	require.NoError(t, err)
	assert.Equal(t, "superadmin", fetched.Payload["role"])
	assert.True(t, updateGrantTime.Equal(fetched.UpdatedAt))

	// Delete grant
	err = mutator.ApplyDeleteGrant(storage.WithDeterministicTime(ctx, updateGrantTime.Add(time.Minute)), "grant-fixed-1")
	require.NoError(t, err)
	_, err = store.GetGrant(ctx, "grant-fixed-1")
	assert.ErrorIs(t, err, storage.ErrGrantNotFound)
}

func TestMutatorSchemaLifecycleDeterministic(t *testing.T) {
	ctx, store := setupTestStore(t)
	mutator := NewMutator(store)

	fixedTime := time.Date(2026, 9, 6, 8, 0, 0, 0, time.UTC)
	def := storage.SchemaDefinition{
		ID:        "schema-fixed-1",
		UniqueKey: "schema-uk-1",
		Schema:    json.RawMessage(`{"type":"object"}`),
		Labels:    map[string]string{"category": "test"},
		CreatedAt: fixedTime,
	}

	created, err := mutator.ApplyCreateSchemaDefinition(ctx, def)
	require.NoError(t, err)
	assert.Equal(t, "schema-fixed-1", created.ID)

	fetched, err := store.GetSchemaDefinition(ctx, "schema-fixed-1")
	require.NoError(t, err)
	assert.Equal(t, "schema-fixed-1", fetched.ID)
	assert.Equal(t, "schema-uk-1", fetched.UniqueKey)
	assert.True(t, fixedTime.Equal(fetched.CreatedAt))

	// Update schema labels
	err = mutator.ApplyUpdateSchemaLabels(ctx, "schema-fixed-1", map[string]string{"category": "prod"})
	require.NoError(t, err)
	fetched, err = store.GetSchemaDefinition(ctx, "schema-fixed-1")
	require.NoError(t, err)
	assert.Equal(t, "prod", fetched.Labels["category"])

	// Delete schema definition
	err = mutator.ApplyDeleteSchemaDefinition(storage.WithDeterministicTime(ctx, fixedTime), "schema-fixed-1")
	require.NoError(t, err)
	_, err = store.GetSchemaDefinition(ctx, "schema-fixed-1")
	assert.ErrorIs(t, err, storage.ErrSchemaDefinitionNotFound)
}

func TestMutatorRecordSignatureDeterministic(t *testing.T) {
	ctx, store := setupTestStore(t)
	mutator := NewMutator(store)

	now := time.Now().UTC()
	exp := now.Add(5 * time.Minute)

	_, err := mutator.ApplyCreateHost(ctx, storage.Host{ID: "host-sig-1", CreatedAt: now})
	require.NoError(t, err)

	// Record initial signature
	err = mutator.ApplyRecordSignature(ctx, "host-sig-1", 1000, "nonce-1", exp)
	require.NoError(t, err)

	// Replay nonce must fail
	err = mutator.ApplyRecordSignature(ctx, "host-sig-1", 1005, "nonce-1", exp)
	assert.ErrorIs(t, err, storage.ErrReplayDetected)

	// Timestamp regression beyond grace period must fail
	err = mutator.ApplyRecordSignature(ctx, "host-sig-1", 900, "nonce-2", exp)
	assert.ErrorIs(t, err, storage.ErrTimestampRegressed)

	// Advance timestamp with unique nonce succeeds
	err = mutator.ApplyRecordSignature(ctx, "host-sig-1", 1020, "nonce-2", exp)
	require.NoError(t, err)
}

func TestMutatorDispatchAllCommands(t *testing.T) {
	ctx, store := setupTestStore(t)
	mutator := NewMutator(store)

	now := time.Date(2026, 9, 6, 16, 0, 0, 0, time.UTC)

	// 1. Dispatch CmdCreateHost
	hostCmd, err := NewCommand("ns", CmdCreateHost, now, storage.Host{
		ID:        "host-disp-1",
		Labels:    map[string]string{"role": "db"},
		CreatedAt: now,
	})
	require.NoError(t, err)
	resp := mutator.Dispatch(ctx, hostCmd)
	require.NoError(t, resp.Error)
	createdHost, ok := resp.Data.(storage.Host)
	require.True(t, ok)
	assert.Equal(t, "host-disp-1", createdHost.ID)

	// 2. Dispatch CmdUpdateHostLabels
	updateHostLabelsCmd, err := NewCommand("ns", CmdUpdateHostLabels, now, UpdateLabelsPayload{
		ID:     "host-disp-1",
		Labels: map[string]string{"role": "worker"},
	})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, updateHostLabelsCmd)
	require.NoError(t, resp.Error)

	// 3. Dispatch CmdRecordSignature
	recSigCmd, err := NewCommand("ns", CmdRecordSignature, now, RecordSignaturePayload{
		HostID:    "host-disp-1",
		Timestamp: 2000,
		Nonce:     "nonce-disp-1",
		ExpiresAt: now.Add(time.Hour),
	})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, recSigCmd)
	require.NoError(t, resp.Error)

	// 4. Dispatch CmdCreateSchemaDefinition
	schemaCmd, err := NewCommand("ns", CmdCreateSchemaDefinition, now, storage.SchemaDefinition{
		ID:        "schema-disp-1",
		Schema:    json.RawMessage(`{"title":"demo"}`),
		CreatedAt: now,
	})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, schemaCmd)
	require.NoError(t, resp.Error)

	// 5. Dispatch CmdUpdateSchemaDefinitionLabels
	updateSchemaLabelsCmd, err := NewCommand("ns", CmdUpdateSchemaDefinitionLabels, now, UpdateLabelsPayload{
		ID:     "schema-disp-1",
		Labels: map[string]string{"v": "2"},
	})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, updateSchemaLabelsCmd)
	require.NoError(t, resp.Error)

	// 6. Dispatch CmdCreateRequest
	reqCmd, err := NewCommand("ns", CmdCreateRequest, now, storage.Request{
		ID:        "req-disp-1",
		HostID:    "host-disp-1",
		Payload:   map[string]any{"task": "build"},
		Mutable:   true,
		Version:   1,
		CreatedAt: now,
		UpdatedAt: now,
	})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, reqCmd)
	require.NoError(t, resp.Error)

	// 7. Dispatch CmdUpdateRequest
	newReqPayload := map[string]any{"task": "deploy"}
	updateReqCmd, err := NewCommand("ns", CmdUpdateRequest, now, UpdateRequestPayload{
		ID:      "req-disp-1",
		Payload: &newReqPayload,
	})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, updateReqCmd)
	require.NoError(t, resp.Error)

	// 8. Dispatch CmdUpdateRequestLabels
	updateReqLabelsCmd, err := NewCommand("ns", CmdUpdateRequestLabels, now, UpdateLabelsPayload{
		ID:     "req-disp-1",
		Labels: map[string]string{"status": "in_progress"},
	})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, updateReqLabelsCmd)
	require.NoError(t, resp.Error)

	// 9. Dispatch CmdCreateRegister
	regCmd, err := NewCommand("ns", CmdCreateRegister, now, storage.Register{
		ID:        "reg-disp-1",
		HostID:    "host-disp-1",
		Payload:   map[string]any{"svc": "api"},
		Mutable:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, regCmd)
	require.NoError(t, resp.Error)

	// 10. Dispatch CmdUpdateRegister
	newRegPayload := map[string]any{"svc": "api-v2"}
	updateRegCmd, err := NewCommand("ns", CmdUpdateRegister, now, UpdateRegisterPayload{
		ID:      "reg-disp-1",
		Payload: &newRegPayload,
	})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, updateRegCmd)
	require.NoError(t, resp.Error)

	// 11. Dispatch CmdUpdateRegisterLabels
	updateRegLabelsCmd, err := NewCommand("ns", CmdUpdateRegisterLabels, now, UpdateLabelsPayload{
		ID:     "reg-disp-1",
		Labels: map[string]string{"env": "prod"},
	})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, updateRegLabelsCmd)
	require.NoError(t, resp.Error)

	// 12. Dispatch CmdCreateGrant
	grantCmd, err := NewCommand("ns", CmdCreateGrant, now, storage.Grant{
		ID:             "grant-disp-1",
		RequestID:      "req-disp-1",
		Payload:        map[string]any{"granted": true},
		RequestVersion: 2,
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, grantCmd)
	require.NoError(t, resp.Error)

	// 13. Dispatch CmdUpdateGrant
	updateGrantCmd, err := NewCommand("ns", CmdUpdateGrant, now, UpdateGrantPayload{
		ID:             "grant-disp-1",
		Payload:        map[string]any{"granted": true, "token": "abc"},
		RequestVersion: 2,
	})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, updateGrantCmd)
	require.NoError(t, resp.Error)

	// 14. Dispatch CmdDeleteGrant
	delGrantCmd, err := NewCommand("ns", CmdDeleteGrant, now, DeletePayload{ID: "grant-disp-1"})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, delGrantCmd)
	require.NoError(t, resp.Error)

	// 15. Dispatch CmdDeleteRegister
	delRegCmd, err := NewCommand("ns", CmdDeleteRegister, now, DeletePayload{ID: "reg-disp-1"})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, delRegCmd)
	require.NoError(t, resp.Error)

	// 16. Dispatch CmdDeleteRequest
	delReqCmd, err := NewCommand("ns", CmdDeleteRequest, now, DeletePayload{ID: "req-disp-1"})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, delReqCmd)
	require.NoError(t, resp.Error)

	// 17. Dispatch CmdDeleteSchemaDefinition
	delSchemaCmd, err := NewCommand("ns", CmdDeleteSchemaDefinition, now, DeletePayload{ID: "schema-disp-1"})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, delSchemaCmd)
	require.NoError(t, resp.Error)

	// 18. Dispatch CmdDeleteHost
	delHostCmd, err := NewCommand("ns", CmdDeleteHost, now, DeletePayload{ID: "host-disp-1"})
	require.NoError(t, err)
	resp = mutator.Dispatch(ctx, delHostCmd)
	require.NoError(t, resp.Error)

	// Verify unknown command returns error
	resp = mutator.Dispatch(ctx, RaftCommand{Type: "UNKNOWN"})
	require.Error(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "unknown command type")
}

func TestMutatorApplyUpdateGrant_EmptyPayloadStoresEmptyJSONInSQLite(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	store, err := storage.New(ctx, dbPath)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()
	require.NoError(t, store.Migrate(ctx))

	mutator := NewMutator(store)

	fixedTime := time.Date(2026, 9, 6, 15, 0, 0, 0, time.UTC)
	_, err = mutator.ApplyCreateHost(ctx, storage.Host{ID: "host-empty-p", CreatedAt: fixedTime})
	require.NoError(t, err)

	req := storage.Request{
		ID:        "req-empty-p",
		HostID:    "host-empty-p",
		UniqueKey: "uk-empty-p",
		Payload:   map[string]any{"initial": "val"},
		CreatedAt: fixedTime,
		UpdatedAt: fixedTime,
	}
	_, err = mutator.ApplyCreateRequest(ctx, req)
	require.NoError(t, err)

	grant := storage.Grant{
		ID:             "grant-empty-p",
		RequestID:      "req-empty-p",
		Payload:        map[string]any{"initial": "val"},
		RequestVersion: 1,
		CreatedAt:      fixedTime,
		UpdatedAt:      fixedTime,
	}
	_, err = mutator.ApplyCreateGrant(ctx, grant)
	require.NoError(t, err)

	// Apply CmdUpdateGrant via Dispatch with empty payload map[string]any{}
	updateCmd, err := NewCommand("default", CmdUpdateGrant, fixedTime.Add(time.Minute), UpdateGrantPayload{
		ID:             "grant-empty-p",
		Payload:        map[string]any{},
		RequestVersion: 1,
	})
	require.NoError(t, err)

	resp := mutator.Dispatch(ctx, updateCmd)
	require.NoError(t, resp.Error)

	// Fetch via store: Payload must be non-nil empty map
	fetched, err := store.GetGrant(ctx, "grant-empty-p")
	require.NoError(t, err)
	assert.NotNil(t, fetched.Payload)
	assert.Empty(t, fetched.Payload)

	// Direct raw SQLite inspection: ensure the database column is "{}" and NOT NULL
	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	var rawPayload sql.NullString
	err = db.QueryRowContext(ctx, "SELECT payload FROM grants WHERE id = ?", "grant-empty-p").Scan(&rawPayload)
	require.NoError(t, err)
	assert.True(t, rawPayload.Valid, "payload column must not be NULL")
	assert.Equal(t, "{}", rawPayload.String, "payload column must be raw JSON '{}'")
}

func TestMutatorDeterministicMissingID(t *testing.T) {
	ctx, store := setupTestStore(t)
	mutator := NewMutator(store)

	fixedTime := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	payload := map[string]any{"k": "v"}
	labels := map[string]string{"k": "v"}

	// ApplyCreateHost
	_, err := mutator.ApplyCreateHost(ctx, storage.Host{CreatedAt: fixedTime})
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyDeleteHost
	err = mutator.ApplyDeleteHost(ctx, "")
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyUpdateHostLabels
	err = mutator.ApplyUpdateHostLabels(ctx, "", labels)
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyRecordSignature
	err = mutator.ApplyRecordSignature(ctx, "", 1000, "nonce", fixedTime)
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyCreateRequest
	_, err = mutator.ApplyCreateRequest(ctx, storage.Request{CreatedAt: fixedTime, UpdatedAt: fixedTime, HostID: "h"})
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyUpdateRequest
	err = mutator.ApplyUpdateRequest(ctx, "", &payload, nil, fixedTime)
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyUpdateRequestLabels
	err = mutator.ApplyUpdateRequestLabels(ctx, "", labels, fixedTime)
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyDeleteRequest
	err = mutator.ApplyDeleteRequest(ctx, "")
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyCreateRegister
	_, err = mutator.ApplyCreateRegister(ctx, storage.Register{CreatedAt: fixedTime, UpdatedAt: fixedTime, HostID: "h"})
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyUpdateRegister
	err = mutator.ApplyUpdateRegister(ctx, "", &payload, nil, fixedTime)
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyUpdateRegisterLabels
	err = mutator.ApplyUpdateRegisterLabels(ctx, "", labels, fixedTime)
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyDeleteRegister
	err = mutator.ApplyDeleteRegister(ctx, "")
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyCreateGrant
	_, err = mutator.ApplyCreateGrant(ctx, storage.Grant{CreatedAt: fixedTime, UpdatedAt: fixedTime, RequestID: "r"})
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyUpdateGrant
	err = mutator.ApplyUpdateGrant(ctx, "", payload, 1, fixedTime)
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyDeleteGrant
	err = mutator.ApplyDeleteGrant(ctx, "")
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyCreateSchemaDefinition
	_, err = mutator.ApplyCreateSchemaDefinition(ctx, storage.SchemaDefinition{CreatedAt: fixedTime, Schema: json.RawMessage("{}")})
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyUpdateSchemaLabels
	err = mutator.ApplyUpdateSchemaLabels(ctx, "", labels)
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())

	// ApplyDeleteSchemaDefinition
	err = mutator.ApplyDeleteSchemaDefinition(ctx, "")
	require.Error(t, err)
	assert.Equal(t, "id is required", err.Error())
}

func TestMutatorDeterministicMissingTimestamp(t *testing.T) {
	ctx, store := setupTestStore(t)
	mutator := NewMutator(store)

	fixedTime := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	payload := map[string]any{"k": "v"}
	labels := map[string]string{"k": "v"}

	// ApplyCreateHost: zero CreatedAt
	_, err := mutator.ApplyCreateHost(ctx, storage.Host{ID: "host-no-ts"})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	// ApplyRecordSignature: zero timestamp or zero expiresAt
	err = mutator.ApplyRecordSignature(ctx, "host-1", 0, "nonce", fixedTime)
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	err = mutator.ApplyRecordSignature(ctx, "host-1", 1000, "nonce", time.Time{})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	// ApplyCreateRequest: zero timestamps
	_, err = mutator.ApplyCreateRequest(ctx, storage.Request{ID: "req-1", HostID: "host-1"})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	_, err = mutator.ApplyCreateRequest(ctx, storage.Request{ID: "req-1", HostID: "host-1", CreatedAt: fixedTime})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	// ApplyUpdateRequest: zero updatedAt
	err = mutator.ApplyUpdateRequest(ctx, "req-1", &payload, nil, time.Time{})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	// ApplyUpdateRequestLabels: zero updatedAt
	err = mutator.ApplyUpdateRequestLabels(ctx, "req-1", labels, time.Time{})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	// ApplyCreateRegister: zero timestamps
	_, err = mutator.ApplyCreateRegister(ctx, storage.Register{ID: "reg-1", HostID: "host-1"})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	_, err = mutator.ApplyCreateRegister(ctx, storage.Register{ID: "reg-1", HostID: "host-1", CreatedAt: fixedTime})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	// ApplyUpdateRegister: zero updatedAt
	err = mutator.ApplyUpdateRegister(ctx, "reg-1", &payload, nil, time.Time{})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	// ApplyUpdateRegisterLabels: zero updatedAt
	err = mutator.ApplyUpdateRegisterLabels(ctx, "reg-1", labels, time.Time{})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	// ApplyCreateGrant: zero timestamps
	_, err = mutator.ApplyCreateGrant(ctx, storage.Grant{ID: "grant-1", RequestID: "req-1"})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	_, err = mutator.ApplyCreateGrant(ctx, storage.Grant{ID: "grant-1", RequestID: "req-1", CreatedAt: fixedTime})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	// ApplyUpdateGrant: zero updatedAt
	err = mutator.ApplyUpdateGrant(ctx, "grant-1", payload, 1, time.Time{})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())

	// ApplyCreateSchemaDefinition: zero CreatedAt
	_, err = mutator.ApplyCreateSchemaDefinition(ctx, storage.SchemaDefinition{ID: "schema-1", Schema: json.RawMessage("{}")})
	require.Error(t, err)
	assert.Equal(t, "timestamp is required", err.Error())
}

func TestMutatorDeterministicLabelSorting(t *testing.T) {
	ctx, store := setupTestStore(t)
	mutator := NewMutator(store)

	fixedTime := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	labels := map[string]string{
		"zebra":  "val-z",
		"apple":  "val-a",
		"mango":  "val-m",
		"banana": "val-b",
		"cherry": "val-c",
	}

	_, err := mutator.ApplyCreateHost(ctx, storage.Host{
		ID:        "host-label-order",
		Labels:    labels,
		CreatedAt: fixedTime,
	})
	require.NoError(t, err)

	rows, err := store.DB().QueryContext(ctx, `SELECT key FROM host_labels WHERE host_id = ? ORDER BY rowid ASC`, "host-label-order")
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var insertedKeys []string
	for rows.Next() {
		var key string
		require.NoError(t, rows.Scan(&key))
		insertedKeys = append(insertedKeys, key)
	}
	require.NoError(t, rows.Err())

	expectedKeys := []string{"apple", "banana", "cherry", "mango", "zebra"}
	assert.Equal(t, expectedKeys, insertedKeys, "label rows must be inserted in strictly sorted alphabetical order")
}


func TestFormatDBTime(t *testing.T) {
	assert.Equal(t, "2006-01-02 15:04:05.000", storage.DBTimeLayout)

	// Subseconds formatted with millisecond precision according to storage.DBTimeLayout
	t1 := time.Date(2026, 9, 6, 15, 4, 5, 999999999, time.UTC)
	assert.Equal(t, "2026-09-06 15:04:05.999", storage.FormatDBTime(t1))

	// Zero nanoseconds padded with trailing zeros
	t2 := time.Date(2026, 9, 6, 15, 4, 5, 0, time.UTC)
	assert.Equal(t, "2026-09-06 15:04:05.000", storage.FormatDBTime(t2))

	// Intermediate millisecond fraction
	t3 := time.Date(2026, 9, 6, 15, 4, 5, 123456789, time.UTC)
	assert.Equal(t, "2026-09-06 15:04:05.123", storage.FormatDBTime(t3))
}

type captureSchemaDeleteStore struct {
	storage.Store
	capturedTime  time.Time
	capturedFound bool
	deletedID     string
}

func (s *captureSchemaDeleteStore) DeleteSchemaDefinition(ctx context.Context, id string) error {
	s.capturedTime, s.capturedFound = storage.DeterministicTimeFromContext(ctx)
	s.deletedID = id
	return s.Store.DeleteSchemaDefinition(ctx, id)
}

func TestMutatorApplyDeleteSchemaDefinitionDeterministicTime(t *testing.T) {
	ctx, baseStore := setupTestStore(t)

	// Create a schema definition to delete
	fixedCreated := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	_, err := baseStore.CreateSchemaDefinition(ctx, storage.SchemaDefinition{
		ID:        "schema-det-1",
		CreatedAt: fixedCreated,
		Schema:    json.RawMessage(`{"type":"object"}`),
	})
	require.NoError(t, err)

	storeWrapper := &captureSchemaDeleteStore{Store: baseStore}
	mutator := NewMutator(storeWrapper)

	// 1. With deterministic timestamp in context: context receives deterministic timestamp
	fixedDeleted := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	err = mutator.ApplyDeleteSchemaDefinition(storage.WithDeterministicTime(ctx, fixedDeleted), "schema-det-1")
	require.NoError(t, err)
	assert.Equal(t, "schema-det-1", storeWrapper.deletedID)
	assert.True(t, storeWrapper.capturedFound, "deterministic time should be present in context")
	assert.True(t, fixedDeleted.Equal(storeWrapper.capturedTime), "expected %v, got %v", fixedDeleted, storeWrapper.capturedTime)

	// 2. Without deterministic timestamp in context: context does not receive deterministic timestamp
	_, err = baseStore.CreateSchemaDefinition(ctx, storage.SchemaDefinition{
		ID:        "schema-det-2",
		CreatedAt: fixedCreated,
		Schema:    json.RawMessage(`{"type":"object"}`),
	})
	require.NoError(t, err)

	storeWrapper.capturedFound = false
	storeWrapper.capturedTime = time.Time{}
	err = mutator.ApplyDeleteSchemaDefinition(ctx, "schema-det-2")
	require.NoError(t, err)
	assert.Equal(t, "schema-det-2", storeWrapper.deletedID)
	assert.False(t, storeWrapper.capturedFound, "deterministic time should not be set when absent in context")

	// 3. Via Dispatch with CmdDeleteSchemaDefinition: cmd.Timestamp is injected into context
	_, err = baseStore.CreateSchemaDefinition(ctx, storage.SchemaDefinition{
		ID:        "schema-det-disp",
		CreatedAt: fixedCreated,
		Schema:    json.RawMessage(`{"type":"object"}`),
	})
	require.NoError(t, err)

	storeWrapper.capturedFound = false
	storeWrapper.capturedTime = time.Time{}
	dispatchTime := time.Date(2026, 9, 7, 14, 30, 0, 0, time.UTC)
	cmd, err := NewCommand("ns", CmdDeleteSchemaDefinition, dispatchTime, DeletePayload{ID: "schema-det-disp"})
	require.NoError(t, err)
	resp := mutator.Dispatch(ctx, cmd)
	require.NoError(t, resp.Error)
	assert.Equal(t, "schema-det-disp", storeWrapper.deletedID)
	assert.True(t, storeWrapper.capturedFound, "deterministic time should be present in context from Dispatch")
	assert.True(t, dispatchTime.Equal(storeWrapper.capturedTime), "expected %v, got %v", dispatchTime, storeWrapper.capturedTime)
}

func TestMutatorDispatchBundledSignature(t *testing.T) {
	ctx, store := setupTestStore(t)
	mutator := NewMutator(store)

	now := time.Date(2026, 9, 6, 16, 0, 0, 0, time.UTC)
	_, err := mutator.ApplyCreateHost(ctx, storage.Host{
		ID:        "host-bundled-1",
		CreatedAt: now,
	})
	require.NoError(t, err)

	sigPayload := &RecordSignaturePayload{
		HostID:    "host-bundled-1",
		Timestamp: 3000,
		Nonce:     "nonce-bundled-1",
		ExpiresAt: now.Add(10 * time.Minute),
	}

	req := storage.Request{
		ID:        "req-bundled-1",
		HostID:    "host-bundled-1",
		UniqueKey: "uk-bundled-1",
		Payload:   map[string]any{"data": "val1"},
		CreatedAt: now,
		UpdatedAt: now,
	}

	// 1. Dispatch CmdCreateRequest with bundled signature: records signature and creates resource
	cmd, err := NewCommandWithSignature("ns", CmdCreateRequest, now, req, sigPayload)
	require.NoError(t, err)

	resp := mutator.Dispatch(ctx, cmd)
	require.NoError(t, resp.Error)
	createdReq, ok := resp.Data.(storage.Request)
	require.True(t, ok)
	assert.Equal(t, "req-bundled-1", createdReq.ID)

	savedReq, err := store.GetRequest(ctx, "req-bundled-1")
	require.NoError(t, err)
	assert.Equal(t, "req-bundled-1", savedReq.ID)

	// 2. Replay with identical nonce must fail with ErrReplayDetected and NOT mutate
	req2 := storage.Request{
		ID:        "req-bundled-2",
		HostID:    "host-bundled-1",
		UniqueKey: "uk-bundled-2",
		Payload:   map[string]any{"data": "val2"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	replaySig := &RecordSignaturePayload{
		HostID:    "host-bundled-1",
		Timestamp: 3005,
		Nonce:     "nonce-bundled-1", // Reused nonce
		ExpiresAt: now.Add(10 * time.Minute),
	}
	replayCmd, err := NewCommandWithSignature("ns", CmdCreateRequest, now, req2, replaySig)
	require.NoError(t, err)

	replayResp := mutator.Dispatch(ctx, replayCmd)
	assert.ErrorIs(t, replayResp.Error, storage.ErrReplayDetected)

	// Verify req-bundled-2 was NOT created in store
	_, err = store.GetRequest(ctx, "req-bundled-2")
	assert.ErrorIs(t, err, storage.ErrRequestNotFound)

	// 3. Timestamp regression must fail with ErrTimestampRegressed and NOT mutate
	req3 := storage.Request{
		ID:        "req-bundled-3",
		HostID:    "host-bundled-1",
		UniqueKey: "uk-bundled-3",
		Payload:   map[string]any{"data": "val3"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	regressedSig := &RecordSignaturePayload{
		HostID:    "host-bundled-1",
		Timestamp: 2000, // Regressed before 3000
		Nonce:     "nonce-bundled-unique",
		ExpiresAt: now.Add(10 * time.Minute),
	}
	regressedCmd, err := NewCommandWithSignature("ns", CmdCreateRequest, now, req3, regressedSig)
	require.NoError(t, err)

	regressedResp := mutator.Dispatch(ctx, regressedCmd)
	assert.ErrorIs(t, regressedResp.Error, storage.ErrTimestampRegressed)

	// Verify req-bundled-3 was NOT created in store
	_, err = store.GetRequest(ctx, "req-bundled-3")
	assert.ErrorIs(t, err, storage.ErrRequestNotFound)
}

func TestMutatorDispatchBundledSignatureAtomicity(t *testing.T) {
	ctx, store := setupTestStore(t)
	mutator := NewMutator(store)

	now := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	_, err := mutator.ApplyCreateHost(ctx, storage.Host{
		ID:        "host-atomic-1",
		CreatedAt: now,
	})
	require.NoError(t, err)

	// 1. Initial valid request with bundled signature
	sig1 := &RecordSignaturePayload{
		HostID:    "host-atomic-1",
		Timestamp: 5000,
		Nonce:     "nonce-atomic-1",
		ExpiresAt: now.Add(10 * time.Minute),
	}
	req1 := storage.Request{
		ID:        "req-atomic-1",
		HostID:    "host-atomic-1",
		UniqueKey: "uk-conflict-key",
		Payload:   map[string]any{"data": "atomic1"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	cmd1, err := NewCommandWithSignature("ns", CmdCreateRequest, now, req1, sig1)
	require.NoError(t, err)

	resp1 := mutator.Dispatch(ctx, cmd1)
	require.NoError(t, resp1.Error)

	// Verify req1 and nonce-atomic-1 exist
	_, err = store.GetRequest(ctx, "req-atomic-1")
	require.NoError(t, err)

	var nonce1Count int
	err = store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM nonces WHERE host_id = ? AND nonce = ?`, "host-atomic-1", "nonce-atomic-1").Scan(&nonce1Count)
	require.NoError(t, err)
	assert.Equal(t, 1, nonce1Count)

	// 2. Second request causes an entity mutation error (duplicate unique key "uk-conflict-key")
	sig2 := &RecordSignaturePayload{
		HostID:    "host-atomic-1",
		Timestamp: 5010,
		Nonce:     "nonce-rollback-test",
		ExpiresAt: now.Add(10 * time.Minute),
	}
	req2 := storage.Request{
		ID:        "req-atomic-2",
		HostID:    "host-atomic-1",
		UniqueKey: "uk-conflict-key", // duplicate!
		Payload:   map[string]any{"data": "atomic2"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	cmd2, err := NewCommandWithSignature("ns", CmdCreateRequest, now, req2, sig2)
	require.NoError(t, err)

	resp2 := mutator.Dispatch(ctx, cmd2)
	assert.ErrorIs(t, resp2.Error, storage.ErrRequestUniqueKeyConflict)

	// Verify req2 was NOT created
	_, err = store.GetRequest(ctx, "req-atomic-2")
	assert.ErrorIs(t, err, storage.ErrRequestNotFound)

	// CRITICAL ATOMICITY CHECK: Verify nonce-rollback-test was rolled back and NOT recorded in the nonces table
	var nonce2Count int
	err = store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM nonces WHERE host_id = ? AND nonce = ?`, "host-atomic-1", "nonce-rollback-test").Scan(&nonce2Count)
	require.NoError(t, err)
	assert.Equal(t, 0, nonce2Count, "nonce must not be recorded when entity mutation fails")

	// Verify that host's last_signature_timestamp was also rolled back
	host, err := store.GetHost(ctx, "host-atomic-1")
	require.NoError(t, err)
	assert.Equal(t, int64(5000), host.LastSignatureTimestamp, "host last signature timestamp must roll back")

	// 3. Since nonce-rollback-test was rolled back, a subsequent request using it (with a valid unique key) must SUCCEED
	req3 := storage.Request{
		ID:        "req-atomic-3",
		HostID:    "host-atomic-1",
		UniqueKey: "uk-conflict-resolved",
		Payload:   map[string]any{"data": "atomic3"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	cmd3, err := NewCommandWithSignature("ns", CmdCreateRequest, now, req3, sig2)
	require.NoError(t, err)

	resp3 := mutator.Dispatch(ctx, cmd3)
	require.NoError(t, resp3.Error, "nonce reuse must succeed because previous transaction rolled back")

	savedReq3, err := store.GetRequest(ctx, "req-atomic-3")
	require.NoError(t, err)
	assert.Equal(t, "req-atomic-3", savedReq3.ID)

	// Now nonce-rollback-test must be recorded
	err = store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM nonces WHERE host_id = ? AND nonce = ?`, "host-atomic-1", "nonce-rollback-test").Scan(&nonce2Count)
	require.NoError(t, err)
	assert.Equal(t, 1, nonce2Count)

	// 4. Subsequent replay of cmd3 must be rejected with ErrReplayDetected
	replayResp := mutator.Dispatch(ctx, cmd3)
	assert.ErrorIs(t, replayResp.Error, storage.ErrReplayDetected)
}
