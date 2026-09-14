package raft

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	hashiraft "github.com/hashicorp/raft"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
	"github.com/tasansga/terraform-provider-grantory/internal/store"
)

func TestFSMApplyMultiNamespace(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	fsm := NewFSM(ctx, nsStore)

	// 1. Create host in namespace "team_a"
	hostA := storage.Host{ID: "host-a", CreatedAt: time.Now().UTC()}
	cmdA, err := NewCommand("team_a", CmdCreateHost, hostA.CreatedAt, hostA)
	require.NoError(t, err)
	bytesA, err := cmdA.Encode()
	require.NoError(t, err)

	respA := fsm.Apply(&hashiraft.Log{Index: 1, Term: 1, Data: bytesA})
	appRespA, ok := respA.(ApplyResponse)
	require.True(t, ok)
	require.NoError(t, appRespA.Error)

	// 2. Verify "team_a" has host-a, but "team_b" does not
	storeA, err := nsStore.StoreFor(ctx, "team_a")
	require.NoError(t, err)
	resHostA, err := storeA.GetHost(ctx, "host-a")
	require.NoError(t, err)
	assert.Equal(t, "host-a", resHostA.ID)

	storeB, err := nsStore.StoreFor(ctx, "team_b")
	require.NoError(t, err)
	_, err = storeB.GetHost(ctx, "host-a")
	assert.ErrorIs(t, err, storage.ErrHostNotFound)

	// 3. Create host in namespace "team_b" and verify it does not leak into "team_a"
	hostB := storage.Host{ID: "host-b", CreatedAt: time.Now().UTC()}
	cmdB, err := NewCommand("team_b", CmdCreateHost, hostB.CreatedAt, hostB)
	require.NoError(t, err)
	bytesB, err := cmdB.Encode()
	require.NoError(t, err)

	respB := fsm.Apply(&hashiraft.Log{Index: 2, Term: 1, Data: bytesB})
	appRespB, ok := respB.(ApplyResponse)
	require.True(t, ok)
	require.NoError(t, appRespB.Error)

	resHostB, err := storeB.GetHost(ctx, "host-b")
	require.NoError(t, err)
	assert.Equal(t, "host-b", resHostB.ID)

	_, err = storeA.GetHost(ctx, "host-b")
	assert.ErrorIs(t, err, storage.ErrHostNotFound)
}

func TestFSMApplyBadLogData(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	fsm := NewFSM(ctx, nsStore)

	t.Run("nil log", func(t *testing.T) {
		resp := fsm.Apply(nil)
		appResp, ok := resp.(ApplyResponse)
		require.True(t, ok)
		require.Error(t, appResp.Error)
		assert.Contains(t, appResp.Error.Error(), "log entry is nil")
	})

	t.Run("corrupt data", func(t *testing.T) {
		resp := fsm.Apply(&hashiraft.Log{Index: 42, Term: 1, Data: []byte("not-valid-json")})
		appResp, ok := resp.(ApplyResponse)
		require.True(t, ok)
		require.Error(t, appResp.Error)
		assert.Contains(t, appResp.Error.Error(), "decode command at index 42")
	})

	t.Run("invalid namespace", func(t *testing.T) {
		cmd, err := NewCommand("bad", CmdCreateHost, time.Now().UTC(), storage.Host{ID: "host-bad"})
		require.NoError(t, err)
		data, err := cmd.Encode()
		require.NoError(t, err)

		resp := fsm.Apply(&hashiraft.Log{Index: 3, Term: 1, Data: data})
		appResp, ok := resp.(ApplyResponse)
		require.True(t, ok)
		require.Error(t, appResp.Error)
		assert.Contains(t, appResp.Error.Error(), "resolve namespace store")
	})

	t.Run("invalid command type", func(t *testing.T) {
		cmd := RaftCommand{
			Namespace: "team_a",
			Type:      CommandType("UNKNOWN_CMD"),
			Timestamp: time.Now().UTC(),
			Payload:   []byte(`{}`),
		}
		data, err := cmd.Encode()
		require.NoError(t, err)

		resp := fsm.Apply(&hashiraft.Log{Index: 4, Term: 1, Data: data})
		appResp, ok := resp.(ApplyResponse)
		require.True(t, ok)
		require.Error(t, appResp.Error)
		assert.Contains(t, appResp.Error.Error(), "unknown command type")
	})

	t.Run("invalid payload missing required field", func(t *testing.T) {
		cmd, err := NewCommand("team_a", CmdCreateHost, time.Now().UTC(), storage.Host{})
		require.NoError(t, err)
		data, err := cmd.Encode()
		require.NoError(t, err)

		resp := fsm.Apply(&hashiraft.Log{Index: 5, Term: 1, Data: data})
		appResp, ok := resp.(ApplyResponse)
		require.True(t, ok)
		require.Error(t, appResp.Error)
		assert.Contains(t, appResp.Error.Error(), "id is required")
	})
}

func TestFSMInterface(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	fsm := NewFSM(ctx, nsStore)

	// Verify interface compliance
	var _ hashiraft.FSM = fsm

	// Verify Snapshot succeeds
	snap, err := fsm.Snapshot()
	require.NoError(t, err)
	require.NotNil(t, snap)
	snap.Release()

	// Verify Restore fails on invalid data
	reader := io.NopCloser(strings.NewReader("dummy-snapshot-stream"))
	err = fsm.Restore(reader)
	require.Error(t, err)
}

func TestFSMNilContext(t *testing.T) {
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(context.Background(), dir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	//nolint:staticcheck // testing nil context resilience
	fsm := NewFSM(nil, nsStore)
	require.NotNil(t, fsm)
	require.NotNil(t, fsm.ctx)

	host := storage.Host{ID: "host-ctx", CreatedAt: time.Now().UTC()}
	cmd, err := NewCommand("team_a", CmdCreateHost, host.CreatedAt, host)
	require.NoError(t, err)
	data, err := cmd.Encode()
	require.NoError(t, err)

	resp := fsm.Apply(&hashiraft.Log{Index: 1, Term: 1, Data: data})
	appResp, ok := resp.(ApplyResponse)
	require.True(t, ok)
	require.NoError(t, appResp.Error)
}

func TestFSMNilNamespaceStore(t *testing.T) {
	ctx := context.Background()
	fsm := NewFSM(ctx, nil)

	host := storage.Host{ID: "host-nil", CreatedAt: time.Now().UTC()}
	cmd, err := NewCommand("team_a", CmdCreateHost, host.CreatedAt, host)
	require.NoError(t, err)
	data, err := cmd.Encode()
	require.NoError(t, err)

	resp := fsm.Apply(&hashiraft.Log{Index: 1, Term: 1, Data: data})
	appResp, ok := resp.(ApplyResponse)
	require.True(t, ok)
	require.Error(t, appResp.Error)
	assert.Contains(t, appResp.Error.Error(), "namespace store not initialized")
}

type testLogHook struct {
	entries []*logrus.Entry
}

func (h *testLogHook) Levels() []logrus.Level {
	return []logrus.Level{logrus.ErrorLevel}
}

func (h *testLogHook) Fire(entry *logrus.Entry) error {
	h.entries = append(h.entries, entry)
	return nil
}

func TestFSMApplyErrorLogging(t *testing.T) {
	hook := &testLogHook{}
	logrus.AddHook(hook)
	defer func() {
		for lvl, hooks := range logrus.StandardLogger().Hooks {
			var filtered []logrus.Hook
			for _, hk := range hooks {
				if hk != hook {
					filtered = append(filtered, hk)
				}
			}
			logrus.StandardLogger().Hooks[lvl] = filtered
		}
	}()

	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	fsm := NewFSM(ctx, nsStore)

	// Case 1: Corrupted command payload
	resp := fsm.Apply(&hashiraft.Log{Index: 10, Term: 2, Data: []byte("invalid-command-data")})
	appResp, ok := resp.(ApplyResponse)
	require.True(t, ok)
	require.Error(t, appResp.Error)

	require.NotEmpty(t, hook.entries, "expected an error to be logged for invalid command data")
	lastEntry := hook.entries[len(hook.entries)-1]
	assert.Equal(t, logrus.ErrorLevel, lastEntry.Level)
	assert.Equal(t, "failed to apply raft log entry", lastEntry.Message)
	assert.Equal(t, uint64(10), lastEntry.Data["index"])
	assert.Equal(t, uint64(2), lastEntry.Data["term"])
	assert.Nil(t, lastEntry.Data["namespace"], "namespace should be omitted from error log on decode failure")
	assert.Nil(t, lastEntry.Data["cmd_type"], "cmd_type should be omitted from error log on decode failure")

	// Case 2: Invalid namespace in command
	invalidCmd := RaftCommand{
		Namespace: "ab", // too short, fails validation
		Type:      CmdCreateHost,
		Timestamp: time.Now().UTC(),
	}
	invalidBytes, err := invalidCmd.Encode()
	require.NoError(t, err)

	resp = fsm.Apply(&hashiraft.Log{Index: 11, Term: 2, Data: invalidBytes})
	appResp, ok = resp.(ApplyResponse)
	require.True(t, ok)
	require.Error(t, appResp.Error)

	require.True(t, len(hook.entries) >= 2)
	lastEntry = hook.entries[len(hook.entries)-1]
	assert.Equal(t, logrus.ErrorLevel, lastEntry.Level)
	assert.Equal(t, "failed to apply raft log entry", lastEntry.Message)
	assert.Equal(t, "ab", lastEntry.Data["namespace"])
	assert.Equal(t, CmdCreateHost, lastEntry.Data["cmd_type"])
}

type multiLevelLogHook struct {
	entries []*logrus.Entry
	levels  []logrus.Level
}

func (h *multiLevelLogHook) Levels() []logrus.Level {
	return h.levels
}

func (h *multiLevelLogHook) Fire(entry *logrus.Entry) error {
	h.entries = append(h.entries, entry)
	return nil
}

func TestFSMApplyDomainErrorLogging(t *testing.T) {
	origLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	defer logrus.SetLevel(origLevel)

	hook := &multiLevelLogHook{
		levels: []logrus.Level{logrus.ErrorLevel, logrus.DebugLevel},
	}
	logrus.AddHook(hook)
	defer func() {
		for lvl, hooks := range logrus.StandardLogger().Hooks {
			var filtered []logrus.Hook
			for _, hk := range hooks {
				if hk != hook {
					filtered = append(filtered, hk)
				}
			}
			logrus.StandardLogger().Hooks[lvl] = filtered
		}
	}()

	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	fsm := NewFSM(ctx, nsStore)

	// 1. Create a host with a specific UniqueKey
	host := storage.Host{
		ID:        "host-unique-1",
		UniqueKey: "unique-key-1",
		CreatedAt: time.Now().UTC(),
	}
	cmd, err := NewCommand("team_a", CmdCreateHost, host.CreatedAt, host)
	require.NoError(t, err)
	data, err := cmd.Encode()
	require.NoError(t, err)

	resp := fsm.Apply(&hashiraft.Log{Index: 1, Term: 1, Data: data})
	appResp, ok := resp.(ApplyResponse)
	require.True(t, ok)
	require.NoError(t, appResp.Error)

	hook.entries = nil

	// 2. Create another host with the same UniqueKey -> triggers ErrHostUniqueKeyConflict
	host2 := storage.Host{
		ID:        "host-unique-2",
		UniqueKey: "unique-key-1",
		CreatedAt: time.Now().UTC(),
	}
	cmd2, err := NewCommand("team_a", CmdCreateHost, host2.CreatedAt, host2)
	require.NoError(t, err)
	data2, err := cmd2.Encode()
	require.NoError(t, err)

	resp2 := fsm.Apply(&hashiraft.Log{Index: 2, Term: 1, Data: data2})
	appResp2, ok := resp2.(ApplyResponse)
	require.True(t, ok)
	require.Error(t, appResp2.Error)
	assert.ErrorIs(t, appResp2.Error, storage.ErrHostUniqueKeyConflict)

	// Should be logged at DebugLevel, not ErrorLevel
	require.NotEmpty(t, hook.entries)
	lastEntry := hook.entries[len(hook.entries)-1]
	assert.Equal(t, logrus.DebugLevel, lastEntry.Level)
	assert.Equal(t, "failed to apply raft log entry", lastEntry.Message)

	// Verify no ErrorLevel was logged for this domain conflict
	for _, e := range hook.entries {
		assert.NotEqual(t, logrus.ErrorLevel, e.Level, "domain conflict should not log at ErrorLevel")
	}
}

func TestFSMIsDomainConflictOrExpectedError_ImmutableErrors(t *testing.T) {
	assert.True(t, isDomainConflictOrExpectedError(storage.ErrRequestImmutable), "ErrRequestImmutable must be recognized as expected domain conflict error")
	assert.True(t, isDomainConflictOrExpectedError(storage.ErrRegisterImmutable), "ErrRegisterImmutable must be recognized as expected domain conflict error")
}

func TestFSMApplyImmutableErrorLogging(t *testing.T) {
	origLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	defer logrus.SetLevel(origLevel)

	hook := &multiLevelLogHook{
		levels: []logrus.Level{logrus.ErrorLevel, logrus.DebugLevel},
	}
	logrus.AddHook(hook)
	defer func() {
		for lvl, hooks := range logrus.StandardLogger().Hooks {
			var filtered []logrus.Hook
			for _, hk := range hooks {
				if hk != hook {
					filtered = append(filtered, hk)
				}
			}
			logrus.StandardLogger().Hooks[lvl] = filtered
		}
	}()

	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	fsm := NewFSM(ctx, nsStore)
	now := time.Now().UTC()

	// Setup: create host
	host := storage.Host{ID: "host-imm-1", CreatedAt: now}
	hostCmd, err := NewCommand("team_a", CmdCreateHost, now, host)
	require.NoError(t, err)
	hostBytes, err := hostCmd.Encode()
	require.NoError(t, err)
	resp := fsm.Apply(&hashiraft.Log{Index: 1, Term: 1, Data: hostBytes})
	require.NoError(t, resp.(ApplyResponse).Error)

	// Setup: create immutable request (Mutable: false)
	req := storage.Request{
		ID:        "req-imm-1",
		HostID:    "host-imm-1",
		Payload:   map[string]any{"task": "build"},
		Mutable:   false,
		CreatedAt: now,
		UpdatedAt: now,
	}
	reqCmd, err := NewCommand("team_a", CmdCreateRequest, now, req)
	require.NoError(t, err)
	reqBytes, err := reqCmd.Encode()
	require.NoError(t, err)
	resp = fsm.Apply(&hashiraft.Log{Index: 2, Term: 1, Data: reqBytes})
	require.NoError(t, resp.(ApplyResponse).Error)

	// Setup: create immutable register (Mutable: false)
	reg := storage.Register{
		ID:        "reg-imm-1",
		HostID:    "host-imm-1",
		Payload:   map[string]any{"service": "auth"},
		Mutable:   false,
		CreatedAt: now,
		UpdatedAt: now,
	}
	regCmd, err := NewCommand("team_a", CmdCreateRegister, now, reg)
	require.NoError(t, err)
	regBytes, err := regCmd.Encode()
	require.NoError(t, err)
	resp = fsm.Apply(&hashiraft.Log{Index: 3, Term: 1, Data: regBytes})
	require.NoError(t, resp.(ApplyResponse).Error)

	// 1. Test CmdUpdateRequest payload update on immutable request -> ErrRequestImmutable
	hook.entries = nil
	newPayload := map[string]any{"task": "deploy"}
	updateReqCmd, err := NewCommand("team_a", CmdUpdateRequest, now, UpdateRequestPayload{
		ID:      "req-imm-1",
		Payload: &newPayload,
	})
	require.NoError(t, err)
	updateReqBytes, err := updateReqCmd.Encode()
	require.NoError(t, err)

	resp = fsm.Apply(&hashiraft.Log{Index: 4, Term: 1, Data: updateReqBytes})
	appResp, ok := resp.(ApplyResponse)
	require.True(t, ok)
	require.Error(t, appResp.Error)
	assert.ErrorIs(t, appResp.Error, storage.ErrRequestImmutable)

	require.NotEmpty(t, hook.entries)
	lastEntry := hook.entries[len(hook.entries)-1]
	assert.Equal(t, logrus.DebugLevel, lastEntry.Level)
	assert.Equal(t, "failed to apply raft log entry", lastEntry.Message)
	for _, e := range hook.entries {
		assert.NotEqual(t, logrus.ErrorLevel, e.Level, "ErrRequestImmutable should not log at ErrorLevel")
	}

	// 2. Test CmdUpdateRegister payload update on immutable register -> ErrRegisterImmutable
	hook.entries = nil
	newRegPayload := map[string]any{"service": "billing"}
	updateRegCmd, err := NewCommand("team_a", CmdUpdateRegister, now, UpdateRegisterPayload{
		ID:      "reg-imm-1",
		Payload: &newRegPayload,
	})
	require.NoError(t, err)
	updateRegBytes, err := updateRegCmd.Encode()
	require.NoError(t, err)

	resp = fsm.Apply(&hashiraft.Log{Index: 5, Term: 1, Data: updateRegBytes})
	appResp, ok = resp.(ApplyResponse)
	require.True(t, ok)
	require.Error(t, appResp.Error)
	assert.ErrorIs(t, appResp.Error, storage.ErrRegisterImmutable)

	require.NotEmpty(t, hook.entries)
	lastEntry = hook.entries[len(hook.entries)-1]
	assert.Equal(t, logrus.DebugLevel, lastEntry.Level)
	assert.Equal(t, "failed to apply raft log entry", lastEntry.Message)
	for _, e := range hook.entries {
		assert.NotEqual(t, logrus.ErrorLevel, e.Level, "ErrRegisterImmutable should not log at ErrorLevel")
	}
}

func TestFSMIsDomainConflictOrExpectedError_ReferencedNotFoundErrors(t *testing.T) {
	assert.True(t, isDomainConflictOrExpectedError(storage.ErrReferencedHostNotFound), "ErrReferencedHostNotFound must be recognized as expected domain conflict error")
	assert.True(t, isDomainConflictOrExpectedError(storage.ErrReferencedRequestNotFound), "ErrReferencedRequestNotFound must be recognized as expected domain conflict error")
}

func TestFSMApplyReferencedNotFoundErrorLogging(t *testing.T) {
	origLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	defer logrus.SetLevel(origLevel)

	hook := &multiLevelLogHook{
		levels: []logrus.Level{logrus.ErrorLevel, logrus.DebugLevel},
	}
	logrus.AddHook(hook)
	defer func() {
		for lvl, hooks := range logrus.StandardLogger().Hooks {
			var filtered []logrus.Hook
			for _, hk := range hooks {
				if hk != hook {
					filtered = append(filtered, hk)
				}
			}
			logrus.StandardLogger().Hooks[lvl] = filtered
		}
	}()

	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	fsm := NewFSM(ctx, nsStore)
	now := time.Now().UTC()

	// 1. Test CmdCreateRequest referencing a non-existent host -> ErrReferencedHostNotFound
	hook.entries = nil
	req := storage.Request{
		ID:        "req-ref-missing-host",
		HostID:    "nonexistent-host",
		Payload:   map[string]any{"action": "test"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	reqCmd, err := NewCommand("team_a", CmdCreateRequest, now, req)
	require.NoError(t, err)
	reqBytes, err := reqCmd.Encode()
	require.NoError(t, err)

	resp := fsm.Apply(&hashiraft.Log{Index: 1, Term: 1, Data: reqBytes})
	appResp, ok := resp.(ApplyResponse)
	require.True(t, ok)
	require.Error(t, appResp.Error)
	assert.ErrorIs(t, appResp.Error, storage.ErrReferencedHostNotFound)

	require.NotEmpty(t, hook.entries)
	lastEntry := hook.entries[len(hook.entries)-1]
	assert.Equal(t, logrus.DebugLevel, lastEntry.Level)
	assert.Equal(t, "failed to apply raft log entry", lastEntry.Message)
	for _, e := range hook.entries {
		assert.NotEqual(t, logrus.ErrorLevel, e.Level, "ErrReferencedHostNotFound should not log at ErrorLevel")
	}

	// 2. Test CmdCreateGrant referencing a non-existent request -> ErrReferencedRequestNotFound
	hook.entries = nil
	grant := storage.Grant{
		ID:             "grant-ref-missing-req",
		RequestID:      "nonexistent-req",
		Payload:        map[string]any{"granted": true},
		RequestVersion: 1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	grantCmd, err := NewCommand("team_a", CmdCreateGrant, now, grant)
	require.NoError(t, err)
	grantBytes, err := grantCmd.Encode()
	require.NoError(t, err)

	resp = fsm.Apply(&hashiraft.Log{Index: 2, Term: 1, Data: grantBytes})
	appResp, ok = resp.(ApplyResponse)
	require.True(t, ok)
	require.Error(t, appResp.Error)
	assert.ErrorIs(t, appResp.Error, storage.ErrReferencedRequestNotFound)

	require.NotEmpty(t, hook.entries)
	lastEntry = hook.entries[len(hook.entries)-1]
	assert.Equal(t, logrus.DebugLevel, lastEntry.Level)
	assert.Equal(t, "failed to apply raft log entry", lastEntry.Message)
	for _, e := range hook.entries {
		assert.NotEqual(t, logrus.ErrorLevel, e.Level, "ErrReferencedRequestNotFound should not log at ErrorLevel")
	}
}



type mockFSMRegistrar struct {
	addrs map[string]string
}

func (m *mockFSMRegistrar) RegisterHTTPAddr(raftAddrOrID, httpAddr string) {
	if m.addrs == nil {
		m.addrs = make(map[string]string)
	}
	m.addrs[raftAddrOrID] = httpAddr
}

func (m *mockFSMRegistrar) DeregisterHTTPAddr(raftAddrOrID string) {
	if m.addrs != nil {
		delete(m.addrs, raftAddrOrID)
	}
}

func TestFSMApplyRegisterNodeHTTPAddr(t *testing.T) {
	ctx := context.Background()
	fsm := NewFSM(ctx, nil)
	mockReg := &mockFSMRegistrar{}
	fsm.SetRegistrar(mockReg)

	payload := RegisterNodeHTTPAddrPayload{
		ServerID: "node-99",
		Address:  "192.168.1.99:9090",
		HTTPAddr: "http://192.168.1.99:8080",
	}
	cmd, err := NewCommand("", CmdRegisterNodeHTTPAddr, time.Now().UTC(), payload)
	require.NoError(t, err)

	data, err := cmd.Encode()
	require.NoError(t, err)

	resp := fsm.Apply(&hashiraft.Log{Index: 1, Term: 1, Data: data})
	appResp, ok := resp.(ApplyResponse)
	require.True(t, ok)
	require.NoError(t, appResp.Error)

	assert.Equal(t, "http://192.168.1.99:8080", mockReg.addrs["node-99"])
	assert.Equal(t, "http://192.168.1.99:8080", mockReg.addrs["192.168.1.99:9090"])
}

func TestFSMApplyDeregisterNodeHTTPAddr(t *testing.T) {
	ctx := context.Background()
	fsm := NewFSM(ctx, nil)
	mockReg := &mockFSMRegistrar{
		addrs: map[string]string{
			"node-99":           "http://192.168.1.99:8080",
			"192.168.1.99:9090": "http://192.168.1.99:8080",
			"node-kept":         "http://192.168.1.100:8080",
		},
	}
	fsm.SetRegistrar(mockReg)

	payload := DeregisterNodeHTTPAddrPayload{
		ServerID: "node-99",
		Address:  "192.168.1.99:9090",
	}
	cmd, err := NewCommand("", CmdDeregisterNodeHTTPAddr, time.Now().UTC(), payload)
	require.NoError(t, err)

	data, err := cmd.Encode()
	require.NoError(t, err)

	resp := fsm.Apply(&hashiraft.Log{Index: 2, Term: 1, Data: data})
	appResp, ok := resp.(ApplyResponse)
	require.True(t, ok)
	require.NoError(t, appResp.Error)

	assert.NotContains(t, mockReg.addrs, "node-99")
	assert.NotContains(t, mockReg.addrs, "192.168.1.99:9090")
	assert.Equal(t, "http://192.168.1.100:8080", mockReg.addrs["node-kept"])
}

func TestRaftNodeAddrByServerID(t *testing.T) {
	node := &RaftNode{
		addrByServerID: map[string]string{
			"node-1": "10.0.0.1:9090",
			"node-2": "10.0.0.2:9090",
		},
	}
	assert.Equal(t, "10.0.0.1:9090", node.AddrByServerID("node-1"))
	assert.Equal(t, "10.0.0.2:9090", node.AddrByServerID("node-2"))
	assert.Empty(t, node.AddrByServerID("node-3"))
}

func TestRaftNodeDeregisterHTTPAddrReciprocalCleanup(t *testing.T) {
	t.Run("deregister by server ID cleans up address mapping", func(t *testing.T) {
		node := &RaftNode{
			httpAddrs: map[string]string{
				"node-2":        "http://10.0.0.2:8080",
				"10.0.0.2:9090": "http://10.0.0.2:8080",
				"node-3":        "http://10.0.0.3:8080",
				"10.0.0.3:9090": "http://10.0.0.3:8080",
			},
			addrByServerID: map[string]string{
				"node-2": "10.0.0.2:9090",
				"node-3": "10.0.0.3:9090",
			},
			serverIDByAddr: map[string]string{
				"10.0.0.2:9090": "node-2",
				"10.0.0.3:9090": "node-3",
			},
		}

		node.DeregisterHTTPAddr("node-2")

		assert.Empty(t, node.HTTPAddrFor("node-2"))
		assert.Empty(t, node.HTTPAddrFor("10.0.0.2:9090"))
		assert.Equal(t, "http://10.0.0.3:8080", node.HTTPAddrFor("node-3"))
		assert.Equal(t, "http://10.0.0.3:8080", node.HTTPAddrFor("10.0.0.3:9090"))
	})

	t.Run("deregister by raft address cleans up server ID mapping", func(t *testing.T) {
		node := &RaftNode{
			httpAddrs: map[string]string{
				"node-2":        "http://10.0.0.2:8080",
				"10.0.0.2:9090": "http://10.0.0.2:8080",
				"node-3":        "http://10.0.0.3:8080",
				"10.0.0.3:9090": "http://10.0.0.3:8080",
			},
			addrByServerID: map[string]string{
				"node-2": "10.0.0.2:9090",
				"node-3": "10.0.0.3:9090",
			},
			serverIDByAddr: map[string]string{
				"10.0.0.2:9090": "node-2",
				"10.0.0.3:9090": "node-3",
			},
		}

		node.DeregisterHTTPAddr("10.0.0.2:9090")

		assert.Empty(t, node.HTTPAddrFor("node-2"))
		assert.Empty(t, node.HTTPAddrFor("10.0.0.2:9090"))
		assert.Equal(t, "http://10.0.0.3:8080", node.HTTPAddrFor("node-3"))
		assert.Equal(t, "http://10.0.0.3:8080", node.HTTPAddrFor("10.0.0.3:9090"))
	})
}
