package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	hashiraft "github.com/hashicorp/raft"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/cluster/raft"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
	"github.com/tasansga/terraform-provider-grantory/internal/store"
)

type mockProposer struct {
	lastCmd   raft.RaftCommand
	proposals int
	commands  []raft.RaftCommand
	respData  any
	respErr   error
	propErr   error
	dispatch  *raft.Mutator
}

func (m *mockProposer) Propose(ctx context.Context, cmd raft.RaftCommand) (raft.ApplyResponse, error) {
	m.proposals++
	m.lastCmd = cmd
	m.commands = append(m.commands, cmd)
	if m.propErr != nil {
		return raft.ApplyResponse{}, m.propErr
	}
	if m.dispatch != nil {
		return m.dispatch.Dispatch(ctx, cmd), nil
	}
	return raft.ApplyResponse{
		Data:  m.respData,
		Error: m.respErr,
	}, nil
}

func TestRaftStoreWriteMutationsProposeToRaft(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sqlStore, err := storage.New(ctx, dir+"/test.db")
	require.NoError(t, err)
	defer func() { _ = sqlStore.Close() }()

	proposer := &mockProposer{}
	raftStore := newRaftStore(sqlStore, proposer, "tenant-a")

	t.Run("CreateHost generates ID and timestamp", func(t *testing.T) {
		host, err := raftStore.CreateHost(ctx, storage.Host{
			UniqueKey: "host-1",
			Labels:    map[string]string{"env": "prod"},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, host.ID)
		assert.False(t, host.CreatedAt.IsZero())
		assert.Equal(t, "tenant-a", proposer.lastCmd.Namespace)
		assert.Equal(t, raft.CmdCreateHost, proposer.lastCmd.Type)
	})

	t.Run("CreateHost preserves given ID and propagates error", func(t *testing.T) {
		proposer.respErr = storage.ErrHostAlreadyExists
		_, err := raftStore.CreateHost(ctx, storage.Host{
			ID:        "explicit-id",
			UniqueKey: "host-2",
		})
		require.ErrorIs(t, err, storage.ErrHostAlreadyExists)
		assert.Equal(t, raft.CmdCreateHost, proposer.lastCmd.Type)
		proposer.respErr = nil
	})

	t.Run("DeleteHost proposes CmdDeleteHost", func(t *testing.T) {
		err := raftStore.DeleteHost(ctx, "host-to-del")
		require.NoError(t, err)
		assert.Equal(t, raft.CmdDeleteHost, proposer.lastCmd.Type)
	})

	t.Run("UpdateHostLabels proposes CmdUpdateHostLabels", func(t *testing.T) {
		err := raftStore.UpdateHostLabels(ctx, "host-1", map[string]string{"env": "staging"})
		require.NoError(t, err)
		assert.Equal(t, raft.CmdUpdateHostLabels, proposer.lastCmd.Type)
	})

	t.Run("RecordSignature proposes CmdRecordSignature", func(t *testing.T) {
		exp := time.Now().Add(5 * time.Minute)
		err := raftStore.RecordSignature(ctx, "host-1", 1234567890, "nonce-xyz", exp)
		require.NoError(t, err)
		assert.Equal(t, raft.CmdRecordSignature, proposer.lastCmd.Type)
	})

	t.Run("CreateRequest generates ID, timestamps and defaults version", func(t *testing.T) {
		req, err := raftStore.CreateRequest(ctx, storage.Request{
			HostID:  "host-1",
			Payload: map[string]any{"action": "read"},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, req.ID)
		assert.False(t, req.CreatedAt.IsZero())
		assert.False(t, req.UpdatedAt.IsZero())
		assert.Equal(t, 1, req.Version)
		assert.Equal(t, raft.CmdCreateRequest, proposer.lastCmd.Type)
	})

	t.Run("UpdateRequest proposes CmdUpdateRequest", func(t *testing.T) {
		payload := map[string]any{"action": "write"}
		err := raftStore.UpdateRequest(ctx, "req-1", &payload, nil)
		require.NoError(t, err)
		assert.Equal(t, raft.CmdUpdateRequest, proposer.lastCmd.Type)
	})

	t.Run("UpdateRequestLabels proposes CmdUpdateRequestLabels", func(t *testing.T) {
		err := raftStore.UpdateRequestLabels(ctx, "req-1", map[string]string{"tier": "gold"})
		require.NoError(t, err)
		assert.Equal(t, raft.CmdUpdateRequestLabels, proposer.lastCmd.Type)
	})

	t.Run("DeleteRequest proposes CmdDeleteRequest", func(t *testing.T) {
		err := raftStore.DeleteRequest(ctx, "req-1")
		require.NoError(t, err)
		assert.Equal(t, raft.CmdDeleteRequest, proposer.lastCmd.Type)
	})

	t.Run("CreateRegister generates ID and proposes CmdCreateRegister", func(t *testing.T) {
		reg, err := raftStore.CreateRegister(ctx, storage.Register{
			HostID:  "host-1",
			Payload: map[string]any{"key": "val"},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, reg.ID)
		assert.False(t, reg.CreatedAt.IsZero())
		assert.False(t, reg.UpdatedAt.IsZero())
		assert.Equal(t, raft.CmdCreateRegister, proposer.lastCmd.Type)
	})

	t.Run("UpdateRegister proposes CmdUpdateRegister", func(t *testing.T) {
		payload := map[string]any{"key": "val2"}
		err := raftStore.UpdateRegister(ctx, "reg-1", &payload, nil)
		require.NoError(t, err)
		assert.Equal(t, raft.CmdUpdateRegister, proposer.lastCmd.Type)
	})

	t.Run("UpdateRegisterLabels proposes CmdUpdateRegisterLabels", func(t *testing.T) {
		err := raftStore.UpdateRegisterLabels(ctx, "reg-1", map[string]string{"env": "test"})
		require.NoError(t, err)
		assert.Equal(t, raft.CmdUpdateRegisterLabels, proposer.lastCmd.Type)
	})

	t.Run("DeleteRegister proposes CmdDeleteRegister", func(t *testing.T) {
		err := raftStore.DeleteRegister(ctx, "reg-1")
		require.NoError(t, err)
		assert.Equal(t, raft.CmdDeleteRegister, proposer.lastCmd.Type)
	})

	t.Run("CreateGrant generates ID and proposes CmdCreateGrant", func(t *testing.T) {
		grant, err := raftStore.CreateGrant(ctx, storage.Grant{
			RequestID: "req-1",
			Payload:   map[string]any{"token": "xyz"},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, grant.ID)
		assert.False(t, grant.CreatedAt.IsZero())
		assert.False(t, grant.UpdatedAt.IsZero())
		assert.Equal(t, raft.CmdCreateGrant, proposer.lastCmd.Type)
	})

	t.Run("UpdateGrant proposes CmdUpdateGrant", func(t *testing.T) {
		err := raftStore.UpdateGrant(ctx, "grant-1", map[string]any{"token": "abc"}, 2)
		require.NoError(t, err)
		assert.Equal(t, raft.CmdUpdateGrant, proposer.lastCmd.Type)
	})

	t.Run("DeleteGrant proposes CmdDeleteGrant", func(t *testing.T) {
		err := raftStore.DeleteGrant(ctx, "grant-1")
		require.NoError(t, err)
		assert.Equal(t, raft.CmdDeleteGrant, proposer.lastCmd.Type)
	})

	t.Run("CreateSchemaDefinition generates ID and proposes CmdCreateSchemaDefinition", func(t *testing.T) {
		def, err := raftStore.CreateSchemaDefinition(ctx, storage.SchemaDefinition{
			Schema: []byte(`{"type":"object"}`),
		})
		require.NoError(t, err)
		assert.NotEmpty(t, def.ID)
		assert.False(t, def.CreatedAt.IsZero())
		assert.Equal(t, raft.CmdCreateSchemaDefinition, proposer.lastCmd.Type)
	})

	t.Run("UpdateSchemaDefinitionLabels proposes CmdUpdateSchemaDefinitionLabels", func(t *testing.T) {
		err := raftStore.UpdateSchemaDefinitionLabels(ctx, "def-1", map[string]string{"type": "user"})
		require.NoError(t, err)
		assert.Equal(t, raft.CmdUpdateSchemaDefinitionLabels, proposer.lastCmd.Type)
	})

	t.Run("DeleteSchemaDefinition proposes CmdDeleteSchemaDefinition", func(t *testing.T) {
		err := raftStore.DeleteSchemaDefinition(ctx, "def-1")
		require.NoError(t, err)
		assert.Equal(t, raft.CmdDeleteSchemaDefinition, proposer.lastCmd.Type)
	})
}

func TestRaftStoreReadDelegation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sqlStore, err := storage.New(ctx, dir+"/test.db")
	require.NoError(t, err)
	defer func() { _ = sqlStore.Close() }()
	require.NoError(t, sqlStore.Migrate(ctx))

	// Seed host directly in underlying storage
	seededHost, err := sqlStore.CreateHost(ctx, storage.Host{
		UniqueKey: "host-direct",
		Labels:    map[string]string{"loc": "us-east"},
	})
	require.NoError(t, err)

	proposer := &mockProposer{
		propErr: errors.New("proposer must NOT be called for reads"),
	}
	raftStore := newRaftStore(sqlStore, proposer, "default")

	// Verify read delegates to local store without calling proposer
	readHost, err := raftStore.GetHost(ctx, seededHost.ID)
	require.NoError(t, err)
	assert.Equal(t, seededHost.ID, readHost.ID)
	assert.Equal(t, "host-direct", readHost.UniqueKey)

	hosts, err := raftStore.ListHosts(ctx)
	require.NoError(t, err)
	assert.Len(t, hosts, 1)

	// Verify DB access, Migrate, and SetNamespace
	assert.NotNil(t, raftStore.DB())
	assert.NoError(t, raftStore.Migrate(ctx))
	raftStore.SetNamespace("custom-ns")
	assert.Equal(t, "custom-ns", raftStore.namespace)
}

func TestHTTPHandlersExecuteWritesThroughRaftStore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)
	defer func() { _ = nsStore.Close() }()

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftBootstrapExpect: 1,
		Database:            dir,
		BindAddr:            "0.0.0.0:8080",
	}

	raftNode, err := raft.NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = raftNode.Close() }()

	// Wait for single-node cluster to elect itself leader
	require.Eventually(t, func() bool {
		return raftNode.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	s := &Server{
		cfg:      cfg,
		nsStore:  nsStore,
		raftNode: raftNode,
	}

	app := fiber.New()
	api := app.Group("/", s.namespaceMiddleware())
	registerHostRoutes(api)

	// Execute POST /hosts to create a host via HTTP handler
	payload := `{"unique_key":"replicated-host-http","labels":{"env":"prod"}}`
	req := httptest.NewRequest(http.MethodPost, "/hosts", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Verify that the host is persisted in the namespace store via Raft FSM commit
	defaultStore, err := nsStore.StoreFor(ctx, store.DefaultNamespace)
	require.NoError(t, err)

	hosts, err := defaultStore.ListHosts(ctx)
	require.NoError(t, err)
	require.Len(t, hosts, 1)
	assert.Equal(t, "replicated-host-http", hosts[0].UniqueKey)
	assert.Equal(t, "prod", hosts[0].Labels["env"])
}

func TestRaftNodeLeaderHTTPAddressResolution(t *testing.T) {
	t.Run("maps Raft host to HTTP port", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		nsStore, err := store.NewNamespaceStore(ctx, dir)
		require.NoError(t, err)
		defer func() { _ = nsStore.Close() }()

		cfg := config.Config{
			RaftBind:            "127.0.0.1:0",
			RaftBootstrapExpect: 1,
			Database:            dir,
			BindAddr:            "0.0.0.0:8080",
		}

		raftNode, err := raft.NewRaftNode(ctx, cfg, nsStore, dir)
		require.NoError(t, err)
		defer func() { _ = raftNode.Close() }()

		require.Eventually(t, func() bool {
			return raftNode.IsLeader()
		}, 5*time.Second, 50*time.Millisecond)

		raftNode.SetHTTPPort("9090")
		httpAddr := raftNode.LeaderHTTPAddr()
		assert.Contains(t, httpAddr, ":9090")
	})

	t.Run("explicit registered HTTP address takes precedence", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		nsStore, err := store.NewNamespaceStore(ctx, dir)
		require.NoError(t, err)
		defer func() { _ = nsStore.Close() }()

		cfg := config.Config{
			RaftBind:            "127.0.0.1:0",
			RaftBootstrapExpect: 1,
			Database:            dir,
		}

		raftNode, err := raft.NewRaftNode(ctx, cfg, nsStore, dir)
		require.NoError(t, err)
		defer func() { _ = raftNode.Close() }()

		require.Eventually(t, func() bool {
			return raftNode.IsLeader()
		}, 5*time.Second, 50*time.Millisecond)

		leaderRaftAddr := raftNode.LeaderAddr()
		require.NotEmpty(t, leaderRaftAddr)

		raftNode.RegisterHTTPAddr(leaderRaftAddr, "https://leader.internal:8443")
		assert.Equal(t, "https://leader.internal:8443", raftNode.LeaderHTTPAddr())
	})

	t.Run("resolves peer HTTP address from RaftPeers @ syntax and RaftPeerHTTPAddrs flag", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		nsStore, err := store.NewNamespaceStore(ctx, dir)
		require.NoError(t, err)
		defer func() { _ = nsStore.Close() }()

		cfg := config.Config{
			RaftBind:            "127.0.0.1:0",
			RaftBootstrapExpect: 1,
			Database:            dir,
			RaftPeers: []string{
				"node-peer=10.0.0.2:8081@http://10.0.0.2:8080",
			},
			RaftPeerHTTPAddrs: []string{
				"10.0.0.3:8081=http://10.0.0.3:8080",
			},
		}

		raftNode, err := raft.NewRaftNode(ctx, cfg, nsStore, dir)
		require.NoError(t, err)
		defer func() { _ = raftNode.Close() }()

		// Test direct registration lookup
		raftNode.RegisterHTTPAddr("leader-id", "http://leader.example:8080")
		assert.Equal(t, "http://10.0.0.2:8080", raftNode.HTTPAddrFor("10.0.0.2:8081"))
		assert.Equal(t, "http://10.0.0.2:8080", raftNode.HTTPAddrFor("node-peer"))
		assert.Equal(t, "http://10.0.0.3:8080", raftNode.HTTPAddrFor("10.0.0.3:8081"))
	})

	t.Run("bootstraps with named peer mapping updating local node ID", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		nsStore, err := store.NewNamespaceStore(ctx, dir)
		require.NoError(t, err)
		defer func() { _ = nsStore.Close() }()

		cfg := config.Config{
			RaftBind:            "127.0.0.1:19999",
			RaftAdvertise:       "127.0.0.1:19999",
			RaftBootstrapExpect: 1,
			Database:            dir,
			RaftPeers: []string{
				"node-custom=127.0.0.1:19999@http://127.0.0.1:18888",
			},
		}

		raftNode, err := raft.NewRaftNode(ctx, cfg, nsStore, dir)
		require.NoError(t, err)
		defer func() { _ = raftNode.Close() }()

		assert.Equal(t, "node-custom", raftNode.NodeID(), "node ID should match configured peer name")
		assert.Equal(t, "http://127.0.0.1:18888", raftNode.HTTPAddrFor("node-custom"))
	})
}

type mockUnderlyingStore struct {
	storage.Store
	lastNamespace string
	callCount     int
}

func (m *mockUnderlyingStore) SetNamespace(namespace string) {
	m.callCount++
	m.lastNamespace = namespace
}

func TestRaftStoreSetNamespaceDelegatesToUnderlying(t *testing.T) {
	mockUnderlying := &mockUnderlyingStore{}
	proposer := &mockProposer{}
	raftStore := newRaftStore(mockUnderlying, proposer, "initial-ns")

	raftStore.SetNamespace("custom-namespace")

	assert.Equal(t, "custom-namespace", raftStore.namespace)
	assert.Equal(t, 1, mockUnderlying.callCount)
	assert.Equal(t, "custom-namespace", mockUnderlying.lastNamespace)
}

func TestRaftStoreProposeFailoverErrors(t *testing.T) {
	ctx := context.Background()
	mockUnderlying := &mockUnderlyingStore{}
	proposer := &mockProposer{}
	raftStore := newRaftStore(mockUnderlying, proposer, "test-ns")

	for _, tc := range []struct {
		failoverErr error
		expectedErr error
	}{
		{hashiraft.ErrNotLeader, storage.ErrNotLeader},
		{hashiraft.ErrLeadershipLost, storage.ErrLeadershipLost},
	} {
		t.Run("proposer error "+tc.failoverErr.Error(), func(t *testing.T) {
			proposer.propErr = tc.failoverErr
			proposer.respErr = nil

			assertFailover := func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.expectedErr), "expected %v, got: %v", tc.expectedErr, err)
			}

			_, err := raftStore.CreateHost(ctx, storage.Host{UniqueKey: "h-1"})
			assertFailover(t, err)

			err = raftStore.DeleteHost(ctx, "h-1")
			assertFailover(t, err)

			err = raftStore.UpdateHostLabels(ctx, "h-1", map[string]string{"env": "prod"})
			assertFailover(t, err)

			_, err = raftStore.CreateRequest(ctx, storage.Request{HostID: "h-1"})
			assertFailover(t, err)

			err = raftStore.UpdateRequest(ctx, "req-1", nil, nil)
			assertFailover(t, err)

			err = raftStore.UpdateRequestLabels(ctx, "req-1", map[string]string{"k": "v"})
			assertFailover(t, err)

			err = raftStore.DeleteRequest(ctx, "req-1")
			assertFailover(t, err)

			_, err = raftStore.CreateRegister(ctx, storage.Register{HostID: "h-1", UniqueKey: "reg-1"})
			assertFailover(t, err)

			err = raftStore.UpdateRegister(ctx, "reg-1", nil, nil)
			assertFailover(t, err)

			err = raftStore.UpdateRegisterLabels(ctx, "reg-1", map[string]string{"k": "v"})
			assertFailover(t, err)

			err = raftStore.DeleteRegister(ctx, "reg-1")
			assertFailover(t, err)

			_, err = raftStore.CreateGrant(ctx, storage.Grant{RequestID: "req-1"})
			assertFailover(t, err)

			err = raftStore.UpdateGrant(ctx, "g-1", nil, 1)
			assertFailover(t, err)

			err = raftStore.DeleteGrant(ctx, "g-1")
			assertFailover(t, err)

			_, err = raftStore.CreateSchemaDefinition(ctx, storage.SchemaDefinition{UniqueKey: "s-1"})
			assertFailover(t, err)

			err = raftStore.UpdateSchemaDefinitionLabels(ctx, "s-1", map[string]string{"k": "v"})
			assertFailover(t, err)

			err = raftStore.DeleteSchemaDefinition(ctx, "s-1")
			assertFailover(t, err)

			err = raftStore.RecordSignature(ctx, "h-1", 1234567890, "nonce-1", time.Now().Add(time.Minute))
			assertFailover(t, err)
		})

		t.Run("apply response error "+tc.failoverErr.Error(), func(t *testing.T) {
			proposer.propErr = nil
			proposer.respErr = tc.failoverErr

			assertFailover := func(t *testing.T, err error) {
				t.Helper()
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.expectedErr), "expected %v, got: %v", tc.expectedErr, err)
			}

			_, err := raftStore.CreateHost(ctx, storage.Host{UniqueKey: "h-1"})
			assertFailover(t, err)

			err = raftStore.DeleteHost(ctx, "h-1")
			assertFailover(t, err)

			_, err = raftStore.CreateRequest(ctx, storage.Request{HostID: "h-1"})
			assertFailover(t, err)

			err = raftStore.DeleteRequest(ctx, "req-1")
			assertFailover(t, err)
		})
	}

	t.Run("non-failover errors are preserved", func(t *testing.T) {
		proposer.propErr = errors.New("arbitrary network error")
		proposer.respErr = nil

		_, err := raftStore.CreateHost(ctx, storage.Host{UniqueKey: "h-1"})
		require.Error(t, err)
		var fe *fiber.Error
		assert.False(t, errors.As(err, &fe), "expected raw error, not fiber.Error")
		assert.Equal(t, "arbitrary network error", err.Error())
	})
}

func TestRaftStore_Unwrap(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()
	sqlStore, err := storage.New(ctx, dir+"/test.db")
	require.NoError(t, err)
	defer func() { _ = sqlStore.Close() }()

	proposer := &mockProposer{}
	raftStore := newRaftStore(sqlStore, proposer, "tenant-a")

	// Verify *RaftStore implements interface{ Unwrap() storage.Store }
	var unwrapper interface{ Unwrap() storage.Store } = raftStore
	assert.Same(t, sqlStore, unwrapper.Unwrap())

	// Verify nil receiver returns nil safely
	var nilStore *RaftStore
	assert.Nil(t, nilStore.Unwrap())
}

func TestRaftStore_DeterministicTime(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()
	sqlStore, err := storage.New(ctx, dir+"/test.db")
	require.NoError(t, err)
	defer func() { _ = sqlStore.Close() }()

	proposer := &mockProposer{}
	raftStore := newRaftStore(sqlStore, proposer, "tenant-det")

	fixedTime := time.Date(2025, time.January, 1, 12, 0, 0, 0, time.UTC)
	ctxDet := storage.WithDeterministicTime(ctx, fixedTime)

	t.Run("CreateHost uses deterministic time", func(t *testing.T) {
		host, err := raftStore.CreateHost(ctxDet, storage.Host{
			UniqueKey: "host-det",
		})
		require.NoError(t, err)
		assert.Equal(t, fixedTime, host.CreatedAt)
		assert.Equal(t, fixedTime, proposer.lastCmd.Timestamp)
	})

	t.Run("UpdateHostLabels uses deterministic time", func(t *testing.T) {
		err := raftStore.UpdateHostLabels(ctxDet, "host-det", map[string]string{"env": "test"})
		require.NoError(t, err)
		assert.Equal(t, fixedTime, proposer.lastCmd.Timestamp)
	})

	t.Run("DeleteHost uses deterministic time", func(t *testing.T) {
		err := raftStore.DeleteHost(ctxDet, "host-det")
		require.NoError(t, err)
		assert.Equal(t, fixedTime, proposer.lastCmd.Timestamp)
	})

	t.Run("CreateRequest uses deterministic time", func(t *testing.T) {
		req, err := raftStore.CreateRequest(ctxDet, storage.Request{
			HostID: "host-det",
		})
		require.NoError(t, err)
		assert.Equal(t, fixedTime, req.CreatedAt)
		assert.Equal(t, fixedTime, req.UpdatedAt)
		assert.Equal(t, fixedTime, proposer.lastCmd.Timestamp)
	})

	t.Run("UpdateRequest uses deterministic time", func(t *testing.T) {
		payload := map[string]any{"key": "val"}
		err := raftStore.UpdateRequest(ctxDet, "req-1", &payload, nil)
		require.NoError(t, err)
		assert.Equal(t, fixedTime, proposer.lastCmd.Timestamp)
	})

	t.Run("CreateRegister uses deterministic time", func(t *testing.T) {
		reg, err := raftStore.CreateRegister(ctxDet, storage.Register{
			HostID:    "host-det",
			UniqueKey: "reg-det",
		})
		require.NoError(t, err)
		assert.Equal(t, fixedTime, reg.CreatedAt)
		assert.Equal(t, fixedTime, reg.UpdatedAt)
		assert.Equal(t, fixedTime, proposer.lastCmd.Timestamp)
	})

	t.Run("CreateGrant uses deterministic time", func(t *testing.T) {
		grant, err := raftStore.CreateGrant(ctxDet, storage.Grant{
			RequestID: "req-1",
		})
		require.NoError(t, err)
		assert.Equal(t, fixedTime, grant.CreatedAt)
		assert.Equal(t, fixedTime, grant.UpdatedAt)
		assert.Equal(t, fixedTime, proposer.lastCmd.Timestamp)
	})

	t.Run("CreateSchemaDefinition uses deterministic time", func(t *testing.T) {
		def, err := raftStore.CreateSchemaDefinition(ctxDet, storage.SchemaDefinition{
			UniqueKey: "schema-det",
		})
		require.NoError(t, err)
		assert.Equal(t, fixedTime, def.CreatedAt)
		assert.Equal(t, fixedTime, proposer.lastCmd.Timestamp)
	})

	t.Run("RecordSignature uses deterministic time", func(t *testing.T) {
		err := raftStore.RecordSignature(ctxDet, "host-1", 12345, "nonce-1", fixedTime.Add(time.Hour))
		require.NoError(t, err)
		assert.Equal(t, fixedTime, proposer.lastCmd.Timestamp)
	})
}

func TestSigPayload_EmptyHostIDReturnsNil(t *testing.T) {
	// Context without signature params returns nil
	assert.Nil(t, sigPayload(context.Background()))

	expTime := time.Unix(2000, 0).UTC()

	// Context with signature params but empty HostID returns nil
	ctxEmptyHost := storage.WithSignatureParams(context.Background(), storage.SignatureParams{
		HostID:    "",
		Timestamp: 1000,
		Nonce:     "nonce-empty-host",
		ExpiresAt: expTime,
	})
	assert.Nil(t, sigPayload(ctxEmptyHost), "sigPayload must return nil when HostID is empty")

	// Context with signature params and non-empty HostID returns payload
	ctxWithHost := storage.WithSignatureParams(context.Background(), storage.SignatureParams{
		HostID:    "host-valid",
		Timestamp: 1000,
		Nonce:     "nonce-valid",
		ExpiresAt: expTime,
	})
	payload := sigPayload(ctxWithHost)
	require.NotNil(t, payload)
	assert.Equal(t, "host-valid", payload.HostID)
	assert.Equal(t, int64(1000), payload.Timestamp)
	assert.Equal(t, "nonce-valid", payload.Nonce)
	assert.Equal(t, expTime, payload.ExpiresAt)
}

func TestRaftStore_CreateHost_BundlesSignaturePayload(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sqlStore, err := storage.New(ctx, dir+"/test.db")
	require.NoError(t, err)
	defer func() { _ = sqlStore.Close() }()

	proposer := &mockProposer{}
	raftStore := newRaftStore(sqlStore, proposer, "tenant-a")

	// 1. CreateHost without signature in ctx has nil signature in RaftCommand
	host1, err := raftStore.CreateHost(ctx, storage.Host{
		UniqueKey: "host-without-sig",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, host1.ID)
	assert.Equal(t, raft.CmdCreateHost, proposer.lastCmd.Type)
	assert.Nil(t, proposer.lastCmd.Signature)

	// 2. CreateHost with signature in ctx embeds signature payload in RaftCommand
	expTime := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	ctxWithSig := storage.WithSignatureParams(ctx, storage.SignatureParams{
		HostID:    "host-bootstrap",
		Timestamp: 1700000000,
		Nonce:     "nonce-create-host",
		ExpiresAt: expTime,
	})

	host2, err := raftStore.CreateHost(ctxWithSig, storage.Host{
		UniqueKey: "host-with-sig",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, host2.ID)
	assert.Equal(t, raft.CmdCreateHost, proposer.lastCmd.Type)
	require.NotNil(t, proposer.lastCmd.Signature, "signature payload must be bundled in raft command")
	assert.Equal(t, "host-bootstrap", proposer.lastCmd.Signature.HostID)
	assert.Equal(t, int64(1700000000), proposer.lastCmd.Signature.Timestamp)
	assert.Equal(t, "nonce-create-host", proposer.lastCmd.Signature.Nonce)
	assert.Equal(t, expTime, proposer.lastCmd.Signature.ExpiresAt)
}
