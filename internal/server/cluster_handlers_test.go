package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/cluster/raft"
)

// mockNonProposerNode implements ClusterManager, MembershipManager, and HTTPAddrRegistrar,
// but intentionally does NOT implement CommandProposer.
type mockNonProposerNode struct {
	isLeader          bool
	leaderAddr        string
	nodeID            string
	raftAdvertise     string
	joinedNodeID      string
	joinedAddr        string
	removedNode       string
	httpAddrs         map[string]string
	deregisteredAddrs []string
	addrByServerID    map[string]string
	serverIDByAddr    map[string]string
	addVoterFn        func(id, addr string, prevIndex uint64, timeout time.Duration) error
	removeServerFn    func(id string, prevIndex uint64, timeout time.Duration) error
	stepDownFn        func() error
	stepDownErr       error
}

func (m *mockNonProposerNode) StepDown() error {
	if m.stepDownFn != nil {
		return m.stepDownFn()
	}
	return m.stepDownErr
}

func (m *mockNonProposerNode) IsLeader() bool   { return m.isLeader }
func (m *mockNonProposerNode) LeaderAddr() string { return m.leaderAddr }
func (m *mockNonProposerNode) RaftAdvertise() string { return m.raftAdvertise }
func (m *mockNonProposerNode) NodeID() string {
	if m.nodeID != "" {
		return m.nodeID
	}
	return "mock-non-proposer-node"
}

func (m *mockNonProposerNode) AddVoter(id, addr string, prevIndex uint64, timeout time.Duration) error {
	m.joinedNodeID = id
	m.joinedAddr = addr
	if m.addVoterFn != nil {
		return m.addVoterFn(id, addr, prevIndex, timeout)
	}
	return nil
}

func (m *mockNonProposerNode) RemoveServer(id string, prevIndex uint64, timeout time.Duration) error {
	m.removedNode = id
	if m.removeServerFn != nil {
		return m.removeServerFn(id, prevIndex, timeout)
	}
	return nil
}

func (m *mockNonProposerNode) RegisterHTTPAddr(raftAddrOrID, httpAddr string) {
	if m.httpAddrs == nil {
		m.httpAddrs = make(map[string]string)
	}
	m.httpAddrs[raftAddrOrID] = httpAddr
}

func (m *mockNonProposerNode) DeregisterHTTPAddr(raftAddrOrID string) {
	m.deregisteredAddrs = append(m.deregisteredAddrs, raftAddrOrID)
	if m.httpAddrs != nil {
		delete(m.httpAddrs, raftAddrOrID)
	}
}

func (m *mockNonProposerNode) HTTPAddrFor(key string) string {
	if m.httpAddrs == nil {
		return ""
	}
	return m.httpAddrs[key]
}

func (m *mockNonProposerNode) AddrByServerID(id string) string {
	if m.addrByServerID == nil {
		return ""
	}
	return m.addrByServerID[id]
}

func (m *mockNonProposerNode) ServerIDByAddr(addr string) string {
	if m.serverIDByAddr == nil {
		return ""
	}
	return m.serverIDByAddr[addr]
}

// mockProposerNode implements ClusterManager, MembershipManager, HTTPAddrRegistrar, and CommandProposer.
type mockProposerNode struct {
	mockNonProposerNode
	proposeErr   error
	applyRespErr error
	proposedCmds []raft.RaftCommand
}

func (m *mockProposerNode) Propose(ctx context.Context, cmd raft.RaftCommand) (raft.ApplyResponse, error) {
	m.proposedCmds = append(m.proposedCmds, cmd)
	if m.proposeErr != nil || m.applyRespErr != nil {
		return raft.ApplyResponse{Error: m.applyRespErr}, m.proposeErr
	}
	// Simulate consensus commit and FSM application
	switch cmd.Type {
	case raft.CmdRegisterNodeHTTPAddr:
		var payload raft.RegisterNodeHTTPAddrPayload
		if err := json.Unmarshal(cmd.Payload, &payload); err == nil {
			if payload.Address != "" {
				m.RegisterHTTPAddr(payload.Address, payload.HTTPAddr)
			}
			if payload.ServerID != "" {
				m.RegisterHTTPAddr(payload.ServerID, payload.HTTPAddr)
			}
		}
	case raft.CmdDeregisterNodeHTTPAddr:
		var payload raft.DeregisterNodeHTTPAddrPayload
		if err := json.Unmarshal(cmd.Payload, &payload); err == nil {
			if payload.ServerID != "" {
				m.DeregisterHTTPAddr(payload.ServerID)
			}
			if payload.Address != "" {
				m.DeregisterHTTPAddr(payload.Address)
			}
		}
	}
	return raft.ApplyResponse{}, nil
}

func TestHandleClusterJoin_ProposerFailureDoesNotRegisterInMemory(t *testing.T) {
	t.Run("proposal network error does not register HTTP address in memory", func(t *testing.T) {
		app := fiber.New()
		node := &mockProposerNode{
			mockNonProposerNode: mockNonProposerNode{
				isLeader:   true,
				leaderAddr: "10.0.0.1:8080",
				nodeID:     "leader-1",
			},
			proposeErr: errors.New("raft transport failure"),
		}
		registerClusterRoutes(app, node)

		payload := `{"node_id":"node-2","address":"10.0.0.2:9090","http_address":"http://10.0.0.2:8080"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var respBody map[string]any
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)
		assert.Contains(t, respBody, "warning")
		assert.Contains(t, respBody["warning"], "failed to replicate node HTTP address registration")

		// Address must NOT be stored in memory on proposer failure
		assert.Empty(t, node.HTTPAddrFor("node-2"))
		assert.Empty(t, node.HTTPAddrFor("10.0.0.2:9090"))
		require.Len(t, node.proposedCmds, 1)
		assert.Equal(t, raft.CmdRegisterNodeHTTPAddr, node.proposedCmds[0].Type)
	})

	t.Run("state machine rejection does not register HTTP address in memory", func(t *testing.T) {
		app := fiber.New()
		node := &mockProposerNode{
			mockNonProposerNode: mockNonProposerNode{
				isLeader:   true,
				leaderAddr: "10.0.0.1:8080",
				nodeID:     "leader-1",
			},
			applyRespErr: errors.New("fsm rejected command"),
		}
		registerClusterRoutes(app, node)

		payload := `{"node_id":"node-2","address":"10.0.0.2:9090","http_address":"http://10.0.0.2:8080"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var respBody map[string]any
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)
		assert.Contains(t, respBody, "warning")
		assert.Contains(t, respBody["warning"], "node HTTP address registration rejected by state machine")

		// Address must NOT be stored in memory on state machine rejection
		assert.Empty(t, node.HTTPAddrFor("node-2"))
		assert.Empty(t, node.HTTPAddrFor("10.0.0.2:9090"))
	})
}

func TestHandleClusterJoin_FallbackForNonProposerRegistrar(t *testing.T) {
	app := fiber.New()
	node := &mockNonProposerNode{
		isLeader:   true,
		leaderAddr: "10.0.0.1:8080",
		nodeID:     "leader-1",
	}
	registerClusterRoutes(app, node)

	payload := `{"node_id":"node-2","address":"10.0.0.2:9090","http_address":"http://10.0.0.2:8080"}`
	req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var respBody map[string]any
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	require.NoError(t, err)
	assert.NotContains(t, respBody, "warning")
	assert.Equal(t, "joined", respBody["status"])

	// Fallback directly registers both address and node_id in memory
	assert.Equal(t, "http://10.0.0.2:8080", node.HTTPAddrFor("node-2"))
	assert.Equal(t, "http://10.0.0.2:8080", node.HTTPAddrFor("10.0.0.2:9090"))
}

func TestHandleClusterRemove_ProposerVsNonProposer(t *testing.T) {
	t.Run("proposer node: does not directly deregister when proposal fails", func(t *testing.T) {
		app := fiber.New()
		node := &mockProposerNode{
			mockNonProposerNode: mockNonProposerNode{
				isLeader:   true,
				leaderAddr: "10.0.0.1:8080",
				nodeID:     "leader-1",
				addrByServerID: map[string]string{
					"node-2": "10.0.0.2:9090",
				},
				httpAddrs: map[string]string{
					"node-2":        "http://10.0.0.2:8080",
					"10.0.0.2:9090": "http://10.0.0.2:8080",
				},
			},
			proposeErr: errors.New("propose failed"),
		}
		registerClusterRoutes(app, node)

		payload := `{"node_id":"node-2"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var respBody map[string]any
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)
		assert.Contains(t, respBody, "warning")
		assert.Contains(t, respBody["warning"], "failed to replicate node HTTP address deregistration")

		// Handler did NOT directly deregister; memory retains address because proposal failed
		assert.Empty(t, node.deregisteredAddrs)
		assert.Equal(t, "http://10.0.0.2:8080", node.HTTPAddrFor("node-2"))
		assert.Equal(t, "http://10.0.0.2:8080", node.HTTPAddrFor("10.0.0.2:9090"))
	})

	t.Run("proposer node: proposal succeeds and applies via consensus", func(t *testing.T) {
		app := fiber.New()
		node := &mockProposerNode{
			mockNonProposerNode: mockNonProposerNode{
				isLeader:   true,
				leaderAddr: "10.0.0.1:8080",
				nodeID:     "leader-1",
				addrByServerID: map[string]string{
					"node-2": "10.0.0.2:9090",
				},
				httpAddrs: map[string]string{
					"node-2":        "http://10.0.0.2:8080",
					"10.0.0.2:9090": "http://10.0.0.2:8080",
				},
			},
		}
		registerClusterRoutes(app, node)

		payload := `{"node_id":"node-2"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		require.Len(t, node.proposedCmds, 1)
		assert.Equal(t, raft.CmdDeregisterNodeHTTPAddr, node.proposedCmds[0].Type)

		// Committing the proposal applied the deregistration
		assert.Contains(t, node.deregisteredAddrs, "node-2")
		assert.Empty(t, node.HTTPAddrFor("node-2"))
	})

	t.Run("non-proposer node: directly deregisters from HTTPAddrRegistrar fallback", func(t *testing.T) {
		app := fiber.New()
		node := &mockNonProposerNode{
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "leader-1",
			addrByServerID: map[string]string{
				"node-2": "10.0.0.2:9090",
			},
			httpAddrs: map[string]string{
				"node-2":        "http://10.0.0.2:8080",
				"10.0.0.2:9090": "http://10.0.0.2:8080",
			},
		}
		registerClusterRoutes(app, node)

		payload := `{"node_id":"node-2"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var respBody map[string]any
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)
		assert.NotContains(t, respBody, "warning")

		// Fallback path directly deregistered both node-2 and its raft address
		assert.Contains(t, node.deregisteredAddrs, "node-2")
		assert.Contains(t, node.deregisteredAddrs, "10.0.0.2:9090")
		assert.Empty(t, node.HTTPAddrFor("node-2"))
		assert.Empty(t, node.HTTPAddrFor("10.0.0.2:9090"))
	})
}

func TestHandleClusterJoin_UpdateMemberHTTPAddress(t *testing.T) {
	app := fiber.New()

	type member struct {
		id   string
		addr string
	}
	var existing *member

	node := &mockProposerNode{
		mockNonProposerNode: mockNonProposerNode{
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "leader-1",
		},
	}
	node.addVoterFn = func(id, addr string, prevIndex uint64, timeout time.Duration) error {
		if existing == nil {
			existing = &member{id: id, addr: addr}
			return nil
		}
		// Idempotent success when existing matches both ID and address
		if existing.id == id && existing.addr == addr {
			return nil
		}
		// Membership conflict when ID or address clashes
		return errors.New("a node with that id or address already exists")
	}

	registerClusterRoutes(app, node)

	// 1. Initial join with original HTTP address
	joinPayload1 := `{"node_id":"node-2","address":"10.0.0.2:9090","http_address":"http://10.0.0.2:8080"}`
	req1 := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(joinPayload1))
	req1.Header.Set("Content-Type", "application/json")

	resp1, err := app.Test(req1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	assert.Equal(t, "http://10.0.0.2:8080", node.HTTPAddrFor("node-2"))
	assert.Equal(t, "http://10.0.0.2:8080", node.HTTPAddrFor("10.0.0.2:9090"))
	require.Len(t, node.proposedCmds, 1)

	// 2. Subsequent join updating HTTP address for the same node_id and address
	joinPayload2 := `{"node_id":"node-2","address":"10.0.0.2:9090","http_address":"http://10.0.0.2:8085"}`
	req2 := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(joinPayload2))
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := app.Test(req2)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	assert.Equal(t, "http://10.0.0.2:8085", node.HTTPAddrFor("node-2"))
	assert.Equal(t, "http://10.0.0.2:8085", node.HTTPAddrFor("10.0.0.2:9090"))
	require.Len(t, node.proposedCmds, 2)

	// 3. Join with conflicting address returns 409 Conflict
	joinPayloadConflict := `{"node_id":"node-2","address":"10.0.0.3:9090","http_address":"http://10.0.0.3:8085"}`
	req3 := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(joinPayloadConflict))
	req3.Header.Set("Content-Type", "application/json")

	resp3, err := app.Test(req3)
	require.NoError(t, err)
	assert.Equal(t, http.StatusConflict, resp3.StatusCode)
}

func TestHandleClusterRemove_RejectLeaderRemoval(t *testing.T) {
	t.Run("reject removal by active leader node ID", func(t *testing.T) {
		app := fiber.New()
		node := &mockNonProposerNode{
			isLeader:      true,
			leaderAddr:    "10.0.0.1:8080",
			nodeID:        "leader-1",
			raftAdvertise: "10.0.0.1:8080",
		}
		registerClusterRoutes(app, node)

		payload := `{"node_id":"leader-1"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "cannot remove active cluster leader; step down leadership via /api/v1/cluster/step-down or stop the node to elect a new leader before removal")
	})

	t.Run("reject removal by active leader address matching LeaderAddr", func(t *testing.T) {
		app := fiber.New()
		node := &mockNonProposerNode{
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "leader-1",
		}
		registerClusterRoutes(app, node)

		payload := `{"node_id":"10.0.0.1:8080"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "cannot remove active cluster leader; step down leadership via /api/v1/cluster/step-down or stop the node to elect a new leader before removal")
	})

	t.Run("reject removal by active leader advertise address", func(t *testing.T) {
		app := fiber.New()
		node := &mockNonProposerNode{
			isLeader:      true,
			leaderAddr:    "10.0.0.1:8080",
			nodeID:        "leader-1",
			raftAdvertise: "adv.leader.internal:8080",
		}
		registerClusterRoutes(app, node)

		payload := `{"node_id":"adv.leader.internal:8080"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "cannot remove active cluster leader; step down leadership via /api/v1/cluster/step-down or stop the node to elect a new leader before removal")
	})

	t.Run("reject removal when RemoveServer returns leader removal error", func(t *testing.T) {
		app := fiber.New()
		node := &mockNonProposerNode{
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "leader-1",
			removeServerFn: func(id string, prevIndex uint64, timeout time.Duration) error {
				return errors.New("cannot remove active cluster leader; step down leadership via /api/v1/cluster/step-down or stop the node to elect a new leader before removal")
			},
		}
		registerClusterRoutes(app, node)

		payload := `{"node_id":"some-other-alias"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "cannot remove active cluster leader; step down leadership via /api/v1/cluster/step-down or stop the node to elect a new leader before removal")
	})
}

// minimalNonStepDownerNode implements ClusterManager but not LeaderStepDowner.
type minimalNonStepDownerNode struct {
	isLeader   bool
	leaderAddr string
}

func (m *minimalNonStepDownerNode) IsLeader() bool   { return m.isLeader }
func (m *minimalNonStepDownerNode) LeaderAddr() string { return m.leaderAddr }

func TestHandleClusterStepDown(t *testing.T) {
	t.Run("leader node successfully initiates step-down", func(t *testing.T) {
		app := fiber.New()
		stepDownCalled := false
		node := &mockNonProposerNode{
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "leader-1",
			stepDownFn: func() error {
				stepDownCalled = true
				return nil
			},
		}
		registerClusterRoutes(app, node)

		req := httptest.NewRequest("POST", "/api/v1/cluster/step-down", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body map[string]string
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)
		assert.Equal(t, "ok", body["status"])
		assert.Equal(t, "leadership transfer initiated", body["message"])
		assert.True(t, stepDownCalled)
	})

	t.Run("follower node returns 503 Service Unavailable", func(t *testing.T) {
		app := fiber.New()
		node := &mockNonProposerNode{
			isLeader:   false,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "follower-1",
		}
		registerClusterRoutes(app, node)

		req := httptest.NewRequest("POST", "/api/v1/cluster/step-down", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Equal(t, "1", resp.Header.Get("Retry-After"))

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "node is not cluster leader")
	})

	t.Run("nil cluster manager returns 503 Service Unavailable", func(t *testing.T) {
		app := fiber.New()
		registerClusterRoutes(app, nil)

		req := httptest.NewRequest("POST", "/api/v1/cluster/step-down", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Equal(t, "1", resp.Header.Get("Retry-After"))
	})

	t.Run("node not implementing LeaderStepDowner returns 500", func(t *testing.T) {
		app := fiber.New()
		node := &minimalNonStepDownerNode{
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
		}
		registerClusterRoutes(app, node)

		req := httptest.NewRequest("POST", "/api/v1/cluster/step-down", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "node does not support leadership step-down")
	})

	t.Run("step down error returns 500", func(t *testing.T) {
		app := fiber.New()
		node := &mockNonProposerNode{
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "leader-1",
			stepDownErr: errors.New("simulated leadership transfer failure"),
		}
		registerClusterRoutes(app, node)

		req := httptest.NewRequest("POST", "/api/v1/cluster/step-down", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "simulated leadership transfer failure")
	})

	t.Run("cluster admin auth middleware protects step-down", func(t *testing.T) {
		app := fiber.New()
		secret := "admin-cluster-secret"
		registerClusterAdminAuth(app, secret)

		node := &mockNonProposerNode{
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "leader-1",
		}
		registerClusterRoutes(app, node)

		// 1. Missing secret -> 401 Unauthorized
		reqNoAuth := httptest.NewRequest("POST", "/api/v1/cluster/step-down", nil)
		respNoAuth, err := app.Test(reqNoAuth)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, respNoAuth.StatusCode)

		// 2. Wrong secret -> 401 Unauthorized
		reqWrongAuth := httptest.NewRequest("POST", "/api/v1/cluster/step-down", nil)
		reqWrongAuth.Header.Set("X-Grantory-Cluster-Secret", "wrong-secret")
		respWrongAuth, err := app.Test(reqWrongAuth)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, respWrongAuth.StatusCode)

		// 3. Valid secret in X-Grantory-Cluster-Secret -> 200 OK
		reqSecret := httptest.NewRequest("POST", "/api/v1/cluster/step-down", nil)
		reqSecret.Header.Set("X-Grantory-Cluster-Secret", secret)
		respSecret, err := app.Test(reqSecret)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, respSecret.StatusCode)

		// 4. Valid secret in Bearer Authorization header -> 200 OK
		reqBearer := httptest.NewRequest("POST", "/api/v1/cluster/step-down", nil)
		reqBearer.Header.Set("Authorization", "Bearer "+secret)
		respBearer, err := app.Test(reqBearer)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, respBearer.StatusCode)
	})
}

type mockMembersReporterNode struct {
	mockNonProposerNode
	servers []raft.ServerInfo
}

func (m *mockMembersReporterNode) ClusterServers() []raft.ServerInfo {
	return m.servers
}

func TestHandleClusterStatus_MembersReporter(t *testing.T) {
	t.Parallel()

	t.Run("nil node returns standalone status without servers", func(t *testing.T) {
		app := fiber.New()
		registerClusterRoutes(app, nil)

		req := httptest.NewRequest("GET", "/api/v1/cluster/status", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var status ClusterStatusResponse
		err = json.NewDecoder(resp.Body).Decode(&status)
		require.NoError(t, err)
		assert.Equal(t, "standalone", status.NodeID)
		assert.Equal(t, "standalone", status.Role)
		assert.True(t, status.IsLeader)
		assert.Empty(t, status.LeaderAddr)
		assert.Nil(t, status.Servers)
	})

	t.Run("node without ClusterMembersReporter does not report servers", func(t *testing.T) {
		app := fiber.New()
		node := &mockNonProposerNode{
			nodeID:     "node-1",
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
		}
		registerClusterRoutes(app, node)

		req := httptest.NewRequest("GET", "/api/v1/cluster/status", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.NotContains(t, string(body), `"servers"`)

		var status ClusterStatusResponse
		err = json.Unmarshal(body, &status)
		require.NoError(t, err)
		assert.Equal(t, "node-1", status.NodeID)
		assert.Equal(t, "leader", status.Role)
		assert.True(t, status.IsLeader)
		assert.Equal(t, "10.0.0.1:8080", status.LeaderAddr)
		assert.Nil(t, status.Servers)
	})

	t.Run("node with ClusterMembersReporter includes servers list", func(t *testing.T) {
		app := fiber.New()
		expectedServers := []raft.ServerInfo{
			{ID: "node-1", Address: "10.0.0.1:8080", Suffrage: "voter"},
			{ID: "node-2", Address: "10.0.0.2:8080", Suffrage: "voter"},
			{ID: "node-3", Address: "10.0.0.3:8080", Suffrage: "nonvoter"},
		}
		node := &mockMembersReporterNode{
			mockNonProposerNode: mockNonProposerNode{
				nodeID:     "node-1",
				isLeader:   true,
				leaderAddr: "10.0.0.1:8080",
			},
			servers: expectedServers,
		}
		registerClusterRoutes(app, node)

		req := httptest.NewRequest("GET", "/api/v1/cluster/status", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), `"servers"`)

		var status ClusterStatusResponse
		err = json.Unmarshal(body, &status)
		require.NoError(t, err)
		assert.Equal(t, "node-1", status.NodeID)
		assert.Equal(t, "leader", status.Role)
		assert.True(t, status.IsLeader)
		assert.Equal(t, "10.0.0.1:8080", status.LeaderAddr)
		assert.Equal(t, expectedServers, status.Servers)
	})
}
