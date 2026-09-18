package server

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/cluster/raft"
)

type mockClusterState struct {
	isLeader   bool
	leaderAddr string
	nodeID     string
	role       string
	barrierErr error
	joinErr    error
	removeErr  error
	stepDownErr error
	stepDownCalled bool

	joinedNodeID   string
	joinedAddr     string
	removedNode    string
	isTLS          bool
	httpAddrs      map[string]string
	hopSecret      [32]byte
	proposedCmds   []raft.RaftCommand
	proposeErr     error
	applyRespErr   error
	leaderHTTPAddr *string
	addrByServerID    map[string]string
	serverIDByAddr    map[string]string
	callOrder         []string
	deregisteredAddrs []string
}

func (m *mockClusterState) AddrByServerID(id string) string {
	if m.addrByServerID == nil {
		return ""
	}
	return m.addrByServerID[id]
}

func (m *mockClusterState) ServerIDByAddr(addr string) string {
	if m.serverIDByAddr == nil {
		return ""
	}
	return m.serverIDByAddr[addr]
}

func (m *mockClusterState) HopSecret() [32]byte {
	if m.hopSecret == ([32]byte{}) {
		if _, err := cryptorand.Read(m.hopSecret[:]); err != nil {
			panic(err)
		}
	}
	return m.hopSecret
}

func (m *mockClusterState) RegisterHTTPAddr(raftAddrOrID, httpAddr string) {
	if m.httpAddrs == nil {
		m.httpAddrs = make(map[string]string)
	}
	m.httpAddrs[raftAddrOrID] = httpAddr
}

func (m *mockClusterState) DeregisterHTTPAddr(raftAddrOrID string) {
	m.deregisteredAddrs = append(m.deregisteredAddrs, raftAddrOrID)
	if m.httpAddrs != nil {
		delete(m.httpAddrs, raftAddrOrID)
	}
}

func (m *mockClusterState) HTTPAddrFor(key string) string {
	if m.httpAddrs == nil {
		return ""
	}
	return m.httpAddrs[key]
}

func (m *mockClusterState) IsLeader() bool {
	return m.isLeader
}

func (m *mockClusterState) LeaderAddr() string {
	return m.leaderAddr
}

func (m *mockClusterState) LeaderHTTPAddr() string {
	if m.leaderHTTPAddr != nil {
		return *m.leaderHTTPAddr
	}
	return m.leaderAddr
}

func (m *mockClusterState) IsTLS() bool {
	return m.isTLS
}

func (m *mockClusterState) NodeID() string {
	if m.nodeID != "" {
		return m.nodeID
	}
	return "mock-node-1"
}

func (m *mockClusterState) Role() string {
	if m.role != "" {
		return m.role
	}
	if m.isLeader {
		return "leader"
	}
	return "follower"
}

func (m *mockClusterState) Barrier(ctx context.Context) error {
	return m.barrierErr
}

func (m *mockClusterState) AddVoter(id string, addr string, prevIndex uint64, timeout time.Duration) error {
	m.joinedNodeID = id
	m.joinedAddr = addr
	return m.joinErr
}

func (m *mockClusterState) RemoveServer(id string, prevIndex uint64, timeout time.Duration) error {
	m.removedNode = id
	m.callOrder = append(m.callOrder, "RemoveServer")
	if m.addrByServerID != nil {
		delete(m.addrByServerID, id)
	}
	return m.removeErr
}

func (m *mockClusterState) StepDown() error {
	m.stepDownCalled = true
	m.callOrder = append(m.callOrder, "StepDown")
	return m.stepDownErr
}

func (m *mockClusterState) Propose(ctx context.Context, cmd raft.RaftCommand) (raft.ApplyResponse, error) {
	m.proposedCmds = append(m.proposedCmds, cmd)
	m.callOrder = append(m.callOrder, "Propose:"+string(cmd.Type))
	if m.proposeErr != nil || m.applyRespErr != nil {
		return raft.ApplyResponse{Error: m.applyRespErr}, m.proposeErr
	}
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
	return raft.ApplyResponse{Error: m.applyRespErr}, m.proposeErr
}

func TestFollowerProxyHeaderAndRedirection(t *testing.T) {
	app := fiber.New()
	mock := &mockClusterState{isLeader: false, leaderAddr: "127.0.0.1:9090"}

	app.Use(clusterRoutingMiddleware(mock))
	app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// When not leader and leader is unreachable in unit test, verify 503 or proxy attempt
	req := httptest.NewRequest("POST", "/api/v1/requests", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	// Proxy to non-existent port should return bad gateway or service unavailable
	assert.Contains(t, []int{http.StatusBadGateway, http.StatusServiceUnavailable}, resp.StatusCode)
}

func TestFollowerProxy_EmptyLeaderHTTPAddrDoesNotFallbackToRawRaftPort(t *testing.T) {
	app := fiber.New()
	emptyHTTP := ""
	mock := &mockClusterState{
		isLeader:       false,
		leaderAddr:     "127.0.0.1:9090",
		leaderHTTPAddr: &emptyHTTP,
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("POST", "/api/v1/requests", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "1", resp.Header.Get("Retry-After"))
}


func TestFollowerProxySuccessAndHeaderPreservation(t *testing.T) {
	var receivedForwardedBy string
	var receivedForwardedSig string
	var receivedCustomHeader string
	var receivedBody []byte
	var receivedMethod string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedForwardedBy = r.Header.Get("X-Grantory-Forwarded-By")
		receivedForwardedSig = r.Header.Get("X-Grantory-Forwarded-Sig")
		receivedCustomHeader = r.Header.Get("X-Custom-Token")
		receivedMethod = r.Method
		receivedBody, _ = io.ReadAll(r.Body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"created","upstream":true}`))
	}))
	defer upstream.Close()

	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: upstream.Listener.Addr().String(),
		nodeID:     "node-follower-42",
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	body := `{"unique_key":"req-123","service":"test"}`
	req := httptest.NewRequest("POST", "/api/v1/requests", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom-Token", "secret-token-abc")

	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "node-follower-42", receivedForwardedBy)
	parts := strings.Split(receivedForwardedSig, ":")
	require.Len(t, parts, 3, "forwarded sig header must have 3 parts (nodeID:ts:sig)")
	assert.Equal(t, "node-follower-42", parts[0])
	tsVal, err := strconv.ParseInt(parts[1], 10, 64)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), time.Unix(tsVal, 0), 3*time.Second)
	expectedSig := ComputeHopSignature(mock.HopSecret(), "node-follower-42", tsVal)
	assert.Equal(t, expectedSig, parts[2])
	assert.Equal(t, "secret-token-abc", receivedCustomHeader)
	assert.Equal(t, "POST", receivedMethod)
	assert.JSONEq(t, body, string(receivedBody))

	respBody, _ := io.ReadAll(resp.Body)
	assert.JSONEq(t, `{"status":"created","upstream":true}`, string(respBody))
}

func TestFollowerProxyPreservesPercentEncodingInURI(t *testing.T) {
	var receivedURI string
	var receivedRawPath string
	var receivedRawQuery string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURI = r.RequestURI
		receivedRawPath = r.URL.RawPath
		receivedRawQuery = r.URL.RawQuery

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: upstream.Listener.Addr().String(),
		nodeID:     "node-follower-42",
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Get("/*", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	rawPathAndQuery := "/api/v1/registers/foo%2Fbar?test=123"
	req := httptest.NewRequest("GET", rawPathAndQuery, nil)

	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, rawPathAndQuery, receivedURI, "percent-encoded slash %2F must not be unescaped to /")
	assert.Equal(t, "/api/v1/registers/foo%2Fbar", receivedRawPath)
	assert.Equal(t, "test=123", receivedRawQuery)
	assert.NotContains(t, receivedURI, "foo/bar", "URI path must not contain unescaped slash")
}

func TestFollowerProxyPreservesURLInQueryParameters(t *testing.T) {
	var receivedURI string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURI = r.RequestURI
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: upstream.Listener.Addr().String(),
		nodeID:     "node-follower-42",
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Get("/*", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	pathAndQuery := "/api/v1/requests?callback=https://example.com/webhook&token=123"
	req := httptest.NewRequest("GET", pathAndQuery, nil)

	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, pathAndQuery, receivedURI, "requests with URLs in query parameters must retain full path and query string")
}

func TestFollowerProxyStripsSchemeAndAuthorityFromAbsoluteURI(t *testing.T) {
	var receivedURI string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURI = r.RequestURI
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		if sim := c.Get("X-Simulate-URI"); sim != "" {
			c.Request().SetRequestURI(sim)
		}
		return c.Next()
	})

	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: upstream.Listener.Addr().String(),
		nodeID:     "node-follower-42",
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Get("/*", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	t.Run("absolute URI with path and query", func(t *testing.T) {
		receivedURI = ""
		req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
		req.Header.Set("X-Simulate-URI", "http://proxy.host:8080/api/v1/hosts?filter=active")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "/api/v1/hosts?filter=active", receivedURI, "scheme and authority must be stripped from absolute URI")
	})

	t.Run("absolute URI with path and no query", func(t *testing.T) {
		receivedURI = ""
		req := httptest.NewRequest("GET", "/api/v1/services", nil)
		req.Header.Set("X-Simulate-URI", "https://proxy.host:8443/api/v1/services")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "/api/v1/services", receivedURI, "scheme and authority must be stripped yielding /api/v1/services")
	})
}

func TestFollowerProxyLoopDetection(t *testing.T) {
	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: "127.0.0.1:9090",
		nodeID:     "node-self",
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Request already traversed this node and has valid hop signature
	now := time.Now().Unix()
	sig := ComputeHopSignature(mock.HopSecret(), "node-self", now)
	req := httptest.NewRequest("POST", "/api/v1/requests", nil)
	req.Header.Set("X-Grantory-Forwarded-By", "node-self")
	req.Header.Set("X-Grantory-Forwarded-Sig", fmt.Sprintf("node-self:%d:%s", now, sig))

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusLoopDetected, resp.StatusCode)
}

func TestFollowerProxyLoopDetectionCommaSeparated(t *testing.T) {
	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: "127.0.0.1:9090",
		nodeID:     "node-self",
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Request traversed other nodes, but includes this node in the chain with valid signature
	now := time.Now().Unix()
	sig := ComputeHopSignature(mock.HopSecret(), "node-self", now)
	req := httptest.NewRequest("POST", "/api/v1/requests", nil)
	req.Header.Set("X-Grantory-Forwarded-By", "node-a, node-self, node-b")
	req.Header.Set("X-Grantory-Forwarded-Sig", fmt.Sprintf("node-a:other-sig, node-self:%d:%s, node-b:other-sig-2", now, sig))

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusLoopDetected, resp.StatusCode)
}

func TestFollowerProxyMaxForwardHopsExceeded(t *testing.T) {
	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: "127.0.0.1:9090",
		nodeID:     "node-target",
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// 10 comma-separated hops with valid signatures triggers 508 Loop Detected
	now := time.Now().Unix()
	var sigs []string
	for i := 1; i <= 10; i++ {
		hop := fmt.Sprintf("hop%d", i)
		s := ComputeHopSignature(mock.HopSecret(), hop, now)
		sigs = append(sigs, fmt.Sprintf("%s:%d:%s", hop, now, s))
	}
	tenHops := "hop1, hop2, hop3, hop4, hop5, hop6, hop7, hop8, hop9, hop10"
	tenSigs := strings.Join(sigs, ", ")
	req := httptest.NewRequest("POST", "/api/v1/requests", nil)
	req.Header.Set("X-Grantory-Forwarded-By", tenHops)
	req.Header.Set("X-Grantory-Forwarded-Sig", tenSigs)

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusLoopDetected, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "maximum forward hops exceeded")

	// 9 hops does not trigger maximum hops exceeded (will proceed to leader proxy)
	nineHops := "hop1, hop2, hop3, hop4, hop5, hop6, hop7, hop8, hop9"
	nineSigs := strings.Join(sigs[:9], ", ")
	req9 := httptest.NewRequest("POST", "/api/v1/requests", nil)
	req9.Header.Set("X-Grantory-Forwarded-By", nineHops)
	req9.Header.Set("X-Grantory-Forwarded-Sig", nineSigs)

	resp9, err := app.Test(req9)
	require.NoError(t, err)
	assert.NotEqual(t, http.StatusLoopDetected, resp9.StatusCode)
}

func TestFollowerProxyLoopDetection_NodeIDWithColons(t *testing.T) {
	testCases := []struct {
		name   string
		nodeID string
	}{
		{
			name:   "IPv4 host:port node ID",
			nodeID: "127.0.0.1:8081",
		},
		{
			name:   "IPv6 host:port node ID",
			nodeID: "[::1]:8081",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			mock := &mockClusterState{
				isLeader:   false,
				leaderAddr: "127.0.0.1:9090",
				nodeID:     tc.nodeID,
			}

			app.Use(clusterRoutingMiddleware(mock))
			app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
				return c.SendStatus(fiber.StatusOK)
			})

			now := time.Now().Unix()
			sig := ComputeHopSignature(mock.HopSecret(), tc.nodeID, now)

			// Single hop loop detection
			req := httptest.NewRequest("POST", "/api/v1/requests", nil)
			req.Header.Set("X-Grantory-Forwarded-By", tc.nodeID)
			req.Header.Set("X-Grantory-Forwarded-Sig", fmt.Sprintf("%s:%d:%s", tc.nodeID, now, sig))

			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusLoopDetected, resp.StatusCode)

			// Multi-hop comma-separated loop detection
			reqMulti := httptest.NewRequest("POST", "/api/v1/requests", nil)
			reqMulti.Header.Set("X-Grantory-Forwarded-By", "other-node:8080, "+tc.nodeID+", another-node")
			reqMulti.Header.Set("X-Grantory-Forwarded-Sig", fmt.Sprintf("other-node:8080:other-sig, %s:%d:%s, another-node:sig3", tc.nodeID, now, sig))

			respMulti, err := app.Test(reqMulti)
			require.NoError(t, err)
			assert.Equal(t, http.StatusLoopDetected, respMulti.StatusCode)
		})
	}
}

func TestFollowerProxySpoofedHeaderDoesNotTriggerLoopDetection(t *testing.T) {
	t.Run("spoofed header without signature", func(t *testing.T) {
		upstreamCalled := false
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalled = true
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "node-self",
		}

		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		req := httptest.NewRequest("POST", "/api/v1/requests", nil)
		req.Header.Set("X-Grantory-Forwarded-By", "node-self")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.NotEqual(t, http.StatusLoopDetected, resp.StatusCode)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, upstreamCalled)
	})

	t.Run("spoofed header with invalid signature", func(t *testing.T) {
		upstreamCalled := false
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalled = true
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "node-self",
		}

		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		req := httptest.NewRequest("POST", "/api/v1/requests", nil)
		req.Header.Set("X-Grantory-Forwarded-By", "node-self")
		req.Header.Set("X-Grantory-Forwarded-Sig", "node-self:bogus-fake-signature")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.NotEqual(t, http.StatusLoopDetected, resp.StatusCode)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, upstreamCalled)
	})
}

func TestFollowerProxy_DoSImmunityAndSignatureValidation(t *testing.T) {
	t.Run("10 dummy hops with missing signature is sanitized and proxied to leader", func(t *testing.T) {
		var receivedForwardedBy string
		var receivedForwardedSig string
		upstreamCalled := false
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalled = true
			receivedForwardedBy = r.Header.Get("X-Grantory-Forwarded-By")
			receivedForwardedSig = r.Header.Get("X-Grantory-Forwarded-Sig")
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "node-follower-1",
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		tenDummyHops := "hop1, hop2, hop3, hop4, hop5, hop6, hop7, hop8, hop9, hop10"
		req := httptest.NewRequest("POST", "/api/v1/requests", nil)
		req.Header.Set("X-Grantory-Forwarded-By", tenDummyHops)
		// No X-Grantory-Forwarded-Sig header

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "must proxy to leader without 508 Loop Detected")
		assert.True(t, upstreamCalled, "upstream leader must be called")
		assert.Equal(t, tenDummyHops+", node-follower-1", receivedForwardedBy, "foreign hops preserved, follower appended")
		assert.NotEmpty(t, receivedForwardedSig, "follower must add its own signature")
	})

	t.Run("10 dummy hops with expired signatures is sanitized and proxied to leader", func(t *testing.T) {
		var receivedForwardedBy string
		var receivedForwardedSig string
		upstreamCalled := false
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalled = true
			receivedForwardedBy = r.Header.Get("X-Grantory-Forwarded-By")
			receivedForwardedSig = r.Header.Get("X-Grantory-Forwarded-Sig")
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "node-follower-1",
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		now := time.Now().Unix()
		expiredTS := now - 50 // 50s old (> 45s ForwardHopTTL)
		tenDummyHops := "hop1, hop2, hop3, hop4, hop5, hop6, hop7, hop8, hop9, hop10"
		expiredSigs := fmt.Sprintf("hop1:%d:s1, hop2:%d:s2, hop3:%d:s3, hop4:%d:s4, hop5:%d:s5, hop6:%d:s6, hop7:%d:s7, hop8:%d:s8, hop9:%d:s9, hop10:%d:s10",
			expiredTS, expiredTS, expiredTS, expiredTS, expiredTS, expiredTS, expiredTS, expiredTS, expiredTS, expiredTS)

		req := httptest.NewRequest("POST", "/api/v1/requests", nil)
		req.Header.Set("X-Grantory-Forwarded-By", tenDummyHops)
		req.Header.Set("X-Grantory-Forwarded-Sig", expiredSigs)

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "must proxy to leader without 508 Loop Detected")
		assert.True(t, upstreamCalled, "upstream leader must be called")
		assert.Equal(t, tenDummyHops+", node-follower-1", receivedForwardedBy, "foreign hops preserved, follower appended")
		assert.NotEmpty(t, receivedForwardedSig, "follower must add fresh signature")
	})

	t.Run("10 dummy hops with spoofed signatures is sanitized and proxied to leader", func(t *testing.T) {
		var receivedForwardedBy string
		var receivedForwardedSig string
		upstreamCalled := false
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalled = true
			receivedForwardedBy = r.Header.Get("X-Grantory-Forwarded-By")
			receivedForwardedSig = r.Header.Get("X-Grantory-Forwarded-Sig")
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "node-follower-1",
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		tenDummyHops := "hop1, hop2, hop3, hop4, hop5, hop6, hop7, hop8, hop9, hop10"
		spoofedSigs := "invalid-sig-1, invalid-sig-2, invalid-sig-3"

		req := httptest.NewRequest("POST", "/api/v1/requests", nil)
		req.Header.Set("X-Grantory-Forwarded-By", tenDummyHops)
		req.Header.Set("X-Grantory-Forwarded-Sig", spoofedSigs)

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "must proxy to leader without 508 Loop Detected")
		assert.True(t, upstreamCalled, "upstream leader must be called")
		assert.Equal(t, tenDummyHops+", node-follower-1", receivedForwardedBy, "foreign hops preserved, follower appended")
		assert.NotEmpty(t, receivedForwardedSig, "follower must add fresh signature")
	})

	t.Run("real loop with valid signatures returns 508 Loop Detected", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: "127.0.0.1:9090",
			nodeID:     "node-follower-1",
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		// 1. Max hops loop: 10 hops with 10 valid signatures
		now := time.Now().Unix()
		var sigs []string
		for i := 1; i <= 10; i++ {
			hop := fmt.Sprintf("hop%d", i)
			s := ComputeHopSignature(mock.HopSecret(), hop, now)
			sigs = append(sigs, fmt.Sprintf("%s:%d:%s", hop, now, s))
		}
		tenHops := "hop1, hop2, hop3, hop4, hop5, hop6, hop7, hop8, hop9, hop10"
		tenSigs := strings.Join(sigs, ", ")

		req := httptest.NewRequest("POST", "/api/v1/requests", nil)
		req.Header.Set("X-Grantory-Forwarded-By", tenHops)
		req.Header.Set("X-Grantory-Forwarded-Sig", tenSigs)

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusLoopDetected, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "maximum forward hops exceeded")

		// 2. Node self loop with valid cryptographic signature
		sig := ComputeHopSignature(mock.HopSecret(), "node-follower-1", now)
		reqSelf := httptest.NewRequest("POST", "/api/v1/requests", nil)
		reqSelf.Header.Set("X-Grantory-Forwarded-By", "node-follower-1")
		reqSelf.Header.Set("X-Grantory-Forwarded-Sig", fmt.Sprintf("node-follower-1:%d:%s", now, sig))

		respSelf, err := app.Test(reqSelf)
		require.NoError(t, err)
		assert.Equal(t, http.StatusLoopDetected, respSelf.StatusCode)
		bodySelf, err := io.ReadAll(respSelf.Body)
		require.NoError(t, err)
		assert.Contains(t, string(bodySelf), "forwarding loop detected")
	})
}

func TestFollowerProxyHopSignatureAntiReplay(t *testing.T) {
	t.Run("hop signature generation", func(t *testing.T) {
		var secret [32]byte
		copy(secret[:], "test-secret-32-bytes-long-key!!")
		ts := int64(1773298912)
		sig := ComputeHopSignature(secret, "node-1", ts)
		require.NotEmpty(t, sig)
		// deterministic verification
		mac := hmac.New(sha256.New, secret[:])
		mac.Write([]byte("node-1:1773298912"))
		expected := hex.EncodeToString(mac.Sum(nil))
		assert.Equal(t, expected, sig)
	})

	t.Run("unexpired hop signature within 10s triggers 508 Loop Detected", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: "127.0.0.1:9090",
			nodeID:     "node-self",
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		now := time.Now().Unix()
		sig := ComputeHopSignature(mock.HopSecret(), "node-self", now-5) // 5s old: valid and within 10s
		req := httptest.NewRequest("POST", "/api/v1/requests", nil)
		req.Header.Set("X-Grantory-Forwarded-By", "node-self")
		req.Header.Set("X-Grantory-Forwarded-Sig", fmt.Sprintf("node-self:%d:%s", now-5, sig))

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusLoopDetected, resp.StatusCode)
	})

	t.Run("looping request with valid hop signature older than 45s still triggers 508 Loop Detected", func(t *testing.T) {
		upstreamCalled := false
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalled = true
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "node-self",
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		now := time.Now().Unix()
		expiredTS := now - 50 // 50 seconds old (>45s ForwardHopTTL)
		sig := ComputeHopSignature(mock.HopSecret(), "node-self", expiredTS)
		req := httptest.NewRequest("POST", "/api/v1/requests", nil)
		req.Header.Set("X-Grantory-Forwarded-By", "node-self")
		req.Header.Set("X-Grantory-Forwarded-Sig", fmt.Sprintf("node-self:%d:%s", expiredTS, sig))

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusLoopDetected, resp.StatusCode)
		assert.False(t, upstreamCalled)
	})

	t.Run("future hop signature with valid HMAC triggers 508 Loop Detected", func(t *testing.T) {
		upstreamCalled := false
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalled = true
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "node-self",
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		now := time.Now().Unix()
		futureTS := now + 10 // 10 seconds into future (>5s)
		sig := ComputeHopSignature(mock.HopSecret(), "node-self", futureTS)
		req := httptest.NewRequest("POST", "/api/v1/requests", nil)
		req.Header.Set("X-Grantory-Forwarded-By", "node-self")
		req.Header.Set("X-Grantory-Forwarded-Sig", fmt.Sprintf("node-self:%d:%s", futureTS, sig))

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusLoopDetected, resp.StatusCode)
		assert.False(t, upstreamCalled)
	})

	t.Run("legacy hop signature without timestamp still triggers 508 Loop Detected", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: "127.0.0.1:9090",
			nodeID:     "node-self",
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		// Legacy signature computed without timestamp
		secret := mock.HopSecret()
		mac := hmac.New(sha256.New, secret[:])
		mac.Write([]byte("node-self"))
		legacySig := hex.EncodeToString(mac.Sum(nil))

		req := httptest.NewRequest("POST", "/api/v1/requests", nil)
		req.Header.Set("X-Grantory-Forwarded-By", "node-self")
		req.Header.Set("X-Grantory-Forwarded-Sig", "node-self:"+legacySig)

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusLoopDetected, resp.StatusCode)
	})
}

func TestFollowerProxy_ForwardHopTTLAndForeignHopValidation(t *testing.T) {
	t.Run("forged foreign hop signatures do not cause 508 Loop Detected", func(t *testing.T) {
		upstreamCalled := false
		var receivedForwardedBy string
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalled = true
			receivedForwardedBy = r.Header.Get(HeaderForwardedBy)
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "follower-node",
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/data", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		now := time.Now().Unix()
		var hops []string
		var forgedSigs []string
		for i := 1; i <= 10; i++ {
			h := fmt.Sprintf("n%d", i)
			hops = append(hops, h)
			forgedSigs = append(forgedSigs, fmt.Sprintf("%s:%d:dummy", h, now))
		}

		req := httptest.NewRequest("POST", "/api/v1/data", nil)
		req.Header.Set(HeaderForwardedBy, strings.Join(hops, ", "))
		req.Header.Set(HeaderForwardedSig, strings.Join(forgedSigs, ", "))

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "forged foreign signatures must not cause 508 Loop Detected")
		assert.True(t, upstreamCalled, "upstream leader must be called")
		assert.Equal(t, strings.Join(hops, ", ")+", follower-node", receivedForwardedBy, "foreign hops preserved, follower appended")
	})

	t.Run("hop signatures at 25s and 40s remain valid under ForwardHopTTL", func(t *testing.T) {
		for _, age := range []int64{25, 40} {
			t.Run(fmt.Sprintf("age_%ds", age), func(t *testing.T) {
				app := fiber.New()
				mock := &mockClusterState{
					isLeader:   false,
					leaderAddr: "127.0.0.1:9090",
					nodeID:     "self-node",
				}
				app.Use(clusterRoutingMiddleware(mock))
				app.Post("/api/v1/data", func(c *fiber.Ctx) error {
					return c.SendStatus(fiber.StatusOK)
				})

				now := time.Now().Unix()
				ts := now - age
				sig := ComputeHopSignature(mock.HopSecret(), "self-node", ts)

				req := httptest.NewRequest("POST", "/api/v1/data", nil)
				req.Header.Set(HeaderForwardedBy, "self-node")
				req.Header.Set(HeaderForwardedSig, fmt.Sprintf("self-node:%d:%s", ts, sig))

				resp, err := app.Test(req)
				require.NoError(t, err)
				assert.Equal(t, http.StatusLoopDetected, resp.StatusCode, "signature within ForwardHopTTL (45s) must be detected as loop")
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Contains(t, string(body), "forwarding loop detected")
			})
		}
	})

	t.Run("foreign hop signatures older than 45s are treated as expired and do not trigger max hops", func(t *testing.T) {
		var sharedSecret [32]byte
		copy(sharedSecret[:], "cluster-shared-secret-key-12345!")

		upstreamCalled := false
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalled = true
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "follower-node",
			hopSecret:  sharedSecret,
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/data", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		now := time.Now().Unix()
		expiredTS := now - 50 // > 45s ForwardHopTTL
		var hops []string
		var expiredSigs []string
		for i := 1; i <= 10; i++ {
			nodeName := fmt.Sprintf("foreign-node-%d", i)
			hops = append(hops, nodeName)
			sig := ComputeHopSignature(sharedSecret, nodeName, expiredTS)
			expiredSigs = append(expiredSigs, fmt.Sprintf("%s:%d:%s", nodeName, expiredTS, sig))
		}

		req := httptest.NewRequest("POST", "/api/v1/data", nil)
		req.Header.Set(HeaderForwardedBy, strings.Join(hops, ", "))
		req.Header.Set(HeaderForwardedSig, strings.Join(expiredSigs, ", "))

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "expired foreign signatures (>45s) must not count towards max hops")
		assert.True(t, upstreamCalled, "upstream leader must be reached")
	})

	t.Run("self hop signatures older than 45s still trigger 508 Loop Detected without cycle reset", func(t *testing.T) {
		upstreamCalled := false
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalled = true
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "self-node",
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/data", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		now := time.Now().Unix()
		expiredTS := now - 46 // 46s old (> 45s ForwardHopTTL)
		sig := ComputeHopSignature(mock.HopSecret(), "self-node", expiredTS)

		req := httptest.NewRequest("POST", "/api/v1/data", nil)
		req.Header.Set(HeaderForwardedBy, "self-node")
		req.Header.Set(HeaderForwardedSig, fmt.Sprintf("self-node:%d:%s", expiredTS, sig))

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusLoopDetected, resp.StatusCode, "self hop signature older than 45s must trigger loop detection to prevent cycle reset")
		assert.False(t, upstreamCalled, "upstream leader must not be reached")
	})

	t.Run("when nodes share a cluster secret, foreign hops with authentic signatures are recognized", func(t *testing.T) {
		var sharedSecret [32]byte
		copy(sharedSecret[:], "cluster-shared-secret-key-12345!")

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: "127.0.0.1:9090",
			nodeID:     "follower-b",
			hopSecret:  sharedSecret,
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/data", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		now := time.Now().Unix()
		var hops []string
		var validSigs []string
		for i := 1; i <= 10; i++ {
			nodeName := fmt.Sprintf("node-%d", i)
			hops = append(hops, nodeName)
			sig := ComputeHopSignature(sharedSecret, nodeName, now)
			validSigs = append(validSigs, fmt.Sprintf("%s:%d:%s", nodeName, now, sig))
		}

		req := httptest.NewRequest("POST", "/api/v1/data", nil)
		req.Header.Set(HeaderForwardedBy, strings.Join(hops, ", "))
		req.Header.Set(HeaderForwardedSig, strings.Join(validSigs, ", "))

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusLoopDetected, resp.StatusCode, "authentic foreign signatures sharing cluster secret must trigger max hops")
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "maximum forward hops exceeded")
	})
}

func TestFollowerProxyNoFalsePositiveLoopDetection(t *testing.T) {
	var receivedForwardedBy string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedForwardedBy = r.Header.Get("X-Grantory-Forwarded-By")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: upstream.Listener.Addr().String(),
		nodeID:     "node-1",
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// "node-10" and "node-1-extra" should NOT trigger false positive for "node-1"
	now := time.Now().Unix()
	sig10 := ComputeHopSignature(mock.HopSecret(), "node-10", now)
	sigExtra := ComputeHopSignature(mock.HopSecret(), "node-1-extra", now)
	req := httptest.NewRequest("POST", "/api/v1/requests", nil)
	req.Header.Set("X-Grantory-Forwarded-By", "node-10, node-1-extra")
	req.Header.Set("X-Grantory-Forwarded-Sig", fmt.Sprintf("node-10:%d:%s, node-1-extra:%d:%s", now, sig10, now, sigExtra))

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "node-10, node-1-extra, node-1", receivedForwardedBy)
}

func TestFollowerProxyChainedHeaderAppending(t *testing.T) {
	var receivedForwardedBy string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedForwardedBy = r.Header.Get("X-Grantory-Forwarded-By")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: upstream.Listener.Addr().String(),
		nodeID:     "node-2",
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	now := time.Now().Unix()
	sig1 := ComputeHopSignature(mock.HopSecret(), "node-1", now)
	req := httptest.NewRequest("POST", "/api/v1/requests", nil)
	req.Header.Set("X-Grantory-Forwarded-By", "node-1")
	req.Header.Set("X-Grantory-Forwarded-Sig", fmt.Sprintf("node-1:%d:%s", now, sig1))

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "node-1, node-2", receivedForwardedBy)
}

func TestFollowerProxyTLSScheme(t *testing.T) {
	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: "127.0.0.1:9090",
		isTLS:      true,
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Get("/api/v1/requests", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/v1/requests", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	// Proxy attempting to connect to non-existent TLS port should fail with BadGateway or ServiceUnavailable
	assert.Contains(t, []int{http.StatusBadGateway, http.StatusServiceUnavailable}, resp.StatusCode)
}

func TestFollowerNoLeaderElected(t *testing.T) {
	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: "", // no leader elected
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("POST", "/api/v1/requests", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "1", resp.Header.Get("Retry-After"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "no leader currently elected", string(body))
}

func TestFollowerLeaderHTTPUnavailable(t *testing.T) {
	app := fiber.New()
	emptyHTTP := ""
	mock := &mockClusterState{
		isLeader:       false,
		leaderAddr:     "127.0.0.1:9090", // Raft leader elected
		leaderHTTPAddr: &emptyHTTP,       // HTTP address not yet available
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("POST", "/api/v1/requests", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "1", resp.Header.Get("Retry-After"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "leader HTTP address unavailable", string(body))
}

func TestLeaderLinearizableBarrierCheck(t *testing.T) {
	t.Run("GET barrier succeeds", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			barrierErr: nil,
		}

		app.Use(clusterRoutingMiddleware(mock))
		app.Get("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendString("read data")
		})

		req := httptest.NewRequest("GET", "/api/v1/requests", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("GET barrier fails (lost quorum)", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			barrierErr: errors.New("raft: quorum lost"),
		}

		app.Use(clusterRoutingMiddleware(mock))
		app.Get("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendString("should not reach")
		})

		req := httptest.NewRequest("GET", "/api/v1/requests", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Equal(t, "1", resp.Header.Get("Retry-After"))
	})

	t.Run("GET barrier fails (client context canceled)", func(t *testing.T) {
		hook := test.NewGlobal()
		t.Cleanup(hook.Reset)

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			barrierErr: context.Canceled,
		}

		app.Use(clusterRoutingMiddleware(mock))
		app.Get("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendString("should not reach")
		})

		req := httptest.NewRequest("GET", "/api/v1/requests", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusRequestTimeout, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Retry-After"))
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "client request cancelled or timed out")
		assert.NotContains(t, string(body), "cluster quorum lost")

		for _, entry := range hook.AllEntries() {
			assert.NotContains(t, entry.Message, "cluster quorum lost")
		}
	})

	t.Run("GET barrier fails (client deadline exceeded)", func(t *testing.T) {
		hook := test.NewGlobal()
		t.Cleanup(hook.Reset)

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			barrierErr: context.DeadlineExceeded,
		}

		app.Use(clusterRoutingMiddleware(mock))
		app.Get("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendString("should not reach")
		})

		req := httptest.NewRequest("GET", "/api/v1/requests", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusRequestTimeout, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Retry-After"))
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "client request cancelled or timed out")
		assert.NotContains(t, string(body), "cluster quorum lost")

		for _, entry := range hook.AllEntries() {
			assert.NotContains(t, entry.Message, "cluster quorum lost")
		}
	})

	t.Run("POST write bypasses linearizable read barrier", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			barrierErr: errors.New("barrier would fail if called"),
		}

		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusCreated)
		})

		req := httptest.NewRequest("POST", "/api/v1/requests", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
	})
}

func TestStandalonePassThrough(t *testing.T) {
	app := fiber.New()
	app.Use(clusterRoutingMiddleware(nil)) // Standalone single-node mode

	app.Get("/api/v1/requests", func(c *fiber.Ctx) error {
		return c.SendString("standalone read")
	})
	app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
		return c.SendString("standalone write")
	})

	reqGet := httptest.NewRequest("GET", "/api/v1/requests", nil)
	respGet, err := app.Test(reqGet)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respGet.StatusCode)

	reqPost := httptest.NewRequest("POST", "/api/v1/requests", nil)
	respPost, err := app.Test(reqPost)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respPost.StatusCode)
}

func TestClusterRoutingMiddleware_TypedNilAndUntypedNilPassThrough(t *testing.T) {
	t.Run("untyped nil node passes through", func(t *testing.T) {
		app := fiber.New()
		app.Use(clusterRoutingMiddleware(nil))
		app.Get("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendString("ok untyped nil")
		})
		req := httptest.NewRequest("GET", "/api/v1/requests", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "ok untyped nil", string(body))
	})

	t.Run("typed nil node passes through without panic or reflection in request path", func(t *testing.T) {
		var typedNil *mockClusterState
		app := fiber.New()
		require.NotPanics(t, func() {
			app.Use(clusterRoutingMiddleware(typedNil))
		})
		app.Get("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendString("ok typed nil")
		})
		app.Post("/api/v1/requests", func(c *fiber.Ctx) error {
			return c.SendString("ok typed nil write")
		})

		reqGet := httptest.NewRequest("GET", "/api/v1/requests", nil)
		respGet, err := app.Test(reqGet)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, respGet.StatusCode)
		bodyGet, err := io.ReadAll(respGet.Body)
		require.NoError(t, err)
		assert.Equal(t, "ok typed nil", string(bodyGet))

		reqPost := httptest.NewRequest("POST", "/api/v1/requests", nil)
		respPost, err := app.Test(reqPost)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, respPost.StatusCode)
		bodyPost, err := io.ReadAll(respPost.Body)
		require.NoError(t, err)
		assert.Equal(t, "ok typed nil write", string(bodyPost))
	})
}

func TestClusterManagementRoutes(t *testing.T) {
	t.Run("cluster status on leader", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "node-1",
			role:       "leader",
		}

		registerClusterRoutes(app, mock)

		req := httptest.NewRequest("GET", "/api/v1/cluster/status", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var status map[string]any
		err = json.NewDecoder(resp.Body).Decode(&status)
		require.NoError(t, err)
		assert.Equal(t, "node-1", status["node_id"])
		assert.Equal(t, "leader", status["role"])
		assert.Equal(t, true, status["is_leader"])
		assert.Equal(t, "10.0.0.1:8080", status["leader_addr"])
	})

	t.Run("cluster status in standalone mode", func(t *testing.T) {
		app := fiber.New()
		registerClusterRoutes(app, nil)

		req := httptest.NewRequest("GET", "/api/v1/cluster/status", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var status map[string]any
		err = json.NewDecoder(resp.Body).Decode(&status)
		require.NoError(t, err)
		assert.Equal(t, "standalone", status["role"])
		assert.Equal(t, true, status["is_leader"])
	})

	t.Run("cluster join on leader", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "node-1",
		}

		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-2","address":"10.0.0.2:9090"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "node-2", mock.joinedNodeID)
		assert.Equal(t, "10.0.0.2:9090", mock.joinedAddr)
	})

	t.Run("cluster join validation error", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{isLeader: true}
		registerClusterRoutes(app, mock)

		payload := `{"node_id":""}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("cluster join on follower is rejected", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "node-2",
		}

		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-3","address":"10.0.0.3:9090"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Equal(t, "1", resp.Header.Get("Retry-After"))
	})

	t.Run("cluster remove on leader", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			nodeID:     "node-1",
			addrByServerID: map[string]string{
				"node-2": "10.0.0.2:9090",
			},
			httpAddrs: map[string]string{
				"node-2":        "http://10.0.0.2:8080",
				"10.0.0.2:9090": "http://10.0.0.2:8080",
			},
		}

		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-2"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "node-2", mock.removedNode)

		// Assert in-memory registrar was immediately cleared for node ID and address
		assert.Equal(t, []string{"node-2", "10.0.0.2:9090"}, mock.deregisteredAddrs)
		assert.Empty(t, mock.HTTPAddrFor("node-2"))
		assert.Empty(t, mock.HTTPAddrFor("10.0.0.2:9090"))

		require.Len(t, mock.proposedCmds, 1)
		assert.Equal(t, raft.CmdDeregisterNodeHTTPAddr, mock.proposedCmds[0].Type)
		var deregPayload raft.DeregisterNodeHTTPAddrPayload
		err = json.Unmarshal(mock.proposedCmds[0].Payload, &deregPayload)
		require.NoError(t, err)
		assert.Equal(t, "node-2", deregPayload.ServerID)
		assert.Equal(t, "10.0.0.2:9090", deregPayload.Address)
		assert.Equal(t, []string{"RemoveServer", "Propose:" + string(raft.CmdDeregisterNodeHTTPAddr)}, mock.callOrder)
		assert.Empty(t, mock.addrByServerID["node-2"], "node-2 should be removed from addrByServerID map")
	})

	t.Run("cluster remove resolves node ID when supplied with raft address", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader: true,
			nodeID:   "leader-node",
			serverIDByAddr: map[string]string{
				"10.0.0.2:9090": "node-2",
			},
			addrByServerID: map[string]string{
				"node-2": "10.0.0.2:9090",
			},
			httpAddrs: map[string]string{
				"node-2":        "http://10.0.0.2:8080",
				"10.0.0.2:9090": "http://10.0.0.2:8080",
			},
		}

		registerClusterRoutes(app, mock)

		payload := `{"node_id":"10.0.0.2:9090"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "node-2", mock.removedNode)

		assert.Contains(t, mock.deregisteredAddrs, "node-2")
		assert.Contains(t, mock.deregisteredAddrs, "10.0.0.2:9090")

		require.Len(t, mock.proposedCmds, 1)
		assert.Equal(t, raft.CmdDeregisterNodeHTTPAddr, mock.proposedCmds[0].Type)
		var deregPayload raft.DeregisterNodeHTTPAddrPayload
		err = json.Unmarshal(mock.proposedCmds[0].Payload, &deregPayload)
		require.NoError(t, err)
		assert.Equal(t, "node-2", deregPayload.ServerID)
		assert.Equal(t, "10.0.0.2:9090", deregPayload.Address)
	})

	t.Run("cluster remove leader self-removal is rejected with 400 Bad Request", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader: true,
			nodeID:   "leader-node",
			addrByServerID: map[string]string{
				"leader-node": "10.0.0.1:9090",
			},
		}

		registerClusterRoutes(app, mock)

		payload := `{"node_id":"leader-node"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "cannot remove active cluster leader; step down leadership via /api/v1/cluster/step-down or stop the node to elect a new leader before removal")
		assert.Empty(t, mock.callOrder)
		assert.Empty(t, mock.proposedCmds)
		assert.Empty(t, mock.removedNode)
		assert.Empty(t, mock.deregisteredAddrs)
	})

	t.Run("cluster remove on follower is rejected", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			nodeID:     "node-2",
		}

		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-3"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Equal(t, "1", resp.Header.Get("Retry-After"))
		assert.Empty(t, mock.deregisteredAddrs)
	})

	t.Run("cluster join voter configuration conflict returns 409", func(t *testing.T) {
		conflictErrors := []string{
			"raft: node already exists",
			"address conflict with existing member",
			"node is already part of the cluster",
		}

		for _, errMsg := range conflictErrors {
			t.Run(errMsg, func(t *testing.T) {
				app := fiber.New()
				mock := &mockClusterState{
					isLeader: true,
					joinErr:  errors.New(errMsg),
				}
				registerClusterRoutes(app, mock)

				payload := `{"node_id":"node-2","address":"10.0.0.2:9090"}`
				req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer test-cluster-secret")

				resp, err := app.Test(req)
				require.NoError(t, err)
				assert.Equal(t, http.StatusConflict, resp.StatusCode)
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Contains(t, string(body), "configuration conflict: "+errMsg)
			})
		}
	})

	t.Run("cluster join voter failure propagates underlying error with 500", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader: true,
			joinErr:  errors.New("raft: transport error"),
		}
		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-2","address":"10.0.0.2:9090"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "failed to add voter: raft: transport error")
	})

	t.Run("cluster remove server failure propagates underlying error without proposing deregistration", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:  true,
			nodeID:    "node-1",
			removeErr: errors.New("raft: transport error"),
		}
		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-2"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "failed to remove server: raft: transport error")
		assert.Empty(t, mock.proposedCmds)
		assert.Equal(t, []string{"RemoveServer"}, mock.callOrder)
		assert.Empty(t, mock.deregisteredAddrs)
	})

	t.Run("cluster remove non-existent server returns 404 with wrapped error message", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:  true,
			nodeID:    "node-1",
			removeErr: fmt.Errorf("%w: raft: node not found", raft.ErrNotFound),
		}
		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-99"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "server node-99 not found in cluster")
		assert.Empty(t, mock.proposedCmds)
		assert.Equal(t, []string{"RemoveServer"}, mock.callOrder)
		assert.Empty(t, mock.deregisteredAddrs)
	})

	t.Run("cluster remove non-existent server returns 404 with ErrNotFound sentinel", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:  true,
			nodeID:    "node-1",
			removeErr: raft.ErrNotFound,
		}
		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-missing"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "server node-missing not found in cluster")
		assert.Empty(t, mock.proposedCmds)
		assert.Equal(t, []string{"RemoveServer"}, mock.callOrder)
		assert.Empty(t, mock.deregisteredAddrs)
	})

	t.Run("cluster join includes warning when proposal fails", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "node-1",
			proposeErr: errors.New("replication proposal timeout"),
		}

		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-2","address":"10.0.0.2:9090","http_address":"http://10.0.0.2:8080"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var respData map[string]any
		err = json.NewDecoder(resp.Body).Decode(&respData)
		require.NoError(t, err)
		assert.Equal(t, "joined", respData["status"])
		assert.Equal(t, "node-2", respData["node_id"])
		assert.Equal(t, "10.0.0.2:9090", respData["address"])
		assert.Equal(t, "http://10.0.0.2:8080", respData["http_address"])
		assert.Contains(t, respData["warning"], "failed to replicate node HTTP address registration: replication proposal timeout")
	})

	t.Run("cluster join includes warning when state machine rejects registration", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:     true,
			leaderAddr:   "10.0.0.1:8080",
			nodeID:       "node-1",
			applyRespErr: errors.New("state machine rejected registration"),
		}

		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-2","address":"10.0.0.2:9090","http_address":"http://10.0.0.2:8080"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var respData map[string]any
		err = json.NewDecoder(resp.Body).Decode(&respData)
		require.NoError(t, err)
		assert.Equal(t, "joined", respData["status"])
		assert.Contains(t, respData["warning"], "node HTTP address registration rejected by state machine: state machine rejected registration")
	})

	t.Run("cluster remove includes warning when proposal fails", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader: true,
			nodeID:   "node-1",
			addrByServerID: map[string]string{
				"node-2": "10.0.0.2:9090",
			},
			proposeErr: errors.New("replication proposal timeout"),
		}

		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-2"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var respData map[string]any
		err = json.NewDecoder(resp.Body).Decode(&respData)
		require.NoError(t, err)
		assert.Equal(t, "removed", respData["status"])
		assert.Equal(t, "node-2", respData["node_id"])
		assert.Contains(t, respData["warning"], "failed to replicate node HTTP address deregistration: replication proposal timeout")
	})

	t.Run("cluster remove includes warning when state machine rejects deregistration", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader: true,
			nodeID:   "node-1",
			addrByServerID: map[string]string{
				"node-2": "10.0.0.2:9090",
			},
			applyRespErr: errors.New("state machine rejected deregistration"),
		}

		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-2"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var respData map[string]any
		err = json.NewDecoder(resp.Body).Decode(&respData)
		require.NoError(t, err)
		assert.Equal(t, "removed", respData["status"])
		assert.Equal(t, "node-2", respData["node_id"])
		assert.Contains(t, respData["warning"], "node HTTP address deregistration rejected by state machine: state machine rejected deregistration")
	})
}

func TestClusterMiddlewareMetricsProxiedToLeader(t *testing.T) {
	var proxied bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = true
		assert.Equal(t, "/metrics", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied_metrics"))
	}))
	defer upstream.Close()

	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: upstream.Listener.Addr().String(),
		nodeID:     "node-2",
	}

	app.Use(clusterRoutingMiddleware(mock))
	app.Get("/metrics", func(c *fiber.Ctx) error {
		return c.SendString("local_metrics")
	})

	req := httptest.NewRequest("GET", "/metrics", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "proxied_metrics", string(body))
	assert.True(t, proxied, "/metrics must be proxied to leader on follower")
}

func TestClusterMiddlewareMetricsLeaderExecutesBarrier(t *testing.T) {
	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   true,
		barrierErr: errors.New("quorum lost"),
	}
	app.Use(clusterRoutingMiddleware(mock))
	app.Get("/metrics", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/metrics", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "1", resp.Header.Get("Retry-After"))
}


func TestClusterAdminAuthMiddleware(t *testing.T) {
	secret := "super-secret-cluster-token"

	setupApp := func(configuredSecret string) (*fiber.App, *mockClusterState) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "node-1",
		}
		registerClusterAdminAuth(app, configuredSecret)
		registerClusterRoutes(app, mock)
		return app, mock
	}

	joinPayload := `{"node_id":"node-2","address":"10.0.0.2:9090"}`
	removePayload := `{"node_id":"node-2"}`

	t.Run("unauthenticated requests rejected with 401 when secret configured", func(t *testing.T) {
		app, _ := setupApp(secret)

		// Join without auth header
		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(joinPayload))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Remove without auth header
		req = httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(removePayload))
		req.Header.Set("Content-Type", "application/json")
		resp, err = app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("invalid secret rejected with 401", func(t *testing.T) {
		app, _ := setupApp(secret)

		// Wrong Bearer token
		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(joinPayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer wrong-secret")
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Wrong X-Grantory-Cluster-Secret header
		req = httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(removePayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Grantory-Cluster-Secret", "wrong-secret")
		resp, err = app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("authorized request with Bearer token succeeds", func(t *testing.T) {
		app, mock := setupApp(secret)

		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(joinPayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "node-2", mock.joinedNodeID)

		req = httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(removePayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err = app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "node-2", mock.removedNode)
	})

	t.Run("request with X-Grantory-Cluster-Secret header alone is rejected with 401", func(t *testing.T) {
		app, mock := setupApp(secret)

		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(joinPayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Grantory-Cluster-Secret", secret)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Empty(t, mock.joinedNodeID)

		req = httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(removePayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Grantory-Cluster-Secret", secret)
		resp, err = app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Empty(t, mock.removedNode)
	})

	t.Run("authorized request with whitespace-padded Bearer token succeeds", func(t *testing.T) {
		app, mock := setupApp(secret)

		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(joinPayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer   "+secret+" \t\n")
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "node-2", mock.joinedNodeID)
	})

	t.Run("unauthenticated requests fail with 403 when no secret is configured", func(t *testing.T) {
		app, _ := setupApp("")

		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(joinPayload))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		req = httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(removePayload))
		req.Header.Set("Content-Type", "application/json")
		resp, err = app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("server initialized with Bearer prefix in secret accepts Bearer authorization header", func(t *testing.T) {
		app, mock := setupApp("Bearer supersecret")

		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(joinPayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer supersecret")
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "node-2", mock.joinedNodeID)
	})
}

func TestClusterJoinDynamicHTTPAddress(t *testing.T) {
	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   true,
		leaderAddr: "10.0.0.1:8080",
		nodeID:     "node-1",
	}
	registerClusterRoutes(app, mock)

	payload := `{"node_id":"node-2","address":"10.0.0.2:9090","http_address":"http://10.0.0.2:8080"}`
	req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-cluster-secret")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "node-2", mock.joinedNodeID)
	assert.Equal(t, "10.0.0.2:9090", mock.joinedAddr)

	// Assert address resolution on node maps both Address and NodeID to HTTPAddress
	assert.Equal(t, "http://10.0.0.2:8080", mock.HTTPAddrFor("10.0.0.2:9090"))
	assert.Equal(t, "http://10.0.0.2:8080", mock.HTTPAddrFor("node-2"))

	// Assert dynamic HTTP address registration was proposed to Raft cluster
	require.Len(t, mock.proposedCmds, 1)
	proposed := mock.proposedCmds[0]
	assert.Equal(t, raft.CmdRegisterNodeHTTPAddr, proposed.Type)
	var regPayload raft.RegisterNodeHTTPAddrPayload
	err = json.Unmarshal(proposed.Payload, &regPayload)
	require.NoError(t, err)
	assert.Equal(t, "node-2", regPayload.ServerID)
	assert.Equal(t, "10.0.0.2:9090", regPayload.Address)
	assert.Equal(t, "http://10.0.0.2:8080", regPayload.HTTPAddr)

	// Verify *raft.RaftNode satisfies HTTPAddrRegistrar interface and CommandProposer interface
	var _ HTTPAddrRegistrar = (*raft.RaftNode)(nil)
	var _ CommandProposer = (*raft.RaftNode)(nil)
}

func TestClusterRemoveDynamicHTTPAddress(t *testing.T) {
	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   true,
		leaderAddr: "10.0.0.1:8080",
		nodeID:     "node-1",
		addrByServerID: map[string]string{
			"node-2": "10.0.0.2:9090",
		},
		httpAddrs: map[string]string{
			"node-2":        "http://10.0.0.2:8080",
			"10.0.0.2:9090": "http://10.0.0.2:8080",
		},
	}
	registerClusterRoutes(app, mock)

	payload := `{"node_id":"node-2"}`
	req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-cluster-secret")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "node-2", mock.removedNode)

	// Assert in-memory registrar was cleared immediately for both node-2 and 10.0.0.2:9090
	assert.Equal(t, []string{"node-2", "10.0.0.2:9090"}, mock.deregisteredAddrs)
	assert.Empty(t, mock.HTTPAddrFor("node-2"))
	assert.Empty(t, mock.HTTPAddrFor("10.0.0.2:9090"))

	// Assert Raft proposal for deregistration was also submitted
	require.Len(t, mock.proposedCmds, 1)
	proposed := mock.proposedCmds[0]
	assert.Equal(t, raft.CmdDeregisterNodeHTTPAddr, proposed.Type)
	var deregPayload raft.DeregisterNodeHTTPAddrPayload
	err = json.Unmarshal(proposed.Payload, &deregPayload)
	require.NoError(t, err)
	assert.Equal(t, "node-2", deregPayload.ServerID)
	assert.Equal(t, "10.0.0.2:9090", deregPayload.Address)
}

func TestClusterJoinMalformedAddress(t *testing.T) {
	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   true,
		leaderAddr: "10.0.0.1:8080",
		nodeID:     "node-1",
	}
	registerClusterRoutes(app, mock)

	badAddresses := []string{
		"bad-address",
		":8081",
		"localhost:",
		"10.0.0.2",
		"   :9090",
		"10.0.0.2:   ",
	}

	for _, badAddr := range badAddresses {
		t.Run("rejects_"+badAddr, func(t *testing.T) {
			payload := `{"node_id":"node-bad","address":"` + badAddr + `"}`
			req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer test-cluster-secret")

			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestClusterJoinInvalidHTTPAddress(t *testing.T) {
	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   true,
		leaderAddr: "10.0.0.1:8080",
		nodeID:     "node-1",
	}
	registerClusterRoutes(app, mock)

	invalidHTTPAddrs := []string{
		"not-a-url",
		"ftp://localhost:8080",
		"://foo",
		"http://",
		"https://",
		"ws://10.0.0.2:8080",
	}

	for _, badHTTP := range invalidHTTPAddrs {
		t.Run("rejects_"+badHTTP, func(t *testing.T) {
			payload := `{"node_id":"node-bad","address":"10.0.0.2:9090","http_address":"` + badHTTP + `"}`
			req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer test-cluster-secret")

			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestClusterJoinUnspecifiedIP(t *testing.T) {
	app := fiber.New()
	mock := &mockClusterState{
		isLeader:   true,
		leaderAddr: "10.0.0.1:8080",
		nodeID:     "node-1",
	}
	registerClusterRoutes(app, mock)

	testCases := []struct {
		name        string
		payload     string
		expectedMsg string
	}{
		{
			name:        "unspecified IPv4 raft address 0.0.0.0:8081",
			payload:     `{"node_id":"node-bad","address":"0.0.0.0:8081"}`,
			expectedMsg: "address cannot be an unspecified IP (0.0.0.0 or ::)",
		},
		{
			name:        "unspecified IPv6 raft address [::]:8081",
			payload:     `{"node_id":"node-bad","address":"[::]:8081"}`,
			expectedMsg: "address cannot be an unspecified IP (0.0.0.0 or ::)",
		},
		{
			name:        "unspecified IPv4 http address http://0.0.0.0:8080",
			payload:     `{"node_id":"node-bad","address":"10.0.0.2:8081","http_address":"http://0.0.0.0:8080"}`,
			expectedMsg: "http_address cannot have an unspecified IP host",
		},
		{
			name:        "unspecified IPv6 http address http://[::]:8080",
			payload:     `{"node_id":"node-bad","address":"10.0.0.2:8081","http_address":"http://[::]:8080"}`,
			expectedMsg: "http_address cannot have an unspecified IP host",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(tc.payload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer test-cluster-secret")

			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), tc.expectedMsg)
		})
	}
}

func TestClusterMiddlewareStaticWebUIRoutesExempt(t *testing.T) {
	staticPaths := []string{
		"/",
		"/favicon.ico",
		"/static/app.js",
		"/static/css/style.css",
	}

	t.Run("follower bypasses proxying for static web UI routes", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: "127.0.0.1:9090", // Unreachable proxy target
			nodeID:     "node-follower",
		}
		app.Use(clusterRoutingMiddleware(mock))

		for _, p := range staticPaths {
			path := p
			app.Get(path, func(c *fiber.Ctx) error {
				return c.SendString("static-ui:" + path)
			})
		}

		for _, p := range staticPaths {
			req := httptest.NewRequest("GET", p, nil)
			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "path %s should bypass follower proxying", p)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "static-ui:"+p, string(body))
		}
	})

	t.Run("leader bypasses read barrier for static web UI routes", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			barrierErr: errors.New("raft: lost quorum during read barrier"),
			nodeID:     "node-leader",
		}
		app.Use(clusterRoutingMiddleware(mock))

		for _, p := range staticPaths {
			path := p
			app.Get(path, func(c *fiber.Ctx) error {
				return c.SendString("static-ui:" + path)
			})
		}

		for _, p := range staticPaths {
			req := httptest.NewRequest("GET", p, nil)
			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "path %s should bypass leader read barrier", p)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "static-ui:"+p, string(body))
		}
	})
}

func TestClusterMiddlewareStaticRoutePathNormalization(t *testing.T) {
	testPaths := []string{
		"/static",
		"/static/",
		"/static/css/app.css",
		"//static/app.css",
		"/static/../static/app.css",
		"/favicon.ico",
		"//favicon.ico",
	}

	t.Run("follower bypasses proxying for normalized static routes", func(t *testing.T) {
		var proxied bool
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxied = true
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "node-follower",
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Use(func(c *fiber.Ctx) error {
			return c.SendString("static-route-bypassed")
		})

		for _, p := range testPaths {
			proxied = false
			req := httptest.NewRequest("GET", p, nil)
			resp, err := app.Test(req)
			require.NoError(t, err, "request for %s failed", p)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "path %s should bypass follower proxying", p)
			assert.False(t, proxied, "path %s must not be proxied to leader", p)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "static-route-bypassed", string(body))
		}
	})

	t.Run("leader bypasses read barrier for normalized static routes", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			barrierErr: errors.New("raft: lost quorum during read barrier"),
			nodeID:     "node-leader",
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Use(func(c *fiber.Ctx) error {
			return c.SendString("static-route-bypassed")
		})

		for _, p := range testPaths {
			req := httptest.NewRequest("GET", p, nil)
			resp, err := app.Test(req)
			require.NoError(t, err, "request for %s failed", p)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "path %s should bypass leader read barrier", p)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "static-route-bypassed", string(body))
		}
	})
}

func TestClusterMiddlewareDynamicUIPagesRouteThroughConsensus(t *testing.T) {
	uiPaths := []string{
		"/index.html",
		"/register.html",
		"/request.html",
		"/grant.html",
		"/schema.html",
	}

	t.Run("follower proxies dynamic server-rendered UI pages to leader", func(t *testing.T) {
		var mu sync.Mutex
		var lastReceivedPath string
		var lastForwardedBy string
		var lastForwardedSig string

		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			lastReceivedPath = r.URL.Path
			lastForwardedBy = r.Header.Get(HeaderForwardedBy)
			lastForwardedSig = r.Header.Get(HeaderForwardedSig)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("proxied:" + r.URL.Path))
		}))
		defer upstream.Close()

		leaderHTTP := upstream.URL

		app := fiber.New()
		mock := &mockClusterState{
			isLeader:       false,
			leaderAddr:     upstream.Listener.Addr().String(),
			leaderHTTPAddr: &leaderHTTP,
			nodeID:         "node-follower-ui",
		}
		app.Use(clusterRoutingMiddleware(mock))

		for _, p := range uiPaths {
			req := httptest.NewRequest("GET", p, nil)
			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "dynamic UI path %s should be proxied to leader", p)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "proxied:"+p, string(body))

			mu.Lock()
			assert.Equal(t, p, lastReceivedPath)
			assert.Equal(t, "node-follower-ui", lastForwardedBy)
			assert.NotEmpty(t, lastForwardedSig, "forwarded signature must be set for %s", p)
			mu.Unlock()
		}
	})

	t.Run("leader executes read barrier for dynamic server-rendered UI pages", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			barrierErr: errors.New("raft: lost quorum during read barrier"),
			nodeID:     "node-leader-ui",
		}
		app.Use(clusterRoutingMiddleware(mock))

		for _, p := range uiPaths {
			path := p
			app.Get(path, func(c *fiber.Ctx) error {
				return c.SendString("rendered:" + path)
			})
		}

		for _, p := range uiPaths {
			req := httptest.NewRequest("GET", p, nil)
			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "dynamic UI path %s on leader must fail when barrier fails", p)
			assert.Equal(t, "1", resp.Header.Get("Retry-After"))
		}

		// When barrier succeeds, UI pages render successfully
		mock.barrierErr = nil
		for _, p := range uiPaths {
			req := httptest.NewRequest("GET", p, nil)
			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "dynamic UI path %s on leader must succeed when barrier succeeds", p)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "rendered:"+p, string(body))
		}
	})
}

func TestFollowerProxySafeURIPathAndQueryReconstruction(t *testing.T) {
	var receivedPath string
	var receivedQuery string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"proxied":true}`))
	}))
	defer upstream.Close()

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		if c.Get("X-Simulate-Absolute-URI") != "" {
			c.Request().SetRequestURI("http://external-proxy.example.com/api/v1/requests?id=123")
		}
		return c.Next()
	})
	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: upstream.Listener.Addr().String(),
		nodeID:     "node-follower",
	}
	app.Use(clusterRoutingMiddleware(mock))

	t.Run("proxies complex query string properly", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/requests?status=active&filter=team%20a&page=1", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "/api/v1/requests", receivedPath)
		assert.Equal(t, "status=active&filter=team%20a&page=1", receivedQuery)
	})

	t.Run("handles absolute URI in request target safely", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/requests?id=123", nil)
		req.Header.Set("X-Simulate-Absolute-URI", "true")
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "/api/v1/requests", receivedPath)
		assert.Equal(t, "id=123", receivedQuery)
	})
}

type mockEmptyNodeIDState struct {
	isLeader   bool
	leaderAddr string
	hopSecret  [32]byte
}

func (m *mockEmptyNodeIDState) HopSecret() [32]byte {
	if m.hopSecret == ([32]byte{}) {
		if _, err := cryptorand.Read(m.hopSecret[:]); err != nil {
			panic(err)
		}
	}
	return m.hopSecret
}

func (m *mockEmptyNodeIDState) IsLeader() bool {
	return m.isLeader
}

func (m *mockEmptyNodeIDState) LeaderAddr() string {
	return m.leaderAddr
}

func TestFollowerProxyEmptyNodeIDFallbackDistinctUUID(t *testing.T) {
	var receivedHops string
	var receivedSigs string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHops = r.Header.Get("X-Grantory-Forwarded-By")
		receivedSigs = r.Header.Get("X-Grantory-Forwarded-Sig")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	mock1 := &mockEmptyNodeIDState{isLeader: false, leaderAddr: upstream.Listener.Addr().String()}
	mock2 := &mockEmptyNodeIDState{isLeader: false, leaderAddr: upstream.Listener.Addr().String()}

	mw1 := clusterRoutingMiddleware(mock1)
	mw2 := clusterRoutingMiddleware(mock2)

	app1 := fiber.New()
	app1.Use(mw1)
	app1.Post("/api/v1/requests", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	app2 := fiber.New()
	app2.Use(mw2)
	app2.Post("/api/v1/requests", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	// 1. Request through app1 to upstream captures node 1 instance ID
	req1 := httptest.NewRequest("POST", "/api/v1/requests", nil)
	resp1, err := app1.Test(req1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	id1 := strings.TrimSpace(receivedHops)
	sig1 := strings.TrimSpace(receivedSigs)
	require.NotEmpty(t, id1)
	assert.NotEqual(t, "grantory-node", id1, "fallback node ID must be a unique UUID, not static grantory-node")

	// 2. Request through app2 to upstream captures node 2 instance ID
	req2 := httptest.NewRequest("POST", "/api/v1/requests", nil)
	resp2, err := app2.Test(req2)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	id2 := strings.TrimSpace(receivedHops)
	require.NotEmpty(t, id2)
	assert.NotEqual(t, "grantory-node", id2)
	assert.NotEqual(t, id1, id2, "distinct middleware instances must have distinct fallback IDs")

	// 3. Chaining: simulate a request from node 1 forwarded into node 2
	reqChained := httptest.NewRequest("POST", "/api/v1/requests", nil)
	reqChained.Header.Set("X-Grantory-Forwarded-By", id1)
	reqChained.Header.Set("X-Grantory-Forwarded-Sig", sig1)

	respChained, err := app2.Test(reqChained)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respChained.StatusCode)
	// Node 2 must preserve id1 and append id2, not strip id1 as a spoofed header
	assert.Equal(t, id1+", "+id2, receivedHops)

	// 4. Loop detection: if request carrying node 1's hop arrives back at node 1, loop is detected
	reqLoop := httptest.NewRequest("POST", "/api/v1/requests", nil)
	reqLoop.Header.Set("X-Grantory-Forwarded-By", receivedHops)
	reqLoop.Header.Set("X-Grantory-Forwarded-Sig", receivedSigs)

	respLoop, err := app1.Test(reqLoop)
	require.NoError(t, err)
	assert.Equal(t, http.StatusLoopDetected, respLoop.StatusCode, "loop must be detected when request returns to origin node")
}

func TestMetaRouteBypassesProxyAndReadBarrier(t *testing.T) {
	t.Run("follower mode bypasses proxying for /meta", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: "127.0.0.1:9999", // Unreachable upstream if proxied
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Get("/meta", func(c *fiber.Ctx) error {
			return c.SendString("meta local")
		})

		req := httptest.NewRequest("GET", "/meta", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "meta local", string(body))
	})

	t.Run("leader mode bypasses read barrier for /meta", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			barrierErr: errors.New("raft: lost quorum during read barrier"),
		}
		app.Use(clusterRoutingMiddleware(mock))
		app.Get("/meta", func(c *fiber.Ctx) error {
			return c.SendString("meta local")
		})

		req := httptest.NewRequest("GET", "/meta", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "meta local", string(body))
	})
}

func TestFollowerProxyBypassWithTrailingSlashes(t *testing.T) {
	endpoints := []string{
		"/healthz/",
		"/readyz/",
		"/meta/",
		"/api/v1/cluster/status/",
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			var proxied bool
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxied = true
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			app := fiber.New()
			mock := &mockClusterState{
				isLeader:   false,
				leaderAddr: upstream.Listener.Addr().String(),
				nodeID:     "follower-node-1",
			}
			app.Use(clusterRoutingMiddleware(mock))

			app.Get(endpoint, func(c *fiber.Ctx) error {
				return c.SendString("local:" + c.Path())
			})

			req := httptest.NewRequest("GET", endpoint, nil)
			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "local:"+endpoint, string(body))
			assert.False(t, proxied, "endpoint %s must not be proxied to leader", endpoint)
		})
	}
}

func TestClusterEndpointsFollowerProxyAndStatusLocal(t *testing.T) {
	var proxiedPaths []string
	var mu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		proxiedPaths = append(proxiedPaths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"proxied"}`))
	}))
	defer upstream.Close()

	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: upstream.Listener.Addr().String(),
		nodeID:     "follower-node-1",
	}

	app := fiber.New()
	registerClusterAdminAuth(app, "test-secret")
	app.Use(clusterRoutingMiddleware(mock))
	registerClusterRoutes(app, mock)

	// 1. GET /api/v1/cluster/status executes locally on follower without proxying
	reqStatus := httptest.NewRequest("GET", "/api/v1/cluster/status", nil)
	respStatus, err := app.Test(reqStatus)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respStatus.StatusCode)
	var statusBody ClusterStatusResponse
	require.NoError(t, json.NewDecoder(respStatus.Body).Decode(&statusBody))
	assert.Equal(t, "follower-node-1", statusBody.NodeID)
	assert.Equal(t, "follower", statusBody.Role)
	assert.False(t, statusBody.IsLeader)

	mu.Lock()
	assert.Empty(t, proxiedPaths, "GET /api/v1/cluster/status must not be proxied to leader")
	mu.Unlock()

	// 2. Unauthenticated POST /api/v1/cluster/join returns 401 and is NOT proxied
	joinBody := `{"node_id":"node-2","address":"127.0.0.1:8082"}`
	unauthJoin := httptest.NewRequest("POST", "/api/v1/cluster/join", strings.NewReader(joinBody))
	unauthJoin.Header.Set("Content-Type", "application/json")
	respUnauthJoin, err := app.Test(unauthJoin)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, respUnauthJoin.StatusCode)

	// 3. Unauthenticated POST /api/v1/cluster/remove returns 401 and is NOT proxied
	removeBody := `{"node_id":"node-2"}`
	unauthRemove := httptest.NewRequest("POST", "/api/v1/cluster/remove", strings.NewReader(removeBody))
	unauthRemove.Header.Set("Content-Type", "application/json")
	respUnauthRemove, err := app.Test(unauthRemove)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, respUnauthRemove.StatusCode)

	mu.Lock()
	assert.Empty(t, proxiedPaths, "unauthenticated cluster requests must not be proxied to leader")
	mu.Unlock()

	// 4. Authenticated POST /api/v1/cluster/join is proxied to leader
	reqJoin := httptest.NewRequest("POST", "/api/v1/cluster/join", strings.NewReader(joinBody))
	reqJoin.Header.Set("Content-Type", "application/json")
	reqJoin.Header.Set("Authorization", "Bearer test-secret")
	respJoin, err := app.Test(reqJoin)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respJoin.StatusCode)

	// 5. Authenticated POST /api/v1/cluster/remove is proxied to leader
	reqRemove := httptest.NewRequest("POST", "/api/v1/cluster/remove", strings.NewReader(removeBody))
	reqRemove.Header.Set("Content-Type", "application/json")
	reqRemove.Header.Set("Authorization", "Bearer test-secret")
	respRemove, err := app.Test(reqRemove)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respRemove.StatusCode)

	// 6. Authenticated POST /api/v1/cluster/step-down executes locally on follower without proxying (returns 503)
	reqStepDown := httptest.NewRequest("POST", "/api/v1/cluster/step-down", nil)
	reqStepDown.Header.Set("Authorization", "Bearer test-secret")
	respStepDown, err := app.Test(reqStepDown)
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, respStepDown.StatusCode)
	assert.Equal(t, "1", respStepDown.Header.Get("Retry-After"))

	mu.Lock()
	assert.Contains(t, proxiedPaths, "/api/v1/cluster/join")
	assert.Contains(t, proxiedPaths, "/api/v1/cluster/remove")
	assert.NotContains(t, proxiedPaths, "/api/v1/cluster/step-down", "POST /api/v1/cluster/step-down must not be proxied to leader")
	mu.Unlock()
}

func TestClusterStepDownFollowerBypass(t *testing.T) {
	var proxiedPaths []string
	var mu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		proxiedPaths = append(proxiedPaths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"proxied"}`))
	}))
	defer upstream.Close()

	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: upstream.Listener.Addr().String(),
		nodeID:     "follower-node-2",
	}

	app := fiber.New()
	registerClusterAdminAuth(app, "test-secret")
	app.Use(clusterRoutingMiddleware(mock))
	registerClusterRoutes(app, mock)

	// 1. Unauthenticated POST /api/v1/cluster/step-down returns 401 without proxying
	unauthReq := httptest.NewRequest("POST", "/api/v1/cluster/step-down", nil)
	respUnauth, err := app.Test(unauthReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, respUnauth.StatusCode)

	// 2. Authenticated POST /api/v1/cluster/step-down executes locally, returning 503 and Retry-After: 1
	authReq := httptest.NewRequest("POST", "/api/v1/cluster/step-down", nil)
	authReq.Header.Set("Authorization", "Bearer test-secret")
	respAuth, err := app.Test(authReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, respAuth.StatusCode)
	assert.Equal(t, "1", respAuth.Header.Get("Retry-After"))
	body, err := io.ReadAll(respAuth.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "node is not cluster leader")

	// 3. Trailing slash /api/v1/cluster/step-down/ also bypasses proxying
	slashReq := httptest.NewRequest("POST", "/api/v1/cluster/step-down/", nil)
	slashReq.Header.Set("Authorization", "Bearer test-secret")
	respSlash, err := app.Test(slashReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, respSlash.StatusCode)
	assert.Equal(t, "1", respSlash.Header.Get("Retry-After"))

	// Verify upstream leader never received any step-down request
	mu.Lock()
	assert.Empty(t, proxiedPaths, "POST /api/v1/cluster/step-down must never be reverse-proxied to leader")
	mu.Unlock()
}

func TestClusterEndpointsFollowerUnconfiguredSecret(t *testing.T) {
	var proxiedPaths []string
	var mu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		proxiedPaths = append(proxiedPaths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"proxied"}`))
	}))
	defer upstream.Close()

	mock := &mockClusterState{
		isLeader:   false,
		leaderAddr: upstream.Listener.Addr().String(),
		nodeID:     "follower-node-1",
	}

	app := fiber.New()
	registerClusterAdminAuth(app, "")
	app.Use(clusterRoutingMiddleware(mock))
	registerClusterRoutes(app, mock)

	// Join with empty secret returns 403 Forbidden without proxying
	joinBody := `{"node_id":"node-2","address":"127.0.0.1:8082"}`
	reqJoin := httptest.NewRequest("POST", "/api/v1/cluster/join", strings.NewReader(joinBody))
	reqJoin.Header.Set("Content-Type", "application/json")
	respJoin, err := app.Test(reqJoin)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, respJoin.StatusCode)

	// Remove with empty secret returns 403 Forbidden without proxying
	removeBody := `{"node_id":"node-2"}`
	reqRemove := httptest.NewRequest("POST", "/api/v1/cluster/remove", strings.NewReader(removeBody))
	reqRemove.Header.Set("Content-Type", "application/json")
	respRemove, err := app.Test(reqRemove)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, respRemove.StatusCode)

	mu.Lock()
	assert.Empty(t, proxiedPaths, "unconfigured secret requests must not be proxied to leader")
	mu.Unlock()
}

type testLogHook struct {
	mu       sync.Mutex
	messages []string
}

func (h *testLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *testLogHook) Fire(entry *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messages = append(h.messages, entry.Message)
	return nil
}

func (h *testLogHook) hasMessage(msg string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.messages {
		if strings.Contains(m, msg) {
			return true
		}
	}
	return false
}

func TestClusterJoinAndRemove_ProposeFailureHandlingAndLogging(t *testing.T) {
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

	t.Run("cluster join succeeds when prop.Propose returns error", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			leaderAddr: "10.0.0.1:8080",
			nodeID:     "node-1",
			proposeErr: errors.New("raft replication failed"),
		}
		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-2","address":"10.0.0.2:9090","http_address":"http://10.0.0.2:8080"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "node-2", mock.joinedNodeID)
		assert.True(t, hook.hasMessage("failed to replicate node HTTP address registration"))
	})

	t.Run("cluster join succeeds when applyResp.Error is returned", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:     true,
			leaderAddr:   "10.0.0.1:8080",
			nodeID:       "node-1",
			applyRespErr: errors.New("state machine rejected"),
		}
		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-2","address":"10.0.0.2:9090","http_address":"http://10.0.0.2:8080"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/join", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "node-2", mock.joinedNodeID)
		assert.True(t, hook.hasMessage("node HTTP address registration rejected by state machine"))
	})

	t.Run("cluster remove succeeds when prop.Propose returns error", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:   true,
			nodeID:     "node-1",
			proposeErr: errors.New("raft replication failed"),
		}
		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-2"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "node-2", mock.removedNode)
		assert.True(t, hook.hasMessage("failed to replicate node HTTP address deregistration"))
	})

	t.Run("cluster remove succeeds when applyResp.Error is returned", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader:     true,
			nodeID:       "node-1",
			applyRespErr: errors.New("state machine rejected"),
		}
		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-2"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "node-2", mock.removedNode)
		assert.True(t, hook.hasMessage("node HTTP address deregistration rejected by state machine"))
	})

	t.Run("cluster remove alias does not submit redundant alias proposal", func(t *testing.T) {
		app := fiber.New()
		mock := &mockClusterState{
			isLeader: true,
			nodeID:   "node-1",
			serverIDByAddr: map[string]string{
				"node-alias": "node-2",
			},
			addrByServerID: map[string]string{
				"node-2": "10.0.0.2:9090",
			},
		}
		registerClusterRoutes(app, mock)

		payload := `{"node_id":"node-alias"}`
		req := httptest.NewRequest("POST", "/api/v1/cluster/remove", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cluster-secret")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "node-2", mock.removedNode)
		require.Len(t, mock.proposedCmds, 1, "only single deregistration command should be proposed")
		assert.Equal(t, raft.CmdDeregisterNodeHTTPAddr, mock.proposedCmds[0].Type)
		var deregPayload raft.DeregisterNodeHTTPAddrPayload
		err = json.Unmarshal(mock.proposedCmds[0].Payload, &deregPayload)
		require.NoError(t, err)
		assert.Equal(t, "node-2", deregPayload.ServerID)
		assert.Equal(t, "10.0.0.2:9090", deregPayload.Address)
	})
}

func TestClusterMiddlewareAbsoluteURLRewriting(t *testing.T) {
	testCases := []struct {
		name        string
		inputURL    string
		expectedURI string
	}{
		{
			name:        "absolute URL without path slash but with query",
			inputURL:    "http://example.com?foo=bar",
			expectedURI: "/?foo=bar",
		},
		{
			name:        "absolute URL with path and query",
			inputURL:    "http://example.com/api/v1/resource?foo=bar",
			expectedURI: "/api/v1/resource?foo=bar",
		},
		{
			name:        "https absolute URL without path slash with query",
			inputURL:    "https://example.com?param=value",
			expectedURI: "/?param=value",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var requestedURI string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestedURI = r.RequestURI
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			}))
			defer upstream.Close()

			app := fiber.New()
			mock := &mockClusterState{
				isLeader:   false,
				leaderAddr: upstream.Listener.Addr().String(),
				nodeID:     "follower-node-1",
			}
			app.Use(clusterRoutingMiddleware(mock))

			req := httptest.NewRequest("GET", tc.inputURL, nil)
			req.Proto = "HTTP/1.0"
			req.ProtoMinor = 0
			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, tc.expectedURI, requestedURI)
		})
	}
}

func TestClusterForwarding_DistinctHopSecretsAndLoopDetection(t *testing.T) {
	t.Run("multi-hop forwarding between nodes with distinct hop secrets does not strip forwarding headers", func(t *testing.T) {
		var receivedForwardedBy string
		var receivedForwardedSig string
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedForwardedBy = r.Header.Get(HeaderForwardedBy)
			receivedForwardedSig = r.Header.Get(HeaderForwardedSig)
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		mock1 := &mockClusterState{
			isLeader:   false,
			leaderAddr: "127.0.0.1:9999",
			nodeID:     "node-1",
		}
		mock2 := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "node-2",
		}
		require.NotEqual(t, mock1.HopSecret(), mock2.HopSecret(), "nodes must have distinct secrets")

		// Create app2 (node-2 forwarding to upstream)
		app2 := fiber.New()
		app2.Use(clusterRoutingMiddleware(mock2))
		app2.Post("/api/v1/resource", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		// Create a mock hop from node-1 using node-1's private secret
		now := time.Now().Unix()
		sig1 := ComputeHopSignature(mock1.HopSecret(), "node-1", now)
		sig1Entry := fmt.Sprintf("node-1:%d:%s", now, sig1)

		req := httptest.NewRequest("POST", "/api/v1/resource", nil)
		req.Header.Set(HeaderForwardedBy, "node-1")
		req.Header.Set(HeaderForwardedSig, sig1Entry)

		resp, err := app2.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Node 2 must preserve node-1 and append node-2
		assert.Equal(t, "node-1, node-2", receivedForwardedBy)
		assert.Contains(t, receivedForwardedSig, sig1Entry, "node-1 signature must be preserved")
		assert.Contains(t, receivedForwardedSig, "node-2:", "node-2 signature must be appended")
	})

	t.Run("request cycling back (Node 1 -> Node 2 -> Node 1) triggers 508 Loop Detected on Node 1", func(t *testing.T) {
		var receivedForwardedBy string
		var receivedForwardedSig string
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedForwardedBy = r.Header.Get(HeaderForwardedBy)
			receivedForwardedSig = r.Header.Get(HeaderForwardedSig)
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		mock1 := &mockClusterState{
			isLeader:   false,
			leaderAddr: "127.0.0.1:9999",
			nodeID:     "node-1",
		}
		mock2 := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "node-2",
		}
		require.NotEqual(t, mock1.HopSecret(), mock2.HopSecret(), "nodes must have distinct secrets")

		app1 := fiber.New()
		app1.Use(clusterRoutingMiddleware(mock1))
		app1.Post("/api/v1/resource", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		app2 := fiber.New()
		app2.Use(clusterRoutingMiddleware(mock2))
		app2.Post("/api/v1/resource", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		// Step 1: node-1 creates request with its own hop
		now := time.Now().Unix()
		sig1 := ComputeHopSignature(mock1.HopSecret(), "node-1", now)
		sig1Entry := fmt.Sprintf("node-1:%d:%s", now, sig1)

		// Step 2: request arrives at node-2
		reqToNode2 := httptest.NewRequest("POST", "/api/v1/resource", nil)
		reqToNode2.Header.Set(HeaderForwardedBy, "node-1")
		reqToNode2.Header.Set(HeaderForwardedSig, sig1Entry)

		resp2, err := app2.Test(reqToNode2)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp2.StatusCode)
		assert.Equal(t, "node-1, node-2", receivedForwardedBy)

		// Step 3: request cycles back from node-2 to node-1
		reqLoop := httptest.NewRequest("POST", "/api/v1/resource", nil)
		reqLoop.Header.Set(HeaderForwardedBy, receivedForwardedBy)
		reqLoop.Header.Set(HeaderForwardedSig, receivedForwardedSig)

		respLoop, err := app1.Test(reqLoop)
		require.NoError(t, err)
		assert.Equal(t, http.StatusLoopDetected, respLoop.StatusCode, "cycling back to node-1 must trigger 508 Loop Detected")
		body, err := io.ReadAll(respLoop.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "forwarding loop detected")
	})

	t.Run("spoofed foreign hops with unverified signatures do not trigger 508 Loop Detected", func(t *testing.T) {
		var receivedForwardedBy string
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedForwardedBy = r.Header.Get(HeaderForwardedBy)
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: upstream.Listener.Addr().String(),
			nodeID:     "node-target",
		}

		app := fiber.New()
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/data", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		// Inject 12 foreign hops (exceeding maxForwardHops = 10) with fake signatures
		now := time.Now().Unix()
		var fakeHops []string
		var fakeSigs []string
		for i := 1; i <= 12; i++ {
			h := fmt.Sprintf("external-node-%d", i)
			fakeHops = append(fakeHops, h)
			fakeSigs = append(fakeSigs, fmt.Sprintf("%s:%d:invalid-fake-signature-%d", h, now, i))
		}

		req := httptest.NewRequest("POST", "/api/v1/data", nil)
		req.Header.Set(HeaderForwardedBy, strings.Join(fakeHops, ", "))
		req.Header.Set(HeaderForwardedSig, strings.Join(fakeSigs, ", "))

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "spoofed foreign hops must not trigger 508 Loop Detected")
		assert.Equal(t, strings.Join(fakeHops, ", ")+", node-target", receivedForwardedBy)
	})

	t.Run("upstream reverse proxy failure returns 502 Bad Gateway with Retry-After 1", func(t *testing.T) {
		// Non-routable address to force proxy failure
		mock := &mockClusterState{
			isLeader:   false,
			leaderAddr: "127.0.0.1:54321", // unreachable port
			nodeID:     "node-proxy-fail",
		}

		app := fiber.New()
		app.Use(clusterRoutingMiddleware(mock))
		app.Post("/api/v1/action", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		})

		req := httptest.NewRequest("POST", "/api/v1/action", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
		assert.Equal(t, "1", resp.Header.Get("Retry-After"), "502 Bad Gateway must include Retry-After: 1 header")
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "failed to proxy request to cluster leader")
	})
}
