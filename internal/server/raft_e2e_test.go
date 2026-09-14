package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiclient "github.com/tasansga/terraform-provider-grantory/api/client"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/store"
)

func getFreePorts(t *testing.T, count int) []int {
	t.Helper()
	listeners := make([]net.Listener, count)
	ports := make([]int, count)
	for i := 0; i < count; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		listeners[i] = l
		ports[i] = l.Addr().(*net.TCPAddr).Port
	}
	for _, l := range listeners {
		require.NoError(t, l.Close())
	}
	return ports
}

func TestRaftThreeNodeClusterHTTPWorkflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	var servers []*Server
	var httpPorts, raftPorts []int
	for attempt := 0; attempt < 5; attempt++ {
		ports := getFreePorts(t, 6)
		httpPorts = ports[:3]
		raftPorts = ports[3:]
		peers := []string{
			fmt.Sprintf("node-1=127.0.0.1:%d", raftPorts[0]),
			fmt.Sprintf("node-2=127.0.0.1:%d", raftPorts[1]),
			fmt.Sprintf("node-3=127.0.0.1:%d", raftPorts[2]),
		}

		created := make([]*Server, 0, 3)
		var initErr error
		for i := 0; i < 3; i++ {
			dir := t.TempDir()
			cfg := config.Config{
				BindAddr:            fmt.Sprintf("127.0.0.1:%d", httpPorts[i]),
				Database:            dir,
				RaftBind:            fmt.Sprintf("127.0.0.1:%d", raftPorts[i]),
				RaftAdvertise:       fmt.Sprintf("127.0.0.1:%d", raftPorts[i]),
				RaftNodeID:          fmt.Sprintf("node-%d", i+1),
				RaftBootstrapExpect: 3,
				RaftPeers:           peers,
			}
			srv, err := New(ctx, cfg)
			if err != nil {
				initErr = err
				break
			}
			created = append(created, srv)
		}
		if initErr == nil && len(created) == 3 {
			servers = created
			break
		}
		for _, s := range created {
			_ = s.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.Len(t, servers, 3, "failed to initialize 3-node cluster")

	// Register HTTP address mappings across nodes for multi-node localhost resolution
	for _, srv := range servers {
		for j := 0; j < 3; j++ {
			srv.RaftNode().RegisterHTTPAddr(fmt.Sprintf("127.0.0.1:%d", raftPorts[j]), fmt.Sprintf("http://127.0.0.1:%d", httpPorts[j]))
			srv.RaftNode().RegisterHTTPAddr(fmt.Sprintf("node-%d", j+1), fmt.Sprintf("http://127.0.0.1:%d", httpPorts[j]))
		}
	}

	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			_ = s.Serve(ctx)
		}(srv)
	}

	t.Cleanup(func() {
		http.DefaultClient.CloseIdleConnections()
		cancel()
		for _, srv := range servers {
			_ = srv.Close()
		}
		wg.Wait()
	})

	// Wait for all HTTP listeners to become ready
	for _, port := range httpPorts {
		require.Eventually(t, func() bool {
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
			if err != nil {
				return false
			}
			ok := resp.StatusCode == http.StatusOK
			_ = resp.Body.Close()
			return ok
		}, 10*time.Second, 50*time.Millisecond, "HTTP server readiness check failed")
	}

	// Wait for cluster leader election and consensus agreement across nodes
	require.Eventually(t, func() bool {
		var leaderAddr string
		leaders := 0
		for _, srv := range servers {
			rn := srv.RaftNode()
			if rn == nil {
				return false
			}
			if rn.IsLeader() {
				leaders++
			}
			addr := rn.LeaderAddr()
			if addr == "" {
				return false
			}
			if leaderAddr == "" {
				leaderAddr = addr
			} else if leaderAddr != addr {
				return false
			}
		}
		return leaders == 1 && leaderAddr != ""
	}, 15*time.Second, 100*time.Millisecond, "leader election and convergence failed")

	// Identify leader and follower nodes
	var leaderSrv *Server
	var followerSrvs []*Server
	var leaderHTTP string
	var followerHTTP string
	var followerHTTPs []string

	for i, srv := range servers {
		url := fmt.Sprintf("http://127.0.0.1:%d", httpPorts[i])
		if srv.RaftNode().IsLeader() {
			leaderSrv = srv
			leaderHTTP = url
		} else {
			followerSrvs = append(followerSrvs, srv)
			followerHTTPs = append(followerHTTPs, url)
			if followerHTTP == "" {
				followerHTTP = url
			}
		}
	}
	require.NotNil(t, leaderSrv)
	require.Len(t, followerSrvs, 2)
	require.NotEmpty(t, leaderHTTP)
	require.NotEmpty(t, followerHTTP)
	require.Len(t, followerHTTPs, 2)

	// 1. Send POST write to FOLLOWER node (assert transparent proxying to Leader, commit, and 201 Created)
	hostPayload := map[string]any{
		"unique_key": "e2e-host-test",
		"labels": map[string]string{
			"env":  "production",
			"rack": "a1",
		},
	}
	hostBytes, err := json.Marshal(hostPayload)
	require.NoError(t, err)

	resp, err := http.Post(followerHTTP+"/hosts", "application/json", bytes.NewReader(hostBytes))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var createdHost apiclient.Host
	err = json.NewDecoder(resp.Body).Decode(&createdHost)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.NotEmpty(t, createdHost.ID)
	assert.Equal(t, "e2e-host-test", createdHost.UniqueKey)
	assert.Equal(t, "production", createdHost.Labels["env"])
	assert.Equal(t, "a1", createdHost.Labels["rack"])

	// 2. Create a request via POST /requests on a FOLLOWER node referencing that host
	reqPayload := map[string]any{
		"host_id":    createdHost.ID,
		"unique_key": "e2e-req-test",
		"payload": map[string]any{
			"role": "database-admin",
			"ttl":  "1h",
		},
		"labels": map[string]string{
			"team": "security",
		},
	}
	reqBytes, err := json.Marshal(reqPayload)
	require.NoError(t, err)

	resp, err = http.Post(followerHTTP+"/requests", "application/json", bytes.NewReader(reqBytes))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var createdReq apiclient.Request
	err = json.NewDecoder(resp.Body).Decode(&createdReq)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.NotEmpty(t, createdReq.ID)
	assert.Equal(t, createdHost.ID, createdReq.HostID)
	assert.Equal(t, "e2e-req-test", createdReq.UniqueKey)
	assert.Equal(t, 1, createdReq.Version)

	// 3. Immediately send GET read to FOLLOWER node (asserts linearizable read without staleness)
	getResp, err := http.Get(followerHTTP + "/requests/" + createdReq.ID)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, getResp.StatusCode)

	var fetchedReq apiclient.Request
	err = json.NewDecoder(getResp.Body).Decode(&fetchedReq)
	_ = getResp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, createdReq.ID, fetchedReq.ID)
	assert.Equal(t, createdHost.ID, fetchedReq.HostID)
	assert.Equal(t, "e2e-req-test", fetchedReq.UniqueKey)

	// Verify reading from all nodes in the cluster (both followers and leader)
	for _, port := range httpPorts {
		nodeURL := fmt.Sprintf("http://127.0.0.1:%d", port)
		r, err := http.Get(nodeURL + "/requests/" + createdReq.ID)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, r.StatusCode)
		var nodeReq apiclient.Request
		err = json.NewDecoder(r.Body).Decode(&nodeReq)
		_ = r.Body.Close()
		require.NoError(t, err)
		assert.Equal(t, createdReq.ID, nodeReq.ID)
	}

	// Verify local SQLite stores on all nodes eventually reflect replicated data
	for _, srv := range servers {
		require.Eventually(t, func() bool {
			st, err := srv.nsStore.StoreFor(ctx, store.DefaultNamespace)
			if err != nil {
				return false
			}
			_, err = st.GetHost(ctx, createdHost.ID)
			return err == nil
		}, 5*time.Second, 50*time.Millisecond)
	}

	// 4. Ed25519 signature enforcement & anti-replay across cluster nodes
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	pubHex := hex.EncodeToString(pub)

	// 4a. Create a host on a follower node with public_key and unique_key: "signed-host"
	signedHostPayload := map[string]any{
		"unique_key": "signed-host",
		"public_key": pubHex,
		"labels": map[string]string{
			"env": "production",
		},
	}
	signedHostBytes, err := json.Marshal(signedHostPayload)
	require.NoError(t, err)

	resp, err = http.Post(followerHTTP+"/hosts", "application/json", bytes.NewReader(signedHostBytes))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var signedHost apiclient.Host
	err = json.NewDecoder(resp.Body).Decode(&signedHost)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.NotEmpty(t, signedHost.ID)
	assert.Equal(t, "signed-host", signedHost.UniqueKey)
	assert.Equal(t, pubHex, signedHost.PublicKey)

	// Prepare signed request payload referencing signedHost
	signedReqPayload := map[string]any{
		"host_id":    signedHost.ID,
		"unique_key": "signed-req-raft",
		"payload": map[string]any{
			"role": "cluster-admin",
		},
	}
	signedReqBytes, err := json.Marshal(signedReqPayload)
	require.NoError(t, err)

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := "nonce-raft-1"
	content := fmt.Sprintf("%s:%s:%s:%s:%s", timestamp, nonce, "POST", "/requests", string(signedReqBytes))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(content)))

	// 4b. Send request with wrong signature to Follower node -> 401 Unauthorized
	wrongSigReq, err := http.NewRequest(http.MethodPost, followerHTTP+"/requests", bytes.NewReader(signedReqBytes))
	require.NoError(t, err)
	wrongSigReq.Header.Set("Content-Type", "application/json")
	wrongSigReq.Header.Set("X-Grantory-Timestamp", timestamp)
	wrongSigReq.Header.Set("X-Grantory-Nonce", "nonce-wrong-sig")
	wrongSigReq.Header.Set("X-Grantory-Signature", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))

	resp, err = http.DefaultClient.Do(wrongSigReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_ = resp.Body.Close()

	// 4c. Send POST /requests to Follower node with valid signature
	// Follower proxies request AND signature headers to leader, returns 201 Created
	validSigReq, err := http.NewRequest(http.MethodPost, followerHTTP+"/requests", bytes.NewReader(signedReqBytes))
	require.NoError(t, err)
	validSigReq.Header.Set("Content-Type", "application/json")
	validSigReq.Header.Set("X-Grantory-Timestamp", timestamp)
	validSigReq.Header.Set("X-Grantory-Nonce", nonce)
	validSigReq.Header.Set("X-Grantory-Signature", sig)

	resp, err = http.DefaultClient.Do(validSigReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var createdSignedReq apiclient.Request
	err = json.NewDecoder(resp.Body).Decode(&createdSignedReq)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.NotEmpty(t, createdSignedReq.ID)
	assert.Equal(t, signedHost.ID, createdSignedReq.HostID)
	assert.Equal(t, "signed-req-raft", createdSignedReq.UniqueKey)

	// 4d. Replay attack test: send exact same request with exact same nonce to ANOTHER Follower node
	require.GreaterOrEqual(t, len(followerHTTPs), 2)
	otherFollowerHTTP := followerHTTPs[1]

	replayReq, err := http.NewRequest(http.MethodPost, otherFollowerHTTP+"/requests", bytes.NewReader(signedReqBytes))
	require.NoError(t, err)
	replayReq.Header.Set("Content-Type", "application/json")
	replayReq.Header.Set("X-Grantory-Timestamp", timestamp)
	replayReq.Header.Set("X-Grantory-Nonce", nonce)
	replayReq.Header.Set("X-Grantory-Signature", sig)

	resp, err = http.DefaultClient.Do(replayReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "replay attack should be rejected across cluster nodes")
	_ = resp.Body.Close()

	// 5. Test multi-namespace support (e.g. REMOTE_USER: tenant_b header)
	tenantBHostPayload := map[string]any{
		"unique_key": "tenant-b-host",
		"labels": map[string]string{
			"env": "staging",
		},
	}
	tenantBHostBytes, err := json.Marshal(tenantBHostPayload)
	require.NoError(t, err)

	httpReq, err := http.NewRequest(http.MethodPost, followerHTTP+"/hosts", bytes.NewReader(tenantBHostBytes))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("REMOTE_USER", "tenant_b")

	resp, err = http.DefaultClient.Do(httpReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var tenantBHost apiclient.Host
	err = json.NewDecoder(resp.Body).Decode(&tenantBHost)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.NotEmpty(t, tenantBHost.ID)
	assert.Equal(t, "tenant-b-host", tenantBHost.UniqueKey)

	// Create request in tenant_b referencing tenantBHost.ID
	tenantBReqPayload := map[string]any{
		"host_id":    tenantBHost.ID,
		"unique_key": "tenant-b-req",
		"payload": map[string]any{
			"namespace": "tenant_b",
		},
	}
	tenantBReqBytes, err := json.Marshal(tenantBReqPayload)
	require.NoError(t, err)

	httpReq, err = http.NewRequest(http.MethodPost, followerHTTP+"/requests", bytes.NewReader(tenantBReqBytes))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("REMOTE_USER", "tenant_b")

	resp, err = http.DefaultClient.Do(httpReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var tenantBReq apiclient.Request
	err = json.NewDecoder(resp.Body).Decode(&tenantBReq)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.NotEmpty(t, tenantBReq.ID)

	// Fetch request with REMOTE_USER: tenant_b on follower -> 200 OK
	httpReq, err = http.NewRequest(http.MethodGet, followerHTTP+"/requests/"+tenantBReq.ID, nil)
	require.NoError(t, err)
	httpReq.Header.Set("REMOTE_USER", "tenant_b")

	resp, err = http.DefaultClient.Do(httpReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var fetchedTenantBReq apiclient.Request
	err = json.NewDecoder(resp.Body).Decode(&fetchedTenantBReq)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, tenantBReq.ID, fetchedTenantBReq.ID)

	// Fetch tenant_b request WITHOUT REMOTE_USER (default namespace) -> 404 Not Found
	resp, err = http.Get(followerHTTP + "/requests/" + tenantBReq.ID)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	_ = resp.Body.Close()

	// Fetch default namespace request with REMOTE_USER: tenant_b -> 404 Not Found
	httpReq, err = http.NewRequest(http.MethodGet, followerHTTP+"/requests/"+createdReq.ID, nil)
	require.NoError(t, err)
	httpReq.Header.Set("REMOTE_USER", "tenant_b")

	resp, err = http.DefaultClient.Do(httpReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	_ = resp.Body.Close()

	// 6. Test cluster status endpoint GET /api/v1/cluster/status across leader and followers
	leaderStatusResp, err := http.Get(leaderHTTP + "/api/v1/cluster/status")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, leaderStatusResp.StatusCode)

	var leaderStatus ClusterStatusResponse
	err = json.NewDecoder(leaderStatusResp.Body).Decode(&leaderStatus)
	_ = leaderStatusResp.Body.Close()
	require.NoError(t, err)
	assert.True(t, leaderStatus.IsLeader)
	assert.Equal(t, "leader", leaderStatus.Role)
	assert.Equal(t, leaderSrv.RaftNode().NodeID(), leaderStatus.NodeID)
	assert.NotEmpty(t, leaderStatus.LeaderAddr)

	for _, fHTTP := range followerHTTPs {
		fStatusResp, err := http.Get(fHTTP + "/api/v1/cluster/status")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, fStatusResp.StatusCode)

		var followerStatus ClusterStatusResponse
		err = json.NewDecoder(fStatusResp.Body).Decode(&followerStatus)
		_ = fStatusResp.Body.Close()
		require.NoError(t, err)
		assert.False(t, followerStatus.IsLeader)
		assert.Equal(t, "follower", followerStatus.Role)
		assert.NotEmpty(t, followerStatus.NodeID)
		assert.NotEqual(t, leaderStatus.NodeID, followerStatus.NodeID)
		assert.Equal(t, leaderStatus.LeaderAddr, followerStatus.LeaderAddr)
	}

	// 7. Ensure clean shutdown of all servers on test completion
	http.DefaultClient.CloseIdleConnections()
	cancel()
	for _, srv := range servers {
		require.NoError(t, srv.Close())
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Cleanly shut down
	case <-time.After(15 * time.Second):
		t.Fatal("servers failed to shut down cleanly within 15 seconds")
	}
}
