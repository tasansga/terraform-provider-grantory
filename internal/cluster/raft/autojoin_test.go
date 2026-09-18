package raft

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
)

func TestDiscoverActiveLeader_LeaderDirectly(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/status" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "node-1",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.1:9300",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	cfg := config.Config{
		RaftClusterSecret: "test-secret",
	}
	peers := []parsedPeerConfig{
		{
			id:       "node-1",
			raftAddr: "127.0.0.1:9300",
			httpAddr: ts.URL,
		},
	}
	localAliases := map[string]bool{
		"127.0.0.1:9301": true,
	}

	leaderURL := DiscoverActiveLeader(context.Background(), cfg, peers, localAliases, nil)
	assert.Equal(t, ts.URL, leaderURL)
}

func TestDiscoverActiveLeader_IgnoresStandaloneNode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/status" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "standalone",
				Role:       "standalone",
				IsLeader:   true,
				LeaderAddr: "",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	cfg := config.Config{}
	peers := []parsedPeerConfig{
		{
			id:       "standalone",
			raftAddr: "127.0.0.2:9300",
			httpAddr: ts.URL,
		},
	}
	localAliases := map[string]bool{
		"127.0.0.1:9300": true,
	}

	leaderURL := DiscoverActiveLeader(context.Background(), cfg, peers, localAliases, nil)
	assert.Empty(t, leaderURL, "standalone node should not be identified as an active Raft leader")
}

func TestDiscoverActiveLeader_LeaderViaFollower(t *testing.T) {
	followerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/status" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "node-2",
				Role:       "follower",
				IsLeader:   false,
				LeaderAddr: "127.0.0.1:9301",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer followerServer.Close()

	leaderServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/status" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "node-1",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.1:9301",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer leaderServer.Close()

	cfg := config.Config{}
	peers := []parsedPeerConfig{
		{
			id:       "node-2",
			raftAddr: "127.0.0.1:9302",
			httpAddr: followerServer.URL,
		},
		{
			id:       "node-1",
			raftAddr: "127.0.0.1:9301",
			httpAddr: leaderServer.URL,
		},
	}
	localAliases := map[string]bool{
		"127.0.0.1:9303": true,
	}

	leaderURL := DiscoverActiveLeader(context.Background(), cfg, peers, localAliases, nil)
	assert.Equal(t, leaderServer.URL, leaderURL)
}

func TestDiscoverActiveLeader_NoLeader(t *testing.T) {
	offlineServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer offlineServer.Close()

	cfg := config.Config{}
	peers := []parsedPeerConfig{
		{
			id:       "node-1",
			raftAddr: "127.0.0.1:9301",
			httpAddr: offlineServer.URL,
		},
	}
	localAliases := map[string]bool{
		"127.0.0.1:9302": true,
	}

	leaderURL := DiscoverActiveLeader(context.Background(), cfg, peers, localAliases, nil)
	assert.Empty(t, leaderURL)
}

func TestRequestClusterJoin_Success(t *testing.T) {
	var receivedSecret string
	var receivedBearer string
	var receivedPayload ClusterJoinRequest

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/join" && r.Method == http.MethodPost {
			receivedSecret = r.Header.Get("X-Grantory-Cluster-Secret")
			receivedBearer = r.Header.Get("Authorization")
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &receivedPayload)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	client, err := BuildClusterHTTPClient(config.Config{})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = RequestClusterJoin(ctx, client, ts.URL, "node-2", "127.0.0.1:9302", "https://127.0.0.1:8443", "test-secret")
	require.NoError(t, err)
	assert.Empty(t, receivedSecret)
	assert.Equal(t, "Bearer test-secret", receivedBearer)
	assert.Equal(t, "node-2", receivedPayload.NodeID)
	assert.Equal(t, "127.0.0.1:9302", receivedPayload.Address)
	assert.Equal(t, "https://127.0.0.1:8443", receivedPayload.HTTPAddress)
}

func TestRequestClusterJoin_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`unauthorized`))
	}))
	defer ts.Close()

	client, err := BuildClusterHTTPClient(config.Config{})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = RequestClusterJoin(ctx, client, ts.URL, "node-2", "127.0.0.1:9302", "https://127.0.0.1:8443", "wrong-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 401")
	assert.Contains(t, err.Error(), "unauthorized")
}

func TestCandidateHTTPURLs(t *testing.T) {
	p := parsedPeerConfig{
		raftAddr: "10.0.0.5:8300",
		httpAddr: "https://10.0.0.5:8443",
	}
	cfg := config.Config{}
	urls := candidateHTTPURLsForEndpoint(p, p.raftAddr, cfg, nil)
	require.NotEmpty(t, urls)
	assert.Equal(t, "https://10.0.0.5:8443", urls[0])
	assert.Contains(t, urls, "http://10.0.0.5:8080")
}

func TestCandidateHTTPURLs_WithResolvedIPs(t *testing.T) {
	p := parsedPeerConfig{
		raftAddr:    "grantory-headless:9300",
		resolvedIPs: []string{"10.0.0.1:9300", "10.0.0.2:9300"},
	}
	cfg := config.Config{}
	urls1 := candidateHTTPURLsForEndpoint(p, p.resolvedIPs[0], cfg, nil)
	require.NotEmpty(t, urls1)
	assert.Contains(t, urls1, "http://10.0.0.1:8080")

	urls2 := candidateHTTPURLsForEndpoint(p, p.resolvedIPs[1], cfg, nil)
	require.NotEmpty(t, urls2)
	assert.Contains(t, urls2, "http://10.0.0.2:8080")
}

func TestCandidateHTTPURLs_DecoupledHTTPAddr(t *testing.T) {
	p := parsedPeerConfig{
		raftAddr:    "cluster-peers:9300",
		httpAddr:    "https://remote-leader:8443",
		resolvedIPs: []string{"127.0.0.1:9300", "127.0.0.2:9300"},
	}
	cfg := config.Config{}
	localAliases := map[string]bool{
		"127.0.0.1:9300": true,
	}
	// The first resolved IP is local (127.0.0.1:9300), remote endpoint is 127.0.0.2:9300
	urls := candidateHTTPURLsForEndpoint(p, "127.0.0.2:9300", cfg, localAliases)
	assert.Contains(t, urls, "https://remote-leader:8443")
	assert.Contains(t, urls, "http://127.0.0.2:8080")

	// When p.httpAddr is a local HTTP address, it should not be included
	pLocal := parsedPeerConfig{
		raftAddr:    "cluster-peers:9300",
		httpAddr:    "http://127.0.0.1:8080",
		resolvedIPs: []string{"127.0.0.1:9300", "127.0.0.2:9300"},
	}
	urlsLocal := candidateHTTPURLsForEndpoint(pLocal, "127.0.0.2:9300", cfg, localAliases)
	assert.NotContains(t, urlsLocal, "http://127.0.0.1:8080")
}

func TestDiscoverActiveLeader_HeadlessDNS(t *testing.T) {
	leaderListener, err := net.Listen("tcp", "127.0.0.2:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(leaderListener.Addr().String())
	require.NoError(t, err)

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/status" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "node-2",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.2:9300",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})}
	go func() { _ = server.Serve(leaderListener) }()
	defer func() { _ = server.Close() }()

	cfg := config.Config{
		BindAddr: "127.0.0.1:" + port,
	}
	peers := []parsedPeerConfig{
		{
			raftAddr:    "grantory-headless:9300",
			resolvedIPs: []string{"127.0.0.1:9300", "127.0.0.2:9300"},
		},
	}
	localAliases := map[string]bool{
		"127.0.0.1:9300": true,
	}

	resolver := newDNSResolver(time.Minute, func(host string) ([]net.IP, error) {
		if host == "grantory-headless" {
			return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")}, nil
		}
		return nil, net.UnknownNetworkError("unknown")
	})

	leaderURL := DiscoverActiveLeader(context.Background(), cfg, peers, localAliases, resolver)
	assert.Equal(t, "http://127.0.0.2:"+port, leaderURL)
}

func TestDiscoverActiveLeader_FollowerDoesNotReturnFollowerURL(t *testing.T) {
	t.Run("leader reachable without explicit httpAddr", func(t *testing.T) {
		leaderListener, err := net.Listen("tcp", "127.0.0.4:0")
		require.NoError(t, err)
		_, port, err := net.SplitHostPort(leaderListener.Addr().String())
		require.NoError(t, err)

		leaderServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/cluster/status" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
					NodeID:     "node-leader",
					Role:       "leader",
					IsLeader:   true,
					LeaderAddr: "127.0.0.4:9300",
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})}
		go func() { _ = leaderServer.Serve(leaderListener) }()
		defer func() { _ = leaderServer.Close() }()

		followerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/cluster/status" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
					NodeID:     "node-follower",
					Role:       "follower",
					IsLeader:   false,
					LeaderAddr: "127.0.0.4:9300",
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer followerServer.Close()

		cfg := config.Config{
			BindAddr: "127.0.0.1:" + port,
		}
		peers := []parsedPeerConfig{
			{
				id:       "node-follower",
				raftAddr: followerServer.Listener.Addr().String(),
				httpAddr: followerServer.URL,
			},
			{
				id:       "node-leader",
				raftAddr: "127.0.0.4:9300",
			},
		}
		localAliases := map[string]bool{
			"127.0.0.5:9300": true,
		}

		leaderURL := DiscoverActiveLeader(context.Background(), cfg, peers, localAliases, nil)
		assert.Equal(t, "http://127.0.0.4:"+port, leaderURL)
		assert.NotEqual(t, followerServer.URL, leaderURL)
	})

	t.Run("reported leader unreachable does not return follower URL", func(t *testing.T) {
		followerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/cluster/status" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
					NodeID:     "node-follower",
					Role:       "follower",
					IsLeader:   false,
					LeaderAddr: "127.0.0.99:9300",
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer followerServer.Close()

		cfg := config.Config{}
		peers := []parsedPeerConfig{
			{
				id:       "node-follower",
				raftAddr: followerServer.Listener.Addr().String(),
				httpAddr: followerServer.URL,
			},
			{
				id:       "node-leader",
				raftAddr: "127.0.0.99:9300",
			},
		}
		localAliases := map[string]bool{
			"127.0.0.5:9300": true,
		}

		leaderURL := DiscoverActiveLeader(context.Background(), cfg, peers, localAliases, nil)
		assert.Empty(t, leaderURL)
		assert.NotEqual(t, followerServer.URL, leaderURL)
	})
}

func TestDetermineLocalHTTPAddr_UnspecifiedIP(t *testing.T) {
	node := &RaftNode{
		cfg: config.Config{
			RaftAdvertise: "",
			RaftBind:      "0.0.0.0:9300",
		},
		httpPort: "8080",
	}
	addr := node.determineLocalHTTPAddr(nil, nil, "9300", false, "")
	assert.Empty(t, addr, "should return empty string for 0.0.0.0 and NOT synthesize http://0.0.0.0:8080")

	nodeV6 := &RaftNode{
		cfg: config.Config{
			RaftAdvertise: "",
			RaftBind:      "[::]:9300",
		},
		httpPort: "8080",
	}
	addrV6 := nodeV6.determineLocalHTTPAddr(nil, nil, "9300", true, "")
	assert.Empty(t, addrV6, "should return empty string for [::]")
}

func TestDetermineLocalHTTPAddr_IPv6(t *testing.T) {
	node := &RaftNode{
		cfg: config.Config{
			RaftAdvertise: "[2001:db8::1]:9300",
		},
		httpPort: "8080",
	}
	addr := node.determineLocalHTTPAddr(nil, nil, "9300", true, "")
	assert.Equal(t, "http://[2001:db8::1]:8080", addr)

	nodeTLS := &RaftNode{
		cfg: config.Config{
			RaftAdvertise: "[2001:db8::1]:9300",
		},
		tlsEnabled: true,
		httpPort:   "8443",
	}
	addrTLS := nodeTLS.determineLocalHTTPAddr(nil, nil, "9300", true, "")
	assert.Equal(t, "https://[2001:db8::1]:8443", addrTLS)
}

func TestDetermineLocalHTTPAddr_DisabledListeners(t *testing.T) {
	node := &RaftNode{
		cfg: config.Config{
			RaftAdvertise: "127.0.0.1:9300",
			BindAddr:      "off",
			TLSBind:       "off",
		},
	}
	addr := node.determineLocalHTTPAddr(nil, nil, "9300", false, "")
	assert.Empty(t, addr, "should return empty string when HTTP and TLS listeners are disabled")

	nodeNoTLS := &RaftNode{
		cfg: config.Config{
			RaftAdvertise: "127.0.0.1:9300",
			BindAddr:      "off",
		},
	}
	addrNoTLS := nodeNoTLS.determineLocalHTTPAddr(nil, nil, "9300", false, "")
	assert.Empty(t, addrNoTLS, "should return empty string when BindAddr is off and TLS is unconfigured")
}

func TestDetermineLocalHTTPAddr_UsesAdvAddr(t *testing.T) {
	t.Parallel()
	node := &RaftNode{
		cfg: config.Config{
			BindAddr: ":8080",
		},
	}
	addr := node.determineLocalHTTPAddr(nil, nil, "9300", false, "192.168.1.50:9300")
	assert.Equal(t, "http://192.168.1.50:8080", addr)
}

func TestCandidateHTTPURLs_CustomPortsAndIPv6(t *testing.T) {
	cfg := config.Config{
		BindAddr: "0.0.0.0:9090",
		TLSBind:  "0.0.0.0:9443",
		TLSCert:  "test.crt",
	}
	p := parsedPeerConfig{}
	ep := "[2001:db8::2]:9300"
	urls := candidateHTTPURLsForEndpoint(p, ep, cfg, nil)

	assert.Contains(t, urls, "http://[2001:db8::2]:9090")
	assert.Contains(t, urls, "https://[2001:db8::2]:9443")
}

func TestBuildClusterHTTPClient_ReturnsErrorOnMissingFiles(t *testing.T) {
	client1, err1 := BuildClusterHTTPClient(config.Config{RaftCAFile: "/nonexistent/path/to/ca.pem"})
	require.Error(t, err1)
	assert.Nil(t, client1)
	assert.Contains(t, err1.Error(), "build cluster TLS config: read raft CA file")

	client2, err2 := BuildClusterHTTPClient(config.Config{TLSCert: "/nonexistent/path/to/tls.crt"})
	require.Error(t, err2)
	assert.Nil(t, client2)
	assert.Contains(t, err2.Error(), "build cluster TLS config: read TLS cert file")

	client3, err3 := BuildClusterHTTPClient(config.Config{RaftCertFile: "/nonexistent/path/to/raft.crt", RaftKeyFile: "/nonexistent/path/to/raft.key"})
	require.Error(t, err3)
	assert.Nil(t, client3)
	assert.Contains(t, err3.Error(), "build cluster TLS config: load raft client keypair")
}

func TestStartAutoJoinRetry_DynamicLeaderFailover(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var mu sync.Mutex
	var server2Joined bool

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server 1 is stepping down / unavailable
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cluster/status":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "node-2",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.2:9302",
			})
		case "/api/v1/cluster/join":
			mu.Lock()
			server2Joined = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server2.Close()

	node := &RaftNode{
		cfg:        config.Config{},
		nodeCtx:    ctx,
		nodeCancel: cancel,
		parsedPeers: []parsedPeerConfig{
			{
				id:       "node-1",
				raftAddr: "127.0.0.1:9301",
				httpAddr: server1.URL,
			},
			{
				id:       "node-2",
				raftAddr: "127.0.0.2:9302",
				httpAddr: server2.URL,
			},
		},
		localAliases: map[string]bool{
			"127.0.0.3:9303": true,
		},
		autoJoinBackoff: func(attempt int) time.Duration {
			return 5 * time.Millisecond
		},
	}

	// Start auto-join initially pointing to server1 which is failing
	node.startAutoJoinRetry(server1.URL, "node-3", "127.0.0.3:9303", "http://127.0.0.3:8080")

	mu.Lock()
	joined := server2Joined
	mu.Unlock()

	assert.True(t, joined, "node should have re-discovered server2 as the leader and joined it")
}

func TestStartAutoJoinRetry_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	node := &RaftNode{
		cfg:        config.Config{},
		nodeCtx:    ctx,
		nodeCancel: cancel,
		autoJoinBackoff: func(attempt int) time.Duration {
			return 500 * time.Millisecond
		},
	}

	done := make(chan struct{})
	go func() {
		node.startAutoJoinRetry(ts.URL, "node-1", "127.0.0.1:9301", "http://127.0.0.1:8080")
		close(done)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// success: terminated promptly on cancellation
	case <-time.After(1 * time.Second):
		t.Fatal("startAutoJoinRetry did not terminate promptly upon context cancellation")
	}
}

func TestQueryClusterStatus_BoundedBody(t *testing.T) {
	largeData := strings.Repeat("A", 2*1024*1024)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"node_id":"` + largeData + `","role":"leader","is_leader":true}`))
	}))
	defer ts.Close()

	client, err := BuildClusterHTTPClient(config.Config{})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status, err := queryClusterStatus(ctx, client, ts.URL, "")
	require.Error(t, err, "expected error due to body truncation at 1MB")
	assert.Nil(t, status)
}

func TestRequestClusterJoin_BoundedBody(t *testing.T) {
	largeError := strings.Repeat("E", 2*1024*1024)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(largeError))
	}))
	defer ts.Close()

	client, err := BuildClusterHTTPClient(config.Config{})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = RequestClusterJoin(ctx, client, ts.URL, "node-1", "127.0.0.1:9301", "http://127.0.0.1:8080", "")
	require.Error(t, err)
	assert.LessOrEqual(t, len(err.Error()), (1<<20)+100, "error message body should be bounded to 1MB")
}

type trackingReadCloser struct {
	io.Reader
	bytesRead int
	closed    bool
}

func (tr *trackingReadCloser) Read(p []byte) (int, error) {
	n, err := tr.Reader.Read(p)
	tr.bytesRead += n
	return n, err
}

func (tr *trackingReadCloser) Close() error {
	tr.closed = true
	return nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestQueryClusterStatus_DrainsNon200Body(t *testing.T) {
	tracker := &trackingReadCloser{
		Reader: strings.NewReader("server error details that should be drained"),
	}
	client := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       tracker,
				Header:     make(http.Header),
			}, nil
		}),
	}

	status, err := queryClusterStatus(context.Background(), client, "http://127.0.0.1:8080", "")
	require.Error(t, err)
	assert.Nil(t, status)
	assert.Greater(t, tracker.bytesRead, 0, "response body should be drained on non-200 status")
	assert.True(t, tracker.closed, "response body should be closed")
}

func TestQueryClusterStatus_DrainsRemainderOfNon200Body(t *testing.T) {
	largeBody := strings.Repeat("X", 8192)
	tracker := &trackingReadCloser{
		Reader: strings.NewReader(largeBody),
	}
	client := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       tracker,
				Header:     make(http.Header),
			}, nil
		}),
	}

	status, err := queryClusterStatus(context.Background(), client, "http://127.0.0.1:8080", "")
	require.Error(t, err)
	assert.Nil(t, status)
	assert.Equal(t, 8192, tracker.bytesRead, "entire error response body beyond 4096 bytes should be drained")
	assert.True(t, tracker.closed, "response body should be closed")
}

func TestRequestClusterJoin_DrainsRemainderOfNon200Body(t *testing.T) {
	totalSize := (1 << 20) + 8192
	largeBody := strings.Repeat("Y", totalSize)
	tracker := &trackingReadCloser{
		Reader: strings.NewReader(largeBody),
	}
	client := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       tracker,
				Header:     make(http.Header),
			}, nil
		}),
	}

	err := RequestClusterJoin(context.Background(), client, "http://127.0.0.1:8080", "node-1", "127.0.0.1:9301", "http://127.0.0.1:8080", "")
	require.Error(t, err)
	assert.Equal(t, totalSize, tracker.bytesRead, "entire error response body should be drained")
	assert.True(t, tracker.closed, "response body should be closed")
}

func TestDiscoverActiveLeader_ConcurrentProbing_DoesNotTimeoutOnDeadPeers(t *testing.T) {
	hangServer1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer hangServer1.Close()

	hangServer2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer hangServer2.Close()

	leaderServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/status" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "node-leader",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.3:9303",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer leaderServer.Close()

	cfg := config.Config{}
	peers := []parsedPeerConfig{
		{
			id:       "node-hang1",
			raftAddr: "127.0.0.1:9301",
			httpAddr: hangServer1.URL,
		},
		{
			id:       "node-hang2",
			raftAddr: "127.0.0.2:9302",
			httpAddr: hangServer2.URL,
		},
		{
			id:       "node-leader",
			raftAddr: "127.0.0.3:9303",
			httpAddr: leaderServer.URL,
		},
	}
	localAliases := map[string]bool{
		"127.0.0.99:9300": true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	start := time.Now()
	leaderURL := DiscoverActiveLeader(ctx, cfg, peers, localAliases, nil)
	elapsed := time.Since(start)

	assert.Equal(t, leaderServer.URL, leaderURL)
	assert.Less(t, elapsed, 1500*time.Millisecond, "concurrent probing should discover the leader without waiting for dead peers to time out")
}

func TestCandidateHTTPURLsForEndpoint_FiltersLocalHTTPPort(t *testing.T) {
	p := parsedPeerConfig{
		raftAddr: "cluster-peers:9300",
		httpAddr: "http://127.0.0.1:8080",
	}
	cfg := config.Config{}
	localAliases := map[string]bool{
		"127.0.0.1:9300": true,
	}
	urls := candidateHTTPURLsForEndpoint(p, "127.0.0.2:9300", cfg, localAliases)
	assert.NotContains(t, urls, "http://127.0.0.1:8080", "local HTTP port should be filtered out even if localAliases has Raft port 9300")
	assert.Contains(t, urls, "http://127.0.0.2:8080")
}

func TestCandidateHTTPURLsForAddr_BindAddrOff(t *testing.T) {
	cfg := config.Config{
		BindAddr: "off",
		TLSBind:  "0.0.0.0:8443",
		TLSCert:  "test.crt",
	}
	urls := candidateHTTPURLsForAddr("10.0.0.1", cfg)
	assert.Contains(t, urls, "https://10.0.0.1:8443")
	assert.NotContains(t, urls, "http://10.0.0.1:8080", "http scheme should not be generated when BindAddr is 'off'")
}

func TestIsClusterLeader(t *testing.T) {
	assert.False(t, isClusterLeader(nil))
	assert.False(t, isClusterLeader(&ClusterStatusResponse{IsLeader: false, Role: "leader", LeaderAddr: "127.0.0.1:9300"}))
	assert.False(t, isClusterLeader(&ClusterStatusResponse{IsLeader: true, Role: "follower", LeaderAddr: "127.0.0.1:9300"}))
	assert.False(t, isClusterLeader(&ClusterStatusResponse{IsLeader: true, Role: "standalone", LeaderAddr: "127.0.0.1:9300"}))
	assert.False(t, isClusterLeader(&ClusterStatusResponse{IsLeader: true, Role: "leader", LeaderAddr: ""}))
	assert.False(t, isClusterLeader(&ClusterStatusResponse{IsLeader: true, Role: "leader", LeaderAddr: "   "}))
	assert.True(t, isClusterLeader(&ClusterStatusResponse{IsLeader: true, Role: "leader", LeaderAddr: "127.0.0.1:9300"}))
}

func TestDiscoverLeader_ImmediateJoinOnNewLeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var mu sync.Mutex
	var joinedNewLeader bool

	deadLeader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer deadLeader.Close()

	newLeader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cluster/status":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "new-leader-node",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.2:9302",
			})
		case "/api/v1/cluster/join":
			mu.Lock()
			joinedNewLeader = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer newLeader.Close()

	node := &RaftNode{
		cfg:        config.Config{},
		nodeCtx:    ctx,
		nodeCancel: cancel,
		parsedPeers: []parsedPeerConfig{
			{
				id:       "dead-leader",
				raftAddr: "127.0.0.1:9301",
				httpAddr: deadLeader.URL,
			},
			{
				id:       "new-leader",
				raftAddr: "127.0.0.2:9302",
				httpAddr: newLeader.URL,
			},
		},
		localAliases: map[string]bool{
			"127.0.0.3:9303": true,
		},
		// High backoff: If immediate join is skipped, test will timeout before backoff finishes
		autoJoinBackoff: func(attempt int) time.Duration {
			return 10 * time.Minute
		},
	}

	done := make(chan struct{})
	go func() {
		node.startAutoJoinRetry(deadLeader.URL, "node-3", "127.0.0.3:9303", "http://127.0.0.3:8080")
		close(done)
	}()

	select {
	case <-done:
		// Succeeded immediately without waiting for backoff
	case <-time.After(1 * time.Second):
		t.Fatal("startAutoJoinRetry did not immediately join new leader and got stuck in backoff")
	}

	mu.Lock()
	joined := joinedNewLeader
	mu.Unlock()
	assert.True(t, joined, "should have immediately joined new leader upon discovery")
}

func TestBuildClusterHTTPClient_ReturnsErrorOnInvalidTLSConfig(t *testing.T) {
	client, err := BuildClusterHTTPClient(config.Config{
		RaftCAFile: "/nonexistent/path/to/ca.pem",
	})
	require.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "build cluster TLS config: read raft CA file:")

	client, err = BuildClusterHTTPClient(config.Config{
		RaftCertFile: "/some/cert.pem",
	})
	require.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "build cluster TLS config: both raft-cert-file and raft-key-file must be specified")
}

func TestResolveLeaderCandidateURLs_FiltersLocalAddresses(t *testing.T) {
	cfg := config.Config{
		BindAddr: "127.0.0.1:8080",
	}
	localAliases := map[string]bool{
		"127.0.0.1:8080": true,
		"127.0.0.1":      true,
		"10.0.0.1:9090":  true,
	}
	peers := []parsedPeerConfig{
		{
			id:       "node-local",
			raftAddr: "10.0.0.1:9090",
			httpAddr: "http://127.0.0.1:8080",
		},
		{
			id:       "node-remote",
			raftAddr: "10.0.0.2:9090",
			httpAddr: "http://10.0.0.2:8080",
		},
	}

	urls := resolveLeaderCandidateURLs("10.0.0.1:9090", peers, cfg, localAliases)
	assert.NotContains(t, urls, "http://127.0.0.1:8080", "local URL should be filtered out")

	urlsRemote := resolveLeaderCandidateURLs("10.0.0.2:9090", peers, cfg, localAliases)
	assert.Contains(t, urlsRemote, "http://10.0.0.2:8080", "remote URL should be preserved")
}

func TestStartAutoJoinRetry_FlushesResolverCacheToDiscoverNewPeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var lookupCount atomic.Int64
	mockLookup := func(host string) ([]net.IP, error) {
		calls := lookupCount.Add(1)
		if calls == 1 {
			// Returns an IP that immediately refuses connections on loopback
			return []net.IP{net.ParseIP("127.0.0.240")}, nil
		}
		return []net.IP{net.ParseIP("127.0.0.2")}, nil
	}

	resolver := newDNSResolver(1*time.Hour, mockLookup)

	leaderListener, err := net.Listen("tcp", "127.0.0.2:0")
	require.NoError(t, err)
	defer func() { _ = leaderListener.Close() }()

	leaderServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cluster/status":
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "leader-node",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.2:9302",
			})
		case "/api/v1/cluster/join":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go func() { _ = leaderServer.Serve(leaderListener) }()
	defer func() { _ = leaderServer.Close() }()

	leaderURL := "http://" + leaderListener.Addr().String()

	node := &RaftNode{
		cfg: config.Config{
			RaftPeers: []string{"headless.example.com:9302"},
			RaftPeerHTTPAddrs: []string{
				"127.0.0.2:9302=" + leaderURL,
			},
		},
		nodeCtx:      ctx,
		nodeCancel:   cancel,
		resolver:     resolver,
		defPort:      "9302",
		localAliases: map[string]bool{"127.0.0.1:9301": true},
		autoJoinBackoff: func(attempt int) time.Duration {
			return 10 * time.Millisecond
		},
	}

	done := make(chan struct{})
	go func() {
		node.startAutoJoinRetry("", "node-1", "127.0.0.1:9301", "http://127.0.0.1:8080")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for auto-join retry")
	}

	assert.Greater(t, lookupCount.Load(), int64(1), "DNS resolver cache should be flushed on retry to pick up new peer IPs")
	assert.Equal(t, "joined", node.AutoJoinStatus())
}

func TestBearerTokenFormatting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		tokenInput string
		wantHeader string
	}{
		{
			name:       "raw secret without prefix",
			tokenInput: "my-secret-token",
			wantHeader: "Bearer my-secret-token",
		},
		{
			name:       "already prefixed with Bearer",
			tokenInput: "Bearer my-secret-token",
			wantHeader: "Bearer my-secret-token",
		},
		{
			name:       "prefixed with lowercase bearer",
			tokenInput: "bearer my-secret-token",
			wantHeader: "Bearer my-secret-token",
		},
		{
			name:       "prefixed with uppercase BEARER and whitespace",
			tokenInput: "  BEARER   my-secret-token  ",
			wantHeader: "Bearer my-secret-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedStatusAuth string
			statusSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedStatusAuth = r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
					NodeID:   "leader",
					IsLeader: true,
					Role:     "leader",
				})
			}))
			defer statusSrv.Close()

			ctx := context.Background()
			client := statusSrv.Client()

			_, err := queryClusterStatus(ctx, client, statusSrv.URL, tt.tokenInput)
			require.NoError(t, err)
			assert.Equal(t, tt.wantHeader, capturedStatusAuth)

			var capturedJoinAuth string
			joinSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedJoinAuth = r.Header.Get("Authorization")
				w.WriteHeader(http.StatusOK)
			}))
			defer joinSrv.Close()

			err = RequestClusterJoin(ctx, joinSrv.Client(), joinSrv.URL, "node-2", "127.0.0.1:9302", "http://127.0.0.1:8082", tt.tokenInput)
			require.NoError(t, err)
			assert.Equal(t, tt.wantHeader, capturedJoinAuth)
		})
	}
}

func TestIsLocalHTTPAddr_NonLoopbackIPWithDifferentPort(t *testing.T) {
	t.Parallel()

	localAliases := map[string]bool{
		"192.168.1.50:9300": true,
		"192.168.1.50":      true,
	}
	cfg := config.Config{
		BindAddr: "192.168.1.50:8080",
		TLSBind:  "192.168.1.50:8443",
	}

	assert.True(t, isLocalHTTPAddr("http://192.168.1.50:8080", cfg, localAliases))
	assert.True(t, isLocalHTTPAddr("https://192.168.1.50:8443", cfg, localAliases))
	assert.False(t, isLocalHTTPAddr("http://192.168.1.50:9090", cfg, localAliases))
	assert.False(t, isLocalHTTPAddr("http://192.168.1.50:9300", cfg, localAliases))
}

func TestCandidateHTTPURLsForEndpoint_MultiIPMapping(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	peer := parsedPeerConfig{
		id:          "headless",
		raftAddr:    "headless.svc:9300",
		resolvedIPs: []string{"10.0.0.1:9300", "10.0.0.2:9300"},
		httpAddr:    "http://10.0.0.1:8080",
		httpAddrsByIP: map[string]string{
			"10.0.0.1:9300": "http://10.0.0.1:8080",
			"10.0.0.2:9300": "http://10.0.0.2:8080",
		},
	}

	urls1 := candidateHTTPURLsForEndpoint(peer, "10.0.0.1:9300", cfg, nil)
	assert.Contains(t, urls1, "http://10.0.0.1:8080")
	assert.NotContains(t, urls1, "http://10.0.0.2:8080")

	urls2 := candidateHTTPURLsForEndpoint(peer, "10.0.0.2:9300", cfg, nil)
	assert.Contains(t, urls2, "http://10.0.0.2:8080")
	assert.NotContains(t, urls2, "http://10.0.0.1:8080")
}

func TestResolveLeaderCandidateURLs_MultiIPMapping(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	peer := parsedPeerConfig{
		id:          "headless",
		raftAddr:    "headless.svc:9300",
		resolvedIPs: []string{"10.0.0.1:9300", "10.0.0.2:9300"},
		httpAddr:    "http://10.0.0.1:8080",
		httpAddrsByIP: map[string]string{
			"10.0.0.1:9300": "http://10.0.0.1:8080",
			"10.0.0.2:9300": "http://10.0.0.2:8080",
		},
	}

	urls := resolveLeaderCandidateURLs("10.0.0.2:9300", []parsedPeerConfig{peer}, cfg, nil)
	assert.Contains(t, urls, "http://10.0.0.2:8080")
	assert.NotContains(t, urls, "http://10.0.0.1:8080")
}

func TestCandidateHTTPURLsForEndpoint_FiltersLocalHTTPAddr(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		BindAddr: "127.0.0.1:8080",
	}
	localAliases := map[string]bool{"127.0.0.1": true, "127.0.0.1:9300": true}
	p := parsedPeerConfig{
		id:       "peer-1",
		raftAddr: "127.0.0.1:9300",
	}

	urls := candidateHTTPURLsForEndpoint(p, "127.0.0.1:9300", cfg, localAliases)
	assert.NotContains(t, urls, "http://127.0.0.1:8080", "local HTTP address should be filtered out from candidate URLs")
}

func TestGetParsedPeers_DeepCopiesHTTPAddrsByIP(t *testing.T) {
	t.Parallel()

	node := &RaftNode{
		parsedPeers: []parsedPeerConfig{
			{
				id:       "node-1",
				raftAddr: "10.0.0.1:9300",
				httpAddrsByIP: map[string]string{
					"10.0.0.1:9300": "http://10.0.0.1:8080",
				},
			},
		},
	}

	peers := node.getParsedPeers()
	require.Len(t, peers, 1)

	// Mutate returned peer map
	peers[0].httpAddrsByIP["10.0.0.1:9300"] = "http://mutated:8080"
	peers[0].httpAddrsByIP["new-key"] = "new-val"

	assert.Equal(t, "http://10.0.0.1:8080", node.parsedPeers[0].httpAddrsByIP["10.0.0.1:9300"], "original map should not be mutated")
	assert.NotContains(t, node.parsedPeers[0].httpAddrsByIP, "new-key", "original map should not have new key")
}

func TestCloneParsedPeersLocked_DeepCopiesResolvedIPs(t *testing.T) {
	t.Parallel()

	node := &RaftNode{
		parsedPeers: []parsedPeerConfig{
			{
				id:          "node-1",
				raftAddr:    "10.0.0.1:9300",
				resolvedIPs: []string{"10.0.0.1:9300", "10.0.0.2:9300"},
			},
		},
	}

	peers := node.cloneParsedPeersLocked()
	require.Len(t, peers, 1)
	require.Len(t, peers[0].resolvedIPs, 2)

	// Mutate returned slice element
	peers[0].resolvedIPs[0] = "mutated:9300"

	assert.Equal(t, "10.0.0.1:9300", node.parsedPeers[0].resolvedIPs[0], "original resolvedIPs should not be mutated")
}

func TestDetermineLocalHTTPAddr_SchemelessHTTPAddr(t *testing.T) {
	t.Parallel()

	// 1. Scheme-less HTTP
	nodeHTTP := &RaftNode{
		cfg: config.Config{
			BindAddr: "10.0.0.1:8080",
		},
	}
	peersHTTP := []parsedPeerConfig{
		{
			raftAddr: "10.0.0.1:9090",
			httpAddr: "10.0.0.1:8080",
		},
	}
	aliasesHTTP := map[string]bool{"10.0.0.1:9090": true}
	addr := nodeHTTP.determineLocalHTTPAddr(peersHTTP, aliasesHTTP, "9090", false, "")
	assert.Equal(t, "http://10.0.0.1:8080", addr)

	// 2. Scheme-less HTTPS
	nodeHTTPS := &RaftNode{
		cfg: config.Config{
			TLSBind: "10.0.0.1:8443",
			TLSCert: "cert.pem",
			TLSKey:  "key.pem",
		},
	}
	peersHTTPS := []parsedPeerConfig{
		{
			raftAddr: "10.0.0.1:9090",
			httpAddr: "10.0.0.1:8443",
		},
	}
	aliasesHTTPS := map[string]bool{"10.0.0.1:9090": true}
	addrHTTPS := nodeHTTPS.determineLocalHTTPAddr(peersHTTPS, aliasesHTTPS, "9090", false, "")
	assert.Equal(t, "https://10.0.0.1:8443", addrHTTPS)

	// 3. Already has scheme
	peersWithScheme := []parsedPeerConfig{
		{
			raftAddr: "10.0.0.1:9090",
			httpAddr: "http://10.0.0.1:8080",
		},
	}
	addrWithScheme := nodeHTTP.determineLocalHTTPAddr(peersWithScheme, aliasesHTTP, "9090", false, "")
	assert.Equal(t, "http://10.0.0.1:8080", addrWithScheme)
}

func TestDetermineLocalHTTPAddr_PrefersSpecificIPMappingInHttpAddrsByIP(t *testing.T) {
	t.Parallel()

	node := &RaftNode{
		cfg: config.Config{
			BindAddr: "10.0.0.1:8080",
		},
	}
	peers := []parsedPeerConfig{
		{
			raftAddr: "10.0.0.1:9090",
			httpAddr: "http://generic:8080",
			httpAddrsByIP: map[string]string{
				"10.0.0.1:9090": "http://specific:8080",
			},
		},
	}
	aliases := map[string]bool{"10.0.0.1:9090": true}

	// 1. Specific IP mapping for advAddr takes precedence over generic httpAddr
	addr := node.determineLocalHTTPAddr(peers, aliases, "9090", false, "10.0.0.1:9090")
	assert.Equal(t, "http://specific:8080", addr, "specific IP mapping for advAddr should take precedence over generic httpAddr")

	// 2. Specific IP mapping for an alias in localAliases takes precedence over generic httpAddr
	peersAlias := []parsedPeerConfig{
		{
			raftAddr: "10.0.0.1:9090",
			httpAddr: "http://generic:8080",
			httpAddrsByIP: map[string]string{
				"127.0.0.1:9090": "http://alias-specific:8080",
			},
		},
	}
	aliasesWithExtra := map[string]bool{
		"10.0.0.1:9090":  true,
		"127.0.0.1:9090": true,
	}
	addrAlias := node.determineLocalHTTPAddr(peersAlias, aliasesWithExtra, "9090", false, "unknown:9090")
	assert.Equal(t, "http://alias-specific:8080", addrAlias, "alias mapping in httpAddrsByIP should take precedence over generic httpAddr")
}

func TestDetermineLocalHTTPAddr_HeadlessDNSWithResolvedIPs(t *testing.T) {
	t.Parallel()

	node := &RaftNode{
		cfg: config.Config{},
	}
	peers := []parsedPeerConfig{
		{
			id:          "node-1",
			raftAddr:    "headless.cluster.local:9300",
			httpAddr:    "http://10.0.0.1:8080",
			resolvedIPs: []string{"10.0.0.1:9300", "10.0.0.2:9300"},
		},
	}
	localAliases := map[string]bool{
		"10.0.0.1:9300": true,
	}

	addr := node.determineLocalHTTPAddr(peers, localAliases, "9300", false, "")
	assert.Equal(t, "http://10.0.0.1:8080", addr, "should match local node when one of resolvedIPs matches local alias")
}


func TestDiscoverActiveLeader_ClosesIdleConnectionsWhenClientNil(t *testing.T) {
	var closedConns atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/status" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "node-1",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.1:9300",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	server.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closedConns.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	cfg := config.Config{
		RaftClusterSecret: "test-secret",
	}
	peers := []parsedPeerConfig{
		{
			raftAddr: server.Listener.Addr().String(),
			httpAddr: server.URL,
		},
	}

	leader := DiscoverActiveLeader(context.Background(), cfg, peers, nil, nil)
	assert.Equal(t, server.URL, leader)

	require.Eventually(t, func() bool {
		return closedConns.Load() > 0
	}, 1*time.Second, 20*time.Millisecond, "idle connection should be closed after DiscoverActiveLeader returns")
}

func TestStartAutoJoinRetry_DynamicPortBindingUpdatesLocalHTTPAddr(t *testing.T) {
	var receivedHTTPAddr atomic.Value
	joinReceived := make(chan struct{})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/join" {
			var req ClusterJoinRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
				receivedHTTPAddr.Store(req.HTTPAddress)
				select {
				case <-joinReceived:
				default:
					close(joinReceived)
				}
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		BindAddr:          "127.0.0.1:0",
		RaftAdvertise:     "127.0.0.1:9301",
		RaftClusterSecret: "test-secret",
	}

	node := &RaftNode{
		cfg:        cfg,
		nodeCtx:    ctx,
		nodeCancel: cancel,
		defPort:    "9301",
		autoJoinBackoff: func(attempt int) time.Duration {
			return 5 * time.Millisecond
		},
	}

	// Initially port is unset, simulating pre-listen state
	initialHTTPAddr := node.determineLocalHTTPAddr(nil, nil, "9301", false, "")
	assert.Equal(t, "", initialHTTPAddr)

	// Now dynamic listener binds to port 49152 and sets HTTPPort
	node.SetHTTPPort("49152")

	// Pass the pre-resolved initialHTTPAddr (which had fallback 8080) to startAutoJoinRetry
	go node.startAutoJoinRetry(ts.URL, "node-1", "127.0.0.1:9301", initialHTTPAddr)

	select {
	case <-joinReceived:
		addr, _ := receivedHTTPAddr.Load().(string)
		assert.Equal(t, "http://127.0.0.1:49152", addr, "dynamic port binding should update advertised localHTTPAddr to bound port")
	case <-time.After(2 * time.Second):
		t.Fatal("join request was not received in time")
	}
}

func TestDiscoverActiveLeader_ConcurrentFollowerRedirectionSafe(t *testing.T) {
	leaderServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/status" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "node-leader",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.1:9301",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer leaderServer.Close()

	followers := make([]*httptest.Server, 4)
	for i := range followers {
		followers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/cluster/status" {
				time.Sleep(5 * time.Millisecond)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
					NodeID:     "node-follower",
					Role:       "follower",
					IsLeader:   false,
					LeaderAddr: "127.0.0.1:9301",
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer followers[i].Close()
	}

	leaderHost, leaderPort, err := net.SplitHostPort(leaderServer.Listener.Addr().String())
	require.NoError(t, err)

	cfg := config.Config{
		BindAddr: ":" + leaderPort,
	}
	var peers []parsedPeerConfig
	for i, f := range followers {
		peers = append(peers, parsedPeerConfig{
			id:       fmt.Sprintf("node-f%d", i),
			raftAddr: fmt.Sprintf("127.0.0.%d:9302", i+10),
			httpAddr: f.URL,
		})
	}
	// Leader is deliberately NOT in peers so it is discovered strictly via follower redirection
	leaderRaftAddr := net.JoinHostPort(leaderHost, leaderPort)

	for _, f := range followers {
		fHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/cluster/status" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
					NodeID:     "node-follower",
					Role:       "follower",
					IsLeader:   false,
					LeaderAddr: leaderRaftAddr,
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
		f.Config.Handler = fHandler
	}

	localAliases := map[string]bool{
		"127.0.0.99:9399": true,
	}

	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iter := 0; iter < 5; iter++ {
				leader := DiscoverActiveLeader(context.Background(), cfg, peers, localAliases, nil)
				assert.Equal(t, leaderServer.URL, leader)
			}
		}()
	}
	wg.Wait()
}

func TestDetermineLocalHTTPAddr_DynamicPortReturnsEmptyWhenHTTPPortUnset(t *testing.T) {
	t.Parallel()

	// 1. Plaintext dynamic port with unset HTTPPort -> should return ""
	node := &RaftNode{
		cfg: config.Config{
			BindAddr:      "127.0.0.1:0",
			RaftAdvertise: "127.0.0.1:9301",
		},
	}
	assert.Equal(t, "", node.determineLocalHTTPAddr(nil, nil, "9301", false, ""))

	// When HTTPPort is set -> returns bound port
	node.SetHTTPPort("45678")
	assert.Equal(t, "http://127.0.0.1:45678", node.determineLocalHTTPAddr(nil, nil, "9301", false, ""))

	// 2. TLS dynamic port with unset HTTPPort -> should return ""
	nodeTLS := &RaftNode{
		cfg: config.Config{
			TLSBind:       "127.0.0.1:0",
			TLSCert:       "test.crt",
			RaftAdvertise: "127.0.0.1:9301",
		},
		tlsEnabled: true,
	}
	assert.Equal(t, "", nodeTLS.determineLocalHTTPAddr(nil, nil, "9301", false, ""))

	// When HTTPPort is set on TLS node -> returns bound port
	nodeTLS.SetHTTPPort("45679")
	assert.Equal(t, "https://127.0.0.1:45679", nodeTLS.determineLocalHTTPAddr(nil, nil, "9301", false, ""))
}

func TestStartAutoJoinRetry_DynamicPort_SetHTTPPortAfterJoinUpdatesLeader(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var receivedHTTPAddrs []string
	joinCh := make(chan string, 10)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/join" {
			var req ClusterJoinRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
				mu.Lock()
				receivedHTTPAddrs = append(receivedHTTPAddrs, req.HTTPAddress)
				mu.Unlock()
				joinCh <- req.HTTPAddress
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		BindAddr:          "127.0.0.1:0",
		RaftAdvertise:     "127.0.0.1:9301",
		RaftClusterSecret: "test-secret",
	}

	node := &RaftNode{
		cfg:        cfg,
		nodeCtx:    ctx,
		nodeCancel: cancel,
		nodeID:     "node-1",
		defPort:    "9301",
		autoJoinBackoff: func(attempt int) time.Duration {
			return 5 * time.Millisecond
		},
	}

	// 1. Initial determineLocalHTTPAddr returns "" because dynamic port is used and HTTPPort is unset
	initialHTTPAddr := node.determineLocalHTTPAddr(nil, nil, "9301", false, "")
	require.Equal(t, "", initialHTTPAddr)

	// 2. Start auto-join retry with empty initial HTTP address
	node.startAutoJoinRetry(ts.URL, "node-1", "127.0.0.1:9301", initialHTTPAddr)

	// 3. Leader receives initial join request with empty HTTPAddress
	select {
	case addr := <-joinCh:
		assert.Equal(t, "", addr, "initial join request should have empty HTTP address")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial join request")
	}

	assert.Equal(t, "joined", node.AutoJoinStatus())

	// 4. Later, HTTP server finishes binding and calls SetHTTPPort
	node.SetHTTPPort("54321")

	// 5. Leader receives updated join request with the newly bound HTTP address
	select {
	case addr := <-joinCh:
		assert.Equal(t, "http://127.0.0.1:54321", addr, "leader should receive updated HTTP address after SetHTTPPort")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for updated join request after SetHTTPPort")
	}

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, receivedHTTPAddrs, 2)
	assert.Equal(t, "", receivedHTTPAddrs[0])
	assert.Equal(t, "http://127.0.0.1:54321", receivedHTTPAddrs[1])
}

func TestCandidateHTTPURLsForAddr_DefaultConfig_NoHTTPS(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		BindAddr: "0.0.0.0:8080",
		TLSBind:  "0.0.0.0:8443",
	}
	urls := candidateHTTPURLsForAddr("10.0.0.1", cfg)
	assert.Contains(t, urls, "http://10.0.0.1:8080")
	for _, u := range urls {
		assert.False(t, strings.HasPrefix(u, "https://"), "candidate URLs on default config without TLS should not contain https URLs: %s", u)
	}
}

func TestIsLocalHTTPAddr_DynamicPort(t *testing.T) {
	t.Parallel()

	localAliases := map[string]bool{
		"192.168.1.50": true,
	}
	cfg := config.Config{
		BindAddr: "192.168.1.50:0",
		TLSBind:  "192.168.1.50:0",
	}

	// When port 0 is configured and no bound port provided, it must not default to 8080 or 8443
	assert.False(t, isLocalHTTPAddr("http://192.168.1.50:8080", cfg, localAliases))
	assert.False(t, isLocalHTTPAddr("https://192.168.1.50:8443", cfg, localAliases))

	// When bound port is provided, it matches the bound port
	assert.True(t, isLocalHTTPAddr("http://192.168.1.50:54321", cfg, localAliases, "54321"))
	assert.False(t, isLocalHTTPAddr("http://192.168.1.50:8080", cfg, localAliases, "54321"))
}

func TestCandidateHTTPURLsForEndpoint_HeadlessDNS_FallbackAndMapping(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	peer := parsedPeerConfig{
		id:          "headless",
		raftAddr:    "headless.default.svc.cluster.local:9300",
		resolvedIPs: []string{"10.0.0.1:9300", "10.0.0.2:9300"},
		httpAddr:    "http://10.0.0.1:8080",
	}

	// When httpAddrsByIP is not populated, should fall back to httpAddr for any endpoint
	urls1 := candidateHTTPURLsForEndpoint(peer, "10.0.0.1:9300", cfg, nil)
	assert.Contains(t, urls1, "http://10.0.0.1:8080")

	urls2 := candidateHTTPURLsForEndpoint(peer, "10.0.0.2:9300", cfg, nil)
	assert.Contains(t, urls2, "http://10.0.0.1:8080")

	// When configured via --raft-peer-http-addrs headless=http://10.0.0.1:8080
	peers := applyPeerHTTPAddrs([]parsedPeerConfig{peer}, []string{"headless=http://10.0.0.1:8080"})
	urlsMapped1 := candidateHTTPURLsForEndpoint(peers[0], "10.0.0.1:9300", cfg, nil)
	assert.Contains(t, urlsMapped1, "http://10.0.0.1:8080")

	urlsMapped2 := candidateHTTPURLsForEndpoint(peers[0], "10.0.0.2:9300", cfg, nil)
	assert.Contains(t, urlsMapped2, "http://10.0.0.1:8080")
}

func TestIsLocalHTTPAddr_BindAddrOff(t *testing.T) {
	t.Parallel()

	localAliases := map[string]bool{
		"127.0.0.1:9300": true,
		"127.0.0.1":      true,
	}

	cfg := config.Config{
		BindAddr: "off",
		TLSBind:  "off",
	}

	assert.False(t, isLocalHTTPAddr("http://127.0.0.1:8080", cfg, localAliases), "port 8080 should not be considered local when BindAddr is off")
	assert.False(t, isLocalHTTPAddr("https://127.0.0.1:8443", cfg, localAliases), "port 8443 should not be considered local when TLSBind is off")
}

func TestCandidateHTTPURLsForEndpoint_BareHostPortSchemeNormalization(t *testing.T) {
	t.Parallel()

	cfgPlain := config.Config{}
	peerPlain := parsedPeerConfig{
		raftAddr: "10.0.0.1:9300",
		httpAddr: "10.0.0.1:8080",
	}
	urls := candidateHTTPURLsForEndpoint(peerPlain, "10.0.0.1:9300", cfgPlain, nil)
	assert.Contains(t, urls, "http://10.0.0.1:8080")

	cfgTLS := config.Config{
		TLSCert: "/path/to/cert.pem",
	}
	peerTLS := parsedPeerConfig{
		raftAddr: "10.0.0.1:9300",
		httpAddr: "10.0.0.1:8443",
	}
	urlsTLS := candidateHTTPURLsForEndpoint(peerTLS, "10.0.0.1:9300", cfgTLS, nil)
	assert.Contains(t, urlsTLS, "https://10.0.0.1:8443")
}

func TestSetHTTPPort_RetriesAndLogsOnJoinFailure(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	var attempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/join" {
			attempts.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal error"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		BindAddr:          "127.0.0.1:0",
		RaftAdvertise:     "127.0.0.1:9301",
		RaftClusterSecret: "test-secret",
	}

	node := &RaftNode{
		cfg:              cfg,
		nodeCtx:          ctx,
		nodeCancel:       cancel,
		nodeID:           "node-1",
		advAddr:          "127.0.0.1:9301",
		lastJoinedLeader: server.URL,
	}

	node.SetHTTPPort("54321")

	// Up to 3 retries (total 4 attempts) with 200ms delay
	assert.Eventually(t, func() bool {
		return attempts.Load() == 4
	}, 3*time.Second, 50*time.Millisecond, "should attempt initial join plus up to 3 retries")

	// Verify warning logged with leader field
	var foundLog bool
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "failed to update leader with dynamic HTTP address") {
			if entry.Data["leader"] == server.URL {
				foundLog = true
				break
			}
		}
	}
	assert.True(t, foundLog, "should log warning with leader field on join update failure")
}

func TestIsLocalHTTPAddr_NoExplicitPort(t *testing.T) {
	t.Parallel()

	localAliases := map[string]bool{
		"localhost": true,
		"127.0.0.1": true,
	}
	cfg := config.Config{
		BindAddr: "127.0.0.1:8080",
	}

	assert.False(t, isLocalHTTPAddr("http://localhost", cfg, localAliases), "http://localhost defaults to port 80, should not match port 8080")
	assert.False(t, isLocalHTTPAddr("https://localhost", cfg, localAliases), "https://localhost defaults to port 443, should not match port 8080")
}

func TestCandidateHTTPURLsForEndpoint_CaseInsensitiveScheme(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	peer := parsedPeerConfig{
		httpAddr: "HTTP://10.0.0.1:8080",
	}
	urls := candidateHTTPURLsForEndpoint(peer, "10.0.0.1:9300", cfg, nil)
	assert.Contains(t, urls, "HTTP://10.0.0.1:8080")
	assert.NotContains(t, urls, "http://HTTP://10.0.0.1:8080")
}

func TestIsLocalHTTPAddr_DynamicPortWithBoundPort(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		BindAddr: "127.0.0.1:0",
	}
	localAliases := map[string]bool{
		"127.0.0.1": true,
	}

	// Without boundPort, port :0 doesn't match 54321
	assert.False(t, isLocalHTTPAddr("http://127.0.0.1:54321", cfg, localAliases))

	// With boundPort passed as 54321, it should match as local
	assert.True(t, isLocalHTTPAddr("http://127.0.0.1:54321", cfg, localAliases, "54321"))

	// Candidate URLs for endpoint should omit the node's own local URL when boundPort is passed
	peer := parsedPeerConfig{
		raftAddr: "127.0.0.1:9000",
		httpAddr: "http://127.0.0.1:54321",
	}
	urls := candidateHTTPURLsForEndpoint(peer, "127.0.0.1:9000", cfg, localAliases, "54321")
	assert.NotContains(t, urls, "http://127.0.0.1:54321")

	// Leader candidate URLs should also omit the node's own local URL when boundPort is passed
	leaderURLs := resolveLeaderCandidateURLs("127.0.0.1:9000", []parsedPeerConfig{peer}, cfg, localAliases, "54321")
	assert.NotContains(t, leaderURLs, "http://127.0.0.1:54321")
}

func TestDiscoverActiveLeader_UnauthorizedLogsWarning(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer server.Close()

	cfg := config.Config{
		RaftClusterSecret: "wrong-secret",
	}
	peers := []parsedPeerConfig{
		{
			raftAddr: server.Listener.Addr().String(),
			httpAddr: server.URL,
		},
	}

	leader := DiscoverActiveLeader(context.Background(), cfg, peers, nil, nil)
	assert.Empty(t, leader)

	var foundWarn bool
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "cluster status query unauthorized (check --raft-cluster-secret)") {
			assert.Equal(t, server.URL, entry.Data["target"])
			foundWarn = true
			break
		}
	}
	assert.True(t, foundWarn, "should log warning when cluster status query returns 401 unauthorized")
}

func TestDetermineLocalHTTPAddr_RaftBindWithPort_FallsBackToAdvAddr(t *testing.T) {
	t.Parallel()
	node := &RaftNode{
		cfg: config.Config{
			RaftAdvertise: "",
			RaftBind:      "0.0.0.0:8300",
			BindAddr:      ":8080",
		},
	}
	addr := node.determineLocalHTTPAddr(nil, nil, "8300", false, "10.0.0.5:8300")
	assert.Equal(t, "http://10.0.0.5:8080", addr)
}

func TestResolveLeaderCandidateURLs_BareCandidateAddressGetsScheme(t *testing.T) {
	t.Parallel()
	cfg := config.Config{}
	peer := parsedPeerConfig{
		raftAddr: "10.0.0.1:8300",
		httpAddr: "10.0.0.1:8080",
	}
	urls := resolveLeaderCandidateURLs("10.0.0.1:8300", []parsedPeerConfig{peer}, cfg, nil)
	assert.Contains(t, urls, "http://10.0.0.1:8080")
	assert.NotContains(t, urls, "10.0.0.1:8080")

	tlsCfg := config.Config{
		TLSCert: "test.crt",
	}
	tlsURLs := resolveLeaderCandidateURLs("10.0.0.1:8300", []parsedPeerConfig{peer}, tlsCfg, nil)
	assert.Contains(t, tlsURLs, "https://10.0.0.1:8080")
	assert.NotContains(t, tlsURLs, "10.0.0.1:8080")
}

func TestIsLocalHTTPAddr_TLSDisabled_Port8443NotLocal(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		BindAddr: "127.0.0.1:8080",
	}
	localAliases := map[string]bool{
		"127.0.0.1:8300": true,
	}

	assert.False(t, isLocalHTTPAddr("http://127.0.0.1:8443", cfg, localAliases), "port 8443 should not be local when TLS is disabled and TLSBind is empty")
	assert.False(t, isLocalHTTPAddr("127.0.0.1:8443", cfg, localAliases), "bare 127.0.0.1:8443 should not be local when TLS is disabled and TLSBind is empty")
}

func TestDetermineLocalHTTPAddr_DeterministicAliasTieBreaking(t *testing.T) {
	t.Parallel()
	node := &RaftNode{
		cfg: config.Config{
			BindAddr: ":8080",
		},
	}
	peers := []parsedPeerConfig{
		{
			raftAddr: "127.0.0.1:8300",
			httpAddrsByIP: map[string]string{
				"10.0.0.1:8300": "http://10.0.0.1:8080",
				"10.0.0.2:8300": "http://10.0.0.2:8080",
				"10.0.0.3:8300": "http://10.0.0.3:8080",
				"10.0.0.4:8300": "http://10.0.0.4:8080",
			},
		},
	}
	localAliases := map[string]bool{
		"127.0.0.1:8300": true,
		"10.0.0.1:8300":  true,
		"10.0.0.2:8300":  true,
		"10.0.0.3:8300":  true,
		"10.0.0.4:8300":  true,
	}

	for i := 0; i < 50; i++ {
		addr := node.determineLocalHTTPAddr(peers, localAliases, "8300", false, "")
		assert.Equal(t, "http://10.0.0.1:8080", addr)
	}
}

func TestResolveLeaderCandidateURLs_IPv6BracketNormalization(t *testing.T) {
	t.Parallel()
	cfg := config.Config{}

	// Case 1: leaderAddr has brackets [::1]:9300, candidate has unbracketed ::1
	peer1 := parsedPeerConfig{
		raftAddr: "::1",
		httpAddr: "http://[::1]:9090",
	}
	urls1 := resolveLeaderCandidateURLs("[::1]:9300", []parsedPeerConfig{peer1}, cfg, nil)
	assert.Contains(t, urls1, "http://[::1]:9090", "should match when leaderAddr has brackets and candidate does not")

	// Case 2: leaderAddr has no brackets ::1, candidate has bracketed [::1]:9300
	peer2 := parsedPeerConfig{
		raftAddr: "[::1]:9300",
		httpAddr: "http://[::1]:9090",
	}
	urls2 := resolveLeaderCandidateURLs("::1", []parsedPeerConfig{peer2}, cfg, nil)
	assert.Contains(t, urls2, "http://[::1]:9090", "should match when candidate has brackets and leaderAddr does not")

	// Case 3: leaderAddr matched via resolvedIPs with bracket variation
	peer3 := parsedPeerConfig{
		raftAddr:    "ipv6-node:9300",
		resolvedIPs: []string{"::1"},
		httpAddr:    "http://[::1]:9090",
	}
	urls3 := resolveLeaderCandidateURLs("[::1]:9300", []parsedPeerConfig{peer3}, cfg, nil)
	assert.Contains(t, urls3, "http://[::1]:9090", "should match resolvedIPs with bracket variation")
}

func TestStartAutoJoinRetry_SteadyStateLogLevelDemoted(t *testing.T) {
	origLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	defer logrus.SetLevel(origLevel)

	hook := test.NewGlobal()
	defer hook.Reset()

	var attempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/join" {
			attempts.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"failed to join"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node := &RaftNode{
		cfg: config.Config{
			RaftClusterSecret: "test-secret",
		},
		nodeCtx:    ctx,
		nodeCancel: cancel,
		autoJoinBackoff: func(attempt int) time.Duration {
			return 1 * time.Millisecond
		},
	}

	done := make(chan struct{})
	go func() {
		node.startAutoJoinRetry(server.URL, "node-1", "127.0.0.1:9301", "http://127.0.0.1:8080")
		close(done)
	}()

	// Wait until steady-state is reached (status = exhausted) and at least one steady-state attempt occurred (> 30)
	assert.Eventually(t, func() bool {
		return node.AutoJoinStatus() == "exhausted" && attempts.Load() > 30
	}, 3*time.Second, 10*time.Millisecond, "should transition to exhausted status and execute steady-state retry")

	cancel()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("startAutoJoinRetry did not terminate after cancel")
	}

	entries := hook.AllEntries()
	var exhaustedIdx = -1
	for i, entry := range entries {
		if strings.Contains(entry.Message, "exhausted retries trying to auto-join Raft cluster leader") {
			exhaustedIdx = i
			break
		}
	}
	require.NotEqual(t, -1, exhaustedIdx, "expected exhausted retries log entry")

	// Verify pre-steady-state entries (attempt >= 0): must log at WarnLevel
	var initialWarnCount int
	for _, entry := range entries[:exhaustedIdx] {
		if strings.Contains(entry.Message, "failed to auto-join Raft cluster leader") {
			assert.Equal(t, logrus.WarnLevel, entry.Level, "pre-steady-state join failure must be logged at Warn level")
			assert.Contains(t, entry.Message, "retrying")
			assert.NotNil(t, entry.Data["attempt"], "pre-steady-state join failure must include attempt field")
			initialWarnCount++
		}
	}
	assert.Greater(t, initialWarnCount, 0, "expected at least one warning during initial retries")

	// Verify steady-state entries (attempt == -1): must log at DebugLevel and NOT at WarnLevel
	var steadyDebugCount int
	for _, entry := range entries[exhaustedIdx+1:] {
		if strings.Contains(entry.Message, "failed to auto-join Raft cluster leader") {
			assert.Equal(t, logrus.DebugLevel, entry.Level, "steady-state join failure must be logged at Debug level")
			assert.Contains(t, entry.Message, "during steady-state retry")
			assert.Nil(t, entry.Data["attempt"], "steady-state retry should not have attempt field")
			assert.Equal(t, server.URL, entry.Data["leader"])
			steadyDebugCount++
		}
	}
	assert.Greater(t, steadyDebugCount, 0, "expected at least one debug log during steady-state retries")
}
