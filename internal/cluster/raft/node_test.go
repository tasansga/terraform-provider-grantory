package raft

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	hashiraft "github.com/hashicorp/raft"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/store"
)

func TestRaftConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "raft", RaftDirName)
	assert.Equal(t, "snapshots", SnapshotsDirName)
	assert.Equal(t, "staging", StagingDirName)
	assert.Equal(t, "raft.db", RaftDBFileName)
	assert.Equal(t, 10*time.Second, DefaultBarrierTimeout)
}

func TestDNSResolver_CacheSaturationAndEviction(t *testing.T) {
	t.Parallel()

	lookupCount := 0
	dummyLookup := func(host string) ([]net.IP, error) {
		lookupCount++
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}

	// 1. When cache is saturated with unexpired entries, clear(r.cache) resets cache and stores new entry.
	resolver := newDNSResolverWithCapacity(10*time.Minute, 3, dummyLookup)

	_, err := resolver.lookup("host1.example.com")
	require.NoError(t, err)
	_, err = resolver.lookup("host2.example.com")
	require.NoError(t, err)
	_, err = resolver.lookup("host3.example.com")
	require.NoError(t, err)

	resolver.mu.RLock()
	assert.Equal(t, 3, len(resolver.cache))
	resolver.mu.RUnlock()

	// Saturated cache: host4 triggers eviction. Since no entries are expired, cache is cleared and host4 added.
	_, err = resolver.lookup("host4.example.com")
	require.NoError(t, err)

	resolver.mu.RLock()
	assert.Equal(t, 1, len(resolver.cache), "cache should have been cleared and only contain host4")
	_, hasHost1 := resolver.cache["host1.example.com"]
	_, hasHost2 := resolver.cache["host2.example.com"]
	_, hasHost3 := resolver.cache["host3.example.com"]
	_, hasHost4 := resolver.cache["host4.example.com"]
	resolver.mu.RUnlock()

	assert.False(t, hasHost1)
	assert.False(t, hasHost2)
	assert.False(t, hasHost3)
	assert.True(t, hasHost4)

	// 2. When cache is saturated and has expired entries, only expired entries are deleted.
	resolver2 := newDNSResolverWithCapacity(10*time.Minute, 2, dummyLookup)
	resolver2.mu.Lock()
	resolver2.cache["expired.example.com"] = dnsCacheEntry{
		ips:       []net.IP{net.ParseIP("127.0.0.1")},
		expiresAt: time.Now().Add(-1 * time.Minute), // expired
	}
	resolver2.cache["active.example.com"] = dnsCacheEntry{
		ips:       []net.IP{net.ParseIP("127.0.0.1")},
		expiresAt: time.Now().Add(10 * time.Minute), // active
	}
	resolver2.mu.Unlock()

	// Adding another entry should evict expired.example.com and retain active.example.com
	_, err = resolver2.lookup("new.example.com")
	require.NoError(t, err)

	resolver2.mu.RLock()
	assert.Equal(t, 2, len(resolver2.cache))
	_, hasExpired := resolver2.cache["expired.example.com"]
	_, hasActive := resolver2.cache["active.example.com"]
	_, hasNew := resolver2.cache["new.example.com"]
	resolver2.mu.RUnlock()

	assert.False(t, hasExpired, "expired entry should be evicted")
	assert.True(t, hasActive, "active entry should be retained")
	assert.True(t, hasNew, "new entry should be stored")
}

func TestIsLocalAddress(t *testing.T) {
	t.Parallel()

	localAliases := map[string]bool{
		"127.0.0.1:8081": true,
		"127.0.0.1":      true,
		"node-1:8081":    true,
	}

	// Direct match in localAliases
	assert.True(t, isLocalAddress("127.0.0.1:8081", localAliases, "8081", false))
	assert.True(t, isLocalAddress("node-1:8081", localAliases, "8081", false))

	// Match via resolveHostPort
	assert.True(t, isLocalAddress("127.0.0.1", localAliases, "8081", false))

	// Negative match
	assert.False(t, isLocalAddress("192.168.1.50:8081", localAliases, "8081", false))
	assert.False(t, isLocalAddress("remote-node:8081", localAliases, "8081", false))
}

func TestRaftNodeGetters(t *testing.T) {
	t.Parallel()

	var nilNode *RaftNode
	assert.Empty(t, nilNode.RaftAddress())
	assert.Nil(t, nilNode.Stats())
	assert.Empty(t, nilNode.NodeID())
	assert.False(t, nilNode.IsLeader())
	assert.Empty(t, nilNode.LeaderAddr())

	emptyNode := &RaftNode{}
	assert.Empty(t, emptyNode.RaftAddress())
	assert.Nil(t, emptyNode.Stats())
}

type testOrderTransport struct {
	hashiraft.Transport
	onClose func()
}

func (m *testOrderTransport) Close() error {
	if m.onClose != nil {
		m.onClose()
	}
	return nil
}

func TestRaftNode_CloseCancelsContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	node := &RaftNode{
		nodeCancel: cancel,
	}

	select {
	case <-ctx.Done():
		t.Fatal("context should not be canceled before Close()")
	default:
	}

	err := node.Close()
	require.NoError(t, err)

	select {
	case <-ctx.Done():
		// OK
	default:
		t.Fatal("context should be canceled upon Close()")
	}
	assert.Nil(t, node.nodeCancel, "nodeCancel should be nil after Close()")

	// Idempotent Close()
	assert.NoError(t, node.Close())
}

func TestRaftNode_CloseOrder_ContextCanceledBeforeTransport(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	var order []string
	var mu sync.Mutex

	node := &RaftNode{
		shutdownOverride: func() error {
			mu.Lock()
			order = append(order, "raftShutdown")
			mu.Unlock()
			return nil
		},
		nodeCancel: func() {
			mu.Lock()
			order = append(order, "cancel")
			mu.Unlock()
			cancel()
		},
		transport: &testOrderTransport{
			onClose: func() {
				mu.Lock()
				order = append(order, "transport")
				mu.Unlock()
			},
		},
	}

	err := node.Close()
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"raftShutdown", "cancel", "transport"}, order, "raft.Shutdown() must complete before nodeCancel(), which must precede transport.Close()")
	assert.ErrorIs(t, ctx.Err(), context.Canceled)
}

func TestRaftNode_Close_ShutdownErrorCaptured(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("simulated raft shutdown error")
	node := &RaftNode{
		shutdownOverride: func() error {
			return expectedErr
		},
	}

	err := node.Close()
	require.ErrorIs(t, err, expectedErr)
}

func TestRaftNode_RealNode_ShutdownOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "order-test",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)

	origCancel := node.nodeCancel
	var shutdownCompletedAtCancel bool
	node.nodeCancel = func() {
		// When nodeCancel is called, raft.Shutdown() must have already completed,
		// putting HashiCorp Raft into Shutdown state.
		if node.raft != nil && node.raft.State() == hashiraft.Shutdown {
			shutdownCompletedAtCancel = true
		}
		if origCancel != nil {
			origCancel()
		}
	}

	err = node.Close()
	require.NoError(t, err)
	assert.True(t, shutdownCompletedAtCancel, "raft.Shutdown() must complete before nodeCancel() is called")
}

func TestResolveHostPort(t *testing.T) {
	t.Parallel()

	// 1. Empty target returns nil
	assert.Nil(t, resolveHostPort("", "8081", false, nil))
	assert.Nil(t, resolveHostPort("   ", "8081", false, nil))

	// 2. IP literals bypass resolver
	assert.Equal(t, []string{"192.168.1.1:8081"}, resolveHostPort("192.168.1.1:8081", "9000", false, nil))
	assert.Equal(t, []string{"192.168.1.1:8081"}, resolveHostPort("192.168.1.1", "8081", false, nil))
	assert.Equal(t, []string{"[::1]:8081"}, resolveHostPort("[::1]:8081", "9000", false, nil))
	assert.Equal(t, []string{"::1"}, resolveHostPort("::1", "", false, nil))

	// 3. Isolated custom resolver with IPv4 & IPv6
	customLookup := func(host string) ([]net.IP, error) {
		if host == "cluster-node.local" {
			return []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("2001:db8::1"),
			}, nil
		}
		if host == "fail.local" {
			return nil, errors.New("dns lookup failure")
		}
		return nil, nil
	}
	resolver := newDNSResolver(1*time.Minute, customLookup)

	// Prefer IPv4
	resV4 := resolveHostPort("cluster-node.local", "8081", false, resolver)
	assert.Equal(t, []string{"10.0.0.1:8081"}, resV4)

	// Prefer IPv6
	resV6 := resolveHostPort("cluster-node.local:9000", "8081", true, resolver)
	assert.Equal(t, []string{"[2001:db8::1]:9000"}, resV6)

	// Lookup failure fallback
	resFail := resolveHostPort("fail.local:8081", "9000", false, resolver)
	assert.Equal(t, []string{"fail.local:8081"}, resFail)

	// Nil resolver falls back cleanly
	resNil := resolveHostPort("127.0.0.1", "8081", false, nil)
	assert.Equal(t, []string{"127.0.0.1:8081"}, resNil)

	// resolveHostPort delegates to default resolver without passing resolver
	resDefault := resolveHostPort("127.0.0.1", "8081", false)
	assert.Equal(t, []string{"127.0.0.1:8081"}, resDefault)
}

func TestGetResolver(t *testing.T) {
	t.Parallel()

	// Empty slice returns default
	assert.Same(t, defaultDNSResolver, getResolver(nil))
	assert.Same(t, defaultDNSResolver, getResolver([]*dnsResolver{}))

	// Nil element returns default
	assert.Same(t, defaultDNSResolver, getResolver([]*dnsResolver{nil}))

	// Non-nil element returns specified resolver
	custom := newDNSResolver(10*time.Second, nil)
	assert.Same(t, custom, getResolver([]*dnsResolver{custom}))
	assert.Same(t, custom, getResolver([]*dnsResolver{custom, defaultDNSResolver}))
}

func TestConsolidatedResolverFunctions(t *testing.T) {
	t.Parallel()

	customLookup := func(host string) ([]net.IP, error) {
		if host == "my-node.example.com" {
			return []net.IP{net.ParseIP("192.168.10.100")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	customRes := newDNSResolver(1*time.Minute, customLookup)

	// parsePeerConfig with resolver
	p := parsePeerConfig("node1=my-node.example.com:8081@192.168.10.100:8080", "8081", false, customRes)
	assert.Equal(t, "node1", p.id)
	assert.Equal(t, "my-node.example.com:8081", p.raftAddr)
	assert.Equal(t, "192.168.10.100:8080", p.httpAddr)
	assert.Contains(t, p.resolvedIPs, "192.168.10.100:8081")

	// parsePeers with resolver
	peers := parsePeers([]string{"node1=my-node.example.com:8081"}, "8081", false, customRes)
	assert.Len(t, peers, 1)
	assert.Contains(t, peers[0].resolvedIPs, "192.168.10.100:8081")

	// isLocalAddress with resolver
	localAliases := map[string]bool{"192.168.10.100:8081": true}
	assert.True(t, isLocalAddress("my-node.example.com:8081", localAliases, "8081", false, customRes))
	assert.False(t, isLocalAddress("other.example.com:8081", localAliases, "8081", false, customRes))

	// buildBootstrapServers with resolver
	cfg := config.Config{
		RaftBootstrapExpect: 1,
		RaftAdvertise:       "192.168.10.100:8081",
		RaftNodeID:          "node1",
	}
	servers, err := buildBootstrapServers(cfg, "node1", "192.168.10.100:8081", nil, customRes)
	assert.NoError(t, err)
	assert.Len(t, servers, 1)
	assert.Equal(t, "node1", string(servers[0].ID))
}

func TestDefaultRaftPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      config.Config
		expected string
	}{
		{
			name:     "empty config",
			cfg:      config.Config{},
			expected: "",
		},
		{
			name: "raft advertise with valid port",
			cfg: config.Config{
				RaftAdvertise: "127.0.0.1:8081",
				RaftBind:      "127.0.0.1:8082",
			},
			expected: "8081",
		},
		{
			name: "raft bind with valid port when advertise empty",
			cfg: config.Config{
				RaftBind: "0.0.0.0:8082",
			},
			expected: "8082",
		},
		{
			name: "raft advertise with port 0 falls back to raft bind",
			cfg: config.Config{
				RaftAdvertise: "127.0.0.1:0",
				RaftBind:      "127.0.0.1:8081",
			},
			expected: "8081",
		},
		{
			name: "raft advertise and raft bind both port 0",
			cfg: config.Config{
				RaftAdvertise: "127.0.0.1:0",
				RaftBind:      "0.0.0.0:0",
			},
			expected: "",
		},
		{
			name: "raft bind port 0 when advertise empty",
			cfg: config.Config{
				RaftBind: "127.0.0.1:0",
			},
			expected: "",
		},
		{
			name: "invalid address without port",
			cfg: config.Config{
				RaftAdvertise: "invalid-host",
				RaftBind:      "invalid-bind",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, defaultRaftPort(tt.cfg))
		})
	}
}

func TestNewRaftNode_TLSOff_ReportsNotTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nsStore, err := store.NewNamespaceStore(ctx, t.TempDir())
	require.NoError(t, err)

	t.Run("TLSCert and TLSKey provided but TLSBind is off", func(t *testing.T) {
		cfg := config.Config{
			RaftBind:            "127.0.0.1:0",
			RaftNodeID:          "tls-off-test",
			RaftBootstrapExpect: 1,
			TLSCert:             "test.crt",
			TLSKey:              "test.key",
			TLSBind:             "off",
			BindAddr:            "127.0.0.1:8080",
		}

		node, err := NewRaftNode(ctx, cfg, nsStore, t.TempDir())
		require.NoError(t, err)
		defer func() { _ = node.Close() }()

		assert.False(t, node.IsTLS())
		assert.Equal(t, "8080", node.HTTPPort())
		assert.Equal(t, "8080", node.httpPort)
	})

	t.Run("TLSCert and TLSKey provided but TLSBind is empty", func(t *testing.T) {
		cfg := config.Config{
			RaftBind:            "127.0.0.1:0",
			RaftNodeID:          "tls-empty-test",
			RaftBootstrapExpect: 1,
			TLSCert:             "test.crt",
			TLSKey:              "test.key",
			TLSBind:             "",
			BindAddr:            "127.0.0.1:8082",
		}

		node, err := NewRaftNode(ctx, cfg, nsStore, t.TempDir())
		require.NoError(t, err)
		defer func() { _ = node.Close() }()

		assert.False(t, node.IsTLS())
		assert.Equal(t, "8082", node.HTTPPort())
		assert.Equal(t, "8082", node.httpPort)
	})
}

func TestRaftAdvertise_DNSHostnamePreservedInTransport(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		RaftBind:      "127.0.0.1:0",
		RaftAdvertise: "grantory-0.headless:8081",
	}

	transport, err := NewTransport(cfg)
	require.NoError(t, err)
	defer func() { _ = transport.Close() }()

	assert.Equal(t, "grantory-0.headless:8081", string(transport.LocalAddr()), "transport.LocalAddr() must preserve DNS hostname string")
}

func TestIsMembershipConflict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{name: "nil error", err: nil, expected: false},
		{name: "generic unrelated error", err: errors.New("timeout connecting to peer"), expected: false},
		{name: "already exists lowercase", err: errors.New("a node with that id already exists"), expected: true},
		{name: "already exists mixed case", err: errors.New("Node ALREADY EXISTS in cluster configuration"), expected: true},
		{name: "conflict keyword", err: errors.New("configuration conflict detected"), expected: true},
		{name: "already part of keyword", err: errors.New("server is already part of the cluster"), expected: true},
		{name: "duplicate id keyword", err: errors.New("found duplicate ID in configuration: node-1"), expected: true},
		{name: "duplicate address keyword", err: errors.New("found duplicate address in configuration: 127.0.0.1:8081"), expected: true},
		{name: "wrapped conflict error", err: fmt.Errorf("raft membership mutation failed: %w", errors.New("node address conflict")), expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsMembershipConflict(tt.err))
		})
	}
}

func TestHopSecretDerivation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nsStore, err := store.NewNamespaceStore(ctx, t.TempDir())
	require.NoError(t, err)

	clusterSecret := "super-secure-cluster-secret-key-123"
	cfg1 := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-sec-1",
		RaftBootstrapExpect: 1,
		RaftClusterSecret:   clusterSecret,
	}

	node1, err := NewRaftNode(ctx, cfg1, nsStore, t.TempDir())
	require.NoError(t, err)
	defer func() { _ = node1.Close() }()

	cfg2 := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-sec-2",
		RaftBootstrapExpect: 1,
		RaftClusterSecret:   clusterSecret,
	}

	node2, err := NewRaftNode(ctx, cfg2, nsStore, t.TempDir())
	require.NoError(t, err)
	defer func() { _ = node2.Close() }()

	// Both nodes sharing RaftClusterSecret must derive identical hopSecret
	assert.Equal(t, node1.HopSecret(), node2.HopSecret())

	mac := hmac.New(sha256.New, []byte(clusterSecret))
	mac.Write([]byte("grantory-cluster-hop-secret"))
	var expectedSecret [32]byte
	copy(expectedSecret[:], mac.Sum(nil))
	assert.Equal(t, expectedSecret, node1.HopSecret())

	// Node without RaftClusterSecret generates random secret
	cfgNoSecret := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-random",
		RaftBootstrapExpect: 1,
	}

	nodeRandom, err := NewRaftNode(ctx, cfgNoSecret, nsStore, t.TempDir())
	require.NoError(t, err)
	defer func() { _ = nodeRandom.Close() }()

	assert.NotEqual(t, [32]byte{}, nodeRandom.HopSecret())
	assert.NotEqual(t, node1.HopSecret(), nodeRandom.HopSecret())
}

func TestRemoveServer_ByAddressAndByID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nsStore, err := store.NewNamespaceStore(ctx, t.TempDir())
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-lead",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, t.TempDir())
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	peer2ID := "peer-addr-test"
	peer2Addr := "127.0.0.1:19876"
	err = node.AddNonvoter(peer2ID, peer2Addr, 0, 5*time.Second)
	require.NoError(t, err)
	node.RegisterHTTPAddr(peer2ID, "http://peer2.example.com:8080")

	peer3ID := "peer-id-test"
	peer3Addr := "127.0.0.1:19877"
	err = node.AddNonvoter(peer3ID, peer3Addr, 0, 5*time.Second)
	require.NoError(t, err)
	node.RegisterHTTPAddr(peer3ID, "http://peer3.example.com:8080")

	// 1. Remove peer2 by its address string
	err = node.RemoveServer(peer2Addr, 0, 5*time.Second)
	require.NoError(t, err)

	// Verify peer2 is removed from raft configuration
	cfgFuture := node.raft.GetConfiguration()
	require.NoError(t, cfgFuture.Error())
	for _, srv := range cfgFuture.Configuration().Servers {
		assert.NotEqual(t, hashiraft.ServerID(peer2ID), srv.ID)
		assert.NotEqual(t, hashiraft.ServerAddress(peer2Addr), srv.Address)
	}
	assert.Empty(t, node.HTTPAddrFor(peer2ID))
	assert.Empty(t, node.HTTPAddrFor(peer2Addr))

	// 2. Remove peer3 by its ID string
	err = node.RemoveServer(peer3ID, 0, 5*time.Second)
	require.NoError(t, err)

	// Verify peer3 is removed from raft configuration
	cfgFuture = node.raft.GetConfiguration()
	require.NoError(t, cfgFuture.Error())
	for _, srv := range cfgFuture.Configuration().Servers {
		assert.NotEqual(t, hashiraft.ServerID(peer3ID), srv.ID)
		assert.NotEqual(t, hashiraft.ServerAddress(peer3Addr), srv.Address)
	}
	assert.Empty(t, node.HTTPAddrFor(peer3ID))
	assert.Empty(t, node.HTTPAddrFor(peer3Addr))

	// 3. Removing an already removed or unknown address returns ErrNotFound
	err = node.RemoveServer(peer2Addr, 0, 5*time.Second)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound), "expected ErrNotFound when removing by unknown address, got: %v", err)
}

func TestAddVoter_Idempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nsStore1, err := store.NewNamespaceStore(ctx, t.TempDir())
	require.NoError(t, err)

	cfg1 := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 1,
	}

	node1, err := NewRaftNode(ctx, cfg1, nsStore1, t.TempDir())
	require.NoError(t, err)
	defer func() { _ = node1.Close() }()

	require.Eventually(t, func() bool {
		return node1.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	nsStore2, err := store.NewNamespaceStore(ctx, t.TempDir())
	require.NoError(t, err)

	cfg2 := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-2",
		RaftBootstrapExpect: 0,
	}

	node2, err := NewRaftNode(ctx, cfg2, nsStore2, t.TempDir())
	require.NoError(t, err)
	defer func() { _ = node2.Close() }()

	voterID := "node-2"
	voterAddr := node2.RaftAddress()
	require.NotEmpty(t, voterAddr)

	// 1. Initial AddVoter succeeds
	err = node1.AddVoter(voterID, voterAddr, 0, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, voterID, node1.ServerIDByAddr(voterAddr))
	assert.Equal(t, voterAddr, node1.AddrByServerID(voterID))

	// 2. Calling AddVoter again with identical ID and address succeeds idempotently
	err = node1.AddVoter(voterID, voterAddr, 0, 5*time.Second)
	require.NoError(t, err, "idempotent AddVoter should return nil when server already exists with same ID and address")
	assert.Equal(t, voterID, node1.ServerIDByAddr(voterAddr))
	assert.Equal(t, voterAddr, node1.AddrByServerID(voterID))

	// 3. Calling AddVoter with different ID but same address returns membership conflict error
	err = node1.AddVoter("node-3", voterAddr, 0, 5*time.Second)
	require.Error(t, err)
	assert.True(t, IsMembershipConflict(err), "conflicting ID with same address must return membership conflict: %v", err)
}

func TestNewRaftNode_PostgresDSNGuard(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nsStore, err := store.NewNamespaceStore(ctx, t.TempDir())
	require.NoError(t, err)

	t.Run("rejects cfg.Database with postgres DSN without creating directories", func(t *testing.T) {
		tempParent := t.TempDir()
		dataDir := filepath.Join(tempParent, "raft-node-data")

		cfg := config.Config{
			Database:            "postgres://user:secret@localhost:5432/grantory?sslmode=disable",
			RaftBind:            "127.0.0.1:0",
			RaftNodeID:          "node-pg-test",
			RaftBootstrapExpect: 1,
		}

		node, err := NewRaftNode(ctx, cfg, nsStore, dataDir)
		require.Error(t, err)
		assert.EqualError(t, err, "raft clustering is not supported with postgresql backend")
		assert.Nil(t, node)

		_, statErr := os.Stat(dataDir)
		assert.True(t, os.IsNotExist(statErr), "dataDir should not have been created on disk")
	})

	t.Run("rejects cfg.Database with postgresql DSN without creating directories", func(t *testing.T) {
		tempParent := t.TempDir()
		dataDir := filepath.Join(tempParent, "raft-node-data-postgresql")

		cfg := config.Config{
			Database:            "postgresql://user:secret@localhost:5432/grantory?sslmode=disable",
			RaftBind:            "127.0.0.1:0",
			RaftNodeID:          "node-pg-test-2",
			RaftBootstrapExpect: 1,
		}

		node, err := NewRaftNode(ctx, cfg, nsStore, dataDir)
		require.Error(t, err)
		assert.EqualError(t, err, "raft clustering is not supported with postgresql backend")
		assert.Nil(t, node)

		_, statErr := os.Stat(dataDir)
		assert.True(t, os.IsNotExist(statErr), "dataDir should not have been created on disk")
	})

	t.Run("rejects dataDir with postgres DSN without creating directories", func(t *testing.T) {
		cfg := config.Config{
			Database:            "",
			RaftBind:            "127.0.0.1:0",
			RaftNodeID:          "node-pg-test-3",
			RaftBootstrapExpect: 1,
		}

		dataDir := "postgres://user:secret@localhost:5432/grantory?sslmode=disable"
		node, err := NewRaftNode(ctx, cfg, nsStore, dataDir)
		require.Error(t, err)
		assert.EqualError(t, err, "raft clustering is not supported with postgresql backend")
		assert.Nil(t, node)

		_, statErr := os.Stat(dataDir)
		assert.True(t, os.IsNotExist(statErr), "dataDir should not have been created on disk")
	})
}

func TestRemoveServer_RejectActiveLeaderRemoval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nsStore, err := store.NewNamespaceStore(ctx, t.TempDir())
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:19988",
		RaftNodeID:          "node-lead",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, t.TempDir())
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// 1. Removing active leader by ID is rejected
	err = node.RemoveServer("node-lead", 0, 5*time.Second)
	require.Error(t, err)
	assert.EqualError(t, err, "cannot remove active cluster leader; step down leadership via /api/v1/cluster/step-down or stop the node to elect a new leader before removal")

	// 2. Removing active leader by advertised address is rejected
	err = node.RemoveServer("127.0.0.1:19988", 0, 5*time.Second)
	require.Error(t, err)
	assert.EqualError(t, err, "cannot remove active cluster leader; step down leadership via /api/v1/cluster/step-down or stop the node to elect a new leader before removal")

	// 3. Removing active leader by transport address is rejected
	transportAddr := node.RaftAddress()
	require.NotEmpty(t, transportAddr)
	err = node.RemoveServer(transportAddr, 0, 5*time.Second)
	require.Error(t, err)
	assert.EqualError(t, err, "cannot remove active cluster leader; step down leadership via /api/v1/cluster/step-down or stop the node to elect a new leader before removal")
}

func TestRaftNode_StepDown(t *testing.T) {
	t.Parallel()

	// 1. Uninitialized node: nil receiver
	var nilNode *RaftNode
	err := nilNode.StepDown()
	assert.EqualError(t, err, "raft not initialized")

	// 2. Uninitialized node: empty struct (nil raft)
	emptyNode := &RaftNode{}
	err = emptyNode.StepDown()
	assert.EqualError(t, err, "raft not initialized")

	// 3. Non-leader node
	nonLeader := &RaftNode{
		raft:             &hashiraft.Raft{},
		isLeaderOverride: func() bool { return false },
	}
	err = nonLeader.StepDown()
	assert.EqualError(t, err, "not the cluster leader")

	// 4. Leader node with stepDownOverride success
	stepDownCalled := false
	leaderNode := &RaftNode{
		isLeaderOverride: func() bool { return true },
		stepDownOverride: func() error {
			stepDownCalled = true
			return nil
		},
	}
	err = leaderNode.StepDown()
	assert.NoError(t, err)
	assert.True(t, stepDownCalled)

	// 5. Leader node with stepDownOverride error
	expectedErr := errors.New("leadership transfer failed")
	failingLeaderNode := &RaftNode{
		isLeaderOverride: func() bool { return true },
		stepDownOverride: func() error {
			return expectedErr
		},
	}
	err = failingLeaderNode.StepDown()
	assert.ErrorIs(t, err, expectedErr)
}

func TestRaftNode_StepDown_RealRaftNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nsStore, err := store.NewNamespaceStore(ctx, t.TempDir())
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-stepdown-real",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, t.TempDir())
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// In a single-node cluster, LeadershipTransfer is invoked directly on hashiraft.Raft;
	// it will return an error because there are no other peers to transfer leadership to.
	err = node.StepDown()
	require.Error(t, err)
	assert.True(t, strings.Contains(strings.ToLower(err.Error()), "cannot find peer") || strings.Contains(strings.ToLower(err.Error()), "cannot transfer leadership"), "expected cannot find peer or cannot transfer leadership, got: %v", err)
}

func TestPropose_NodeContextCanceled(t *testing.T) {
	t.Parallel()

	nodeCtx, cancel := context.WithCancel(context.Background())
	cancel()

	node := &RaftNode{
		raft:    &hashiraft.Raft{},
		nodeCtx: nodeCtx,
	}

	resp, err := node.Propose(context.Background(), RaftCommand{Type: "test"})
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, ApplyResponse{}, resp)
}

func TestPropose_ClosedNodeReturnsContextCanceled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nsStore, err := store.NewNamespaceStore(ctx, t.TempDir())
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-propose-close",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, t.TempDir())
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	require.NoError(t, node.Close())

	resp, err := node.Propose(context.Background(), RaftCommand{Type: "test"})
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, ApplyResponse{}, resp)
}

func TestCleanupStagingDirs(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	dir1 := filepath.Join(baseDir, "dir1")
	dir2 := filepath.Join(baseDir, "dir2")
	require.NoError(t, os.MkdirAll(dir1, 0o755))
	require.NoError(t, os.MkdirAll(dir2, 0o755))

	// Transient directories in dir1
	snapStage1 := filepath.Join(dir1, "snap-stage-12345")
	restore1 := filepath.Join(dir1, "grantory-restore-67890")
	keepDir1 := filepath.Join(dir1, "keep-dir")
	keepFile1 := filepath.Join(dir1, "snap-stage-file.txt")

	require.NoError(t, os.MkdirAll(snapStage1, 0o755))
	require.NoError(t, os.MkdirAll(restore1, 0o755))
	require.NoError(t, os.MkdirAll(keepDir1, 0o755))
	require.NoError(t, os.WriteFile(keepFile1, []byte("data"), 0o644))

	// Transient directory in dir2
	restore2 := filepath.Join(dir2, "grantory-restore-abcde")
	keepDir2 := filepath.Join(dir2, "keep-dir-2")
	require.NoError(t, os.MkdirAll(restore2, 0o755))
	require.NoError(t, os.MkdirAll(keepDir2, 0o755))

	// Call CleanupStagingDirs including edge cases (empty string, postgres DSN, nonexistent directory)
	CleanupStagingDirs(
		dir1,
		dir2,
		"",
		"postgres://user:secret@localhost:5432/grantory?sslmode=disable",
		filepath.Join(baseDir, "nonexistent"),
	)

	// Verify transient staging dirs were removed
	_, err := os.Stat(snapStage1)
	assert.True(t, os.IsNotExist(err), "snap-stage-12345 must be removed")
	_, err = os.Stat(restore1)
	assert.True(t, os.IsNotExist(err), "grantory-restore-67890 must be removed")
	_, err = os.Stat(restore2)
	assert.True(t, os.IsNotExist(err), "grantory-restore-abcde must be removed")

	// Verify non-transient dirs and files are kept
	_, err = os.Stat(keepDir1)
	assert.NoError(t, err, "keep-dir must be preserved")
	_, err = os.Stat(keepDir2)
	assert.NoError(t, err, "keep-dir-2 must be preserved")
	_, err = os.Stat(keepFile1)
	assert.NoError(t, err, "snap-stage-file.txt regular file must be preserved")
}

type mockNodeConfigFuture struct {
	cfg hashiraft.Configuration
	err error
}

func (m *mockNodeConfigFuture) Error() error { return m.err }
func (m *mockNodeConfigFuture) Configuration() hashiraft.Configuration { return m.cfg }
func (m *mockNodeConfigFuture) Index() uint64 { return 1 }

func TestClusterServers(t *testing.T) {
	t.Parallel()

	// 1. Nil node
	var nilNode *RaftNode
	assert.Nil(t, nilNode.ClusterServers())

	// 2. Uninitialized node
	emptyNode := &RaftNode{}
	assert.Nil(t, emptyNode.ClusterServers())

	// 3. Configuration query error
	errNode := &RaftNode{
		getConfigOverride: func() hashiraft.ConfigurationFuture {
			return &mockNodeConfigFuture{err: errors.New("config failed")}
		},
	}
	assert.Nil(t, errNode.ClusterServers())

	// 4. Configuration with voter, nonvoter, and staging
	mockNode := &RaftNode{
		getConfigOverride: func() hashiraft.ConfigurationFuture {
			return &mockNodeConfigFuture{
				cfg: hashiraft.Configuration{
					Servers: []hashiraft.Server{
						{
							ID:       hashiraft.ServerID("node-1"),
							Address:  hashiraft.ServerAddress("10.0.0.1:8080"),
							Suffrage: hashiraft.Voter,
						},
						{
							ID:       hashiraft.ServerID("node-2"),
							Address:  hashiraft.ServerAddress("10.0.0.2:8080"),
							Suffrage: hashiraft.Nonvoter,
						},
						{
							ID:       hashiraft.ServerID("node-3"),
							Address:  hashiraft.ServerAddress("10.0.0.3:8080"),
							Suffrage: hashiraft.Staging,
						},
					},
				},
			}
		},
	}
	servers := mockNode.ClusterServers()
	require.Len(t, servers, 3)
	assert.Equal(t, []ServerInfo{
		{ID: "node-1", Address: "10.0.0.1:8080", Suffrage: "voter"},
		{ID: "node-2", Address: "10.0.0.2:8080", Suffrage: "nonvoter"},
		{ID: "node-3", Address: "10.0.0.3:8080", Suffrage: "staging"},
	}, servers)
}

func TestClusterServers_LiveNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nsStore, err := store.NewNamespaceStore(ctx, t.TempDir())
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-servers-test",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, t.TempDir())
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	servers := node.ClusterServers()
	require.Len(t, servers, 1)
	assert.Equal(t, "node-servers-test", servers[0].ID)
	assert.Equal(t, "voter", servers[0].Suffrage)
	assert.NotEmpty(t, servers[0].Address)
}
