package raft

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hashiraft "github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
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
		certDir := t.TempDir()
		_, certFile, keyFile := generateTestCertificates(t, certDir)

		cfg := config.Config{
			RaftBind:            "127.0.0.1:0",
			RaftNodeID:          "tls-off-test",
			RaftBootstrapExpect: 1,
			TLSCert:             certFile,
			TLSKey:              keyFile,
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
		certDir := t.TempDir()
		_, certFile, keyFile := generateTestCertificates(t, certDir)

		cfg := config.Config{
			RaftBind:            "127.0.0.1:0",
			RaftNodeID:          "tls-empty-test",
			RaftBootstrapExpect: 1,
			TLSCert:             certFile,
			TLSKey:              keyFile,
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
	assert.True(t, errors.Is(err, ErrNotLeader))

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

func TestNewRaftNode_AutoJoinSkippedWhenClusterSecretEmpty(t *testing.T) {
	leaderListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	leaderAddr := leaderListener.Addr().String()

	leaderServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cluster/status":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "existing-leader",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: leaderAddr,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go func() { _ = leaderServer.Serve(leaderListener) }()
	defer func() { _ = leaderServer.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:18091",
		RaftNodeID:          "new-node",
		RaftAutoJoin:        true,
		RaftClusterSecret:   "", // empty secret: auto-join MUST be skipped
		RaftBootstrapExpect: 1,
		RaftPeers:           []string{"node-leader=127.0.0.2:9300@http://" + leaderAddr},
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	// Because cluster secret is empty, auto-join is skipped and node bootstraps as leader
	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	confFuture := node.raft.GetConfiguration()
	require.NoError(t, confFuture.Error())
	assert.Len(t, confFuture.Configuration().Servers, 1)
	assert.Equal(t, hashiraft.ServerID("new-node"), confFuture.Configuration().Servers[0].ID)
}

func TestHeadlessDNSStabilization_EarlyExitWhenAllPeersResolvedAndNoLeader(t *testing.T) {
	mockLookup := func(host string) ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("127.0.0.2"),
			net.ParseIP("127.0.0.3"),
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:18081",
		RaftNodeID:          "127.0.0.1:18081",
		RaftAutoJoin:        true,
		RaftClusterSecret:   "test-secret",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"headless.grantory:18081"},
	}

	start := time.Now()
	node, err := NewRaftNode(ctx, cfg, nsStore, dir,
		WithDNSResolver(newDNSResolver(10*time.Millisecond, mockLookup)),
		WithDNSWaitTimeout(10*time.Second),
		WithDNSRetryInterval(20*time.Millisecond),
	)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	duration := time.Since(start)
	// Without early exit from leaderRetryLoop, this waits 10s. With early exit, it finishes < 3s.
	assert.Less(t, duration, 3*time.Second, "expected early exit from leaderRetryLoop when all peers resolved and no leader")

	confFuture := node.raft.GetConfiguration()
	require.NoError(t, confFuture.Error())
	assert.Len(t, confFuture.Configuration().Servers, 3)
}

func TestFollower_ZeroBootstrapExpect_StartsBackgroundJoinWhenLeaderInitiallyDown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	// Pick a free port for mock leader server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	leaderAddr := listener.Addr().String()
	require.NoError(t, listener.Close())

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:18092",
		RaftNodeID:          "follower-node",
		RaftAutoJoin:        true,
		RaftClusterSecret:   "secret",
		RaftBootstrapExpect: 0,
		RaftPeers:           []string{"leader-node=127.0.0.2:9300@http://" + leaderAddr},
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	// Start mock leader HTTP server on leaderAddr
	joinedChan := make(chan struct{}, 1)
	leaderListener, err := net.Listen("tcp", leaderAddr)
	require.NoError(t, err)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cluster/status":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "leader-node",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.2:9300",
			})
		case "/api/v1/cluster/join":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			select {
			case joinedChan <- struct{}{}:
			default:
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go func() { _ = server.Serve(leaderListener) }()
	defer func() { _ = server.Close() }()

	select {
	case <-joinedChan:
		// Succeeded
	case <-time.After(5 * time.Second):
		t.Fatal("expected follower to auto-join leader in background, but join was not requested")
	}

	require.Eventually(t, func() bool {
		return node.AutoJoinStatus() == "joined"
	}, 2*time.Second, 50*time.Millisecond)
}

func TestDiscoverActiveLeader_RespectsRaftPeerHTTPAddrs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	statusHitChan := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/status" {
			select {
			case statusHitChan <- struct{}{}:
			default:
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "node-2",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.2:9302",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := config.Config{
		RaftPeers:         []string{"node-2=127.0.0.2:9302"},
		RaftPeerHTTPAddrs: []string{"node-2=" + server.URL},
		RaftClusterSecret: "secret",
	}

	peers := parsePeers(cfg.RaftPeers, "9302", false, nil)
	peers = applyPeerHTTPAddrs(peers, cfg.RaftPeerHTTPAddrs)

	localAliases := map[string]bool{"127.0.0.1:9300": true}
	leaderURL := DiscoverActiveLeader(ctx, cfg, peers, localAliases, nil)
	assert.Equal(t, server.URL, leaderURL)

	select {
	case <-statusHitChan:
	default:
		t.Fatal("expected leader discovery to query mock server via RaftPeerHTTPAddrs")
	}
}

func TestAutoJoinStatus(t *testing.T) {
	var nilNode *RaftNode
	assert.Equal(t, "", nilNode.AutoJoinStatus())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	node := &RaftNode{
		cfg:        config.Config{},
		nodeCtx:    ctx,
		nodeCancel: cancel,
		autoJoinBackoff: func(attempt int) time.Duration {
			return 1 * time.Millisecond
		},
	}

	assert.Equal(t, "", node.AutoJoinStatus())

	joinDone := make(chan struct{})
	go func() {
		node.startAutoJoinRetry(ts.URL, "node-1", "127.0.0.1:9301", "http://127.0.0.1:8080")
		close(joinDone)
	}()

	require.Eventually(t, func() bool {
		return node.AutoJoinStatus() == "exhausted"
	}, 3*time.Second, 20*time.Millisecond, "node status should reach exhausted after 30 attempts")

	time.Sleep(50 * time.Millisecond)
	select {
	case <-joinDone:
		t.Fatal("startAutoJoinRetry terminated after exhaustion instead of continuing background retry loop")
	default:
	}

	cancel()
	select {
	case <-joinDone:
	case <-time.After(1 * time.Second):
		t.Fatal("startAutoJoinRetry failed to terminate after context cancellation")
	}
}

func TestDNSStabilization_NoDoubleWait(t *testing.T) {
	mockLookup := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:18082",
		RaftNodeID:          "127.0.0.1:18082",
		RaftAutoJoin:        true,
		RaftClusterSecret:   "test-secret",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"headless.grantory:18082"},
	}

	dnsWait := 200 * time.Millisecond
	start := time.Now()
	node, err := NewRaftNode(ctx, cfg, nsStore, dir,
		WithDNSResolver(newDNSResolver(10*time.Millisecond, mockLookup)),
		WithDNSWaitTimeout(dnsWait),
		WithDNSRetryInterval(20*time.Millisecond),
	)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	elapsed := time.Since(start)
	assert.Less(t, elapsed, 350*time.Millisecond, "should not wait double dnsWaitTimeout")
}

func TestNewRaftNode_InvalidClusterTLSConfig_FailsFast(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:   "127.0.0.1:0",
		RaftCAFile: filepath.Join(dir, "nonexistent-ca.crt"),
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	if node != nil {
		_ = node.Close()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build cluster TLS config")
}

func TestLeaderRetryLoop_FlushesResolverCacheOnTick(t *testing.T) {
	var lookupCalls atomic.Int64

	leaderListener, err := net.Listen("tcp", "127.0.0.2:0")
	require.NoError(t, err)
	defer func() { _ = leaderListener.Close() }()

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/status" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "node-leader",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.2:9302",
			})
			return
		}
		if r.URL.Path == "/api/v1/cluster/join" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})}
	go func() { _ = server.Serve(leaderListener) }()
	defer func() { _ = server.Close() }()

	serverURL := "http://" + leaderListener.Addr().String()
	srvPort := config.ExtractPort(serverURL)

	mockLookup := func(host string) ([]net.IP, error) {
		calls := lookupCalls.Add(1)
		if calls == 1 {
			// Initially returns an unreachable dummy IP on loopback
			return []net.IP{net.ParseIP("127.0.0.99")}, nil
		}
		// On tick flush, returns 127.0.0.2 where leader server is running
		return []net.IP{net.ParseIP("127.0.0.2")}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:18083",
		RaftNodeID:          "127.0.0.1:18083",
		RaftAutoJoin:        true,
		RaftClusterSecret:   "test-secret",
		RaftBootstrapExpect: 0,
		RaftPeers:           []string{"headless.grantory:" + srvPort},
		RaftPeerHTTPAddrs:   []string{"127.0.0.2=" + serverURL},
	}

	dnsWait := 2 * time.Second
	retryInterval := 20 * time.Millisecond
	resolver := newDNSResolver(1*time.Minute, mockLookup)

	start := time.Now()
	node, err := NewRaftNode(ctx, cfg, nsStore, dir,
		WithDNSResolver(resolver),
		WithDNSWaitTimeout(dnsWait),
		WithDNSRetryInterval(retryInterval),
	)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, lookupCalls.Load(), int64(2), "lookup calls should occur on tick when resolver cache is flushed")
	assert.Less(t, elapsed, 1*time.Second, "leader should be discovered quickly on tick rather than waiting full timeout")
}


func TestNewRaftNode_TLSCert_PreflightCheck_FailsFast(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind: "127.0.0.1:0",
		TLSCert:  filepath.Join(dir, "nonexistent-tls.crt"),
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	if node != nil {
		_ = node.Close()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build cluster TLS config")
}

func TestLeaderRetryLoop_HeadlessDNSDiscoversNewPeersOnTick(t *testing.T) {
	var lookupCalls atomic.Int64
	mockLookup := func(host string) ([]net.IP, error) {
		calls := lookupCalls.Add(1)
		if calls == 1 {
			// Initially returns only 1 IP (self)
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		// Subsequent lookups return 3 IPs
		return []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("127.0.0.2"),
			net.ParseIP("127.0.0.3"),
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:18082",
		RaftNodeID:          "127.0.0.1:18082",
		RaftAutoJoin:        true,
		RaftClusterSecret:   "test-secret",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"headless.grantory:18082"},
	}

	// Short TTL so subsequent tick lookups hit mockLookup and discover new IPs
	resolver := newDNSResolver(15*time.Millisecond, mockLookup)

	start := time.Now()
	node, err := NewRaftNode(ctx, cfg, nsStore, dir,
		WithDNSResolver(resolver),
		WithDNSWaitTimeout(2*time.Second),
		WithDNSRetryInterval(20*time.Millisecond),
	)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	elapsed := time.Since(start)
	assert.Less(t, elapsed, 1*time.Second, "should discover all expected bootstrap peers quickly on subsequent ticks")
}

func TestLeaderRetryLoop_WaitsAtLeastOneRetryIntervalBeforeBootstrap(t *testing.T) {
	var lookupCalls atomic.Int64
	mockLookup := func(host string) ([]net.IP, error) {
		lookupCalls.Add(1)
		// Immediately return all 3 bootstrap candidate IPs on the very first call
		return []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("127.0.0.2"),
			net.ParseIP("127.0.0.3"),
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:18082",
		RaftNodeID:          "127.0.0.1:18082",
		RaftAutoJoin:        true,
		RaftClusterSecret:   "test-secret",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"headless.grantory:18082"},
	}

	retryInterval := 80 * time.Millisecond
	dnsWait := 2 * time.Second
	resolver := newDNSResolver(15*time.Millisecond, mockLookup)

	start := time.Now()
	node, err := NewRaftNode(ctx, cfg, nsStore, dir,
		WithDNSResolver(resolver),
		WithDNSWaitTimeout(dnsWait),
		WithDNSRetryInterval(retryInterval),
	)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, 60*time.Millisecond, "should wait at least one retry interval before concluding no leader and bootstrapping")
}

func TestNewRaftNode_RaftKeyFileWithoutCert_PreflightFailsFast(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:    "127.0.0.1:0",
		RaftKeyFile: filepath.Join(dir, "nonexistent-raft.key"),
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	if node != nil {
		_ = node.Close()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build cluster TLS config")
}

func TestNewRaftNode_TLSKeyWithoutCert_PreflightFailsFast(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind: "127.0.0.1:0",
		TLSKey:   filepath.Join(dir, "nonexistent-tls.key"),
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	if node != nil {
		_ = node.Close()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build cluster TLS config")
}

func TestNewRaftNode_BootstrapExpectSkipped_LaunchesBackgroundAutoJoin(t *testing.T) {
	leaderListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = leaderListener.Close() }()

	var leaderReady atomic.Bool
	var joinReceived atomic.Bool
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/status" {
			if !leaderReady.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "leader-node",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.1:9302",
			})
			return
		}
		if r.URL.Path == "/api/v1/cluster/join" {
			joinReceived.Store(true)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})}
	go func() { _ = server.Serve(leaderListener) }()
	defer func() { _ = server.Close() }()

	leaderHTTP := "http://" + leaderListener.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:18084",
		RaftNodeID:          "127.0.0.1:18084",
		RaftAutoJoin:        true,
		RaftClusterSecret:   "test-secret",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"127.0.0.1:9302"},
		RaftPeerHTTPAddrs:   []string{"127.0.0.1:9302=" + leaderHTTP},
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir,
		WithDNSWaitTimeout(50*time.Millisecond),
		WithDNSRetryInterval(10*time.Millisecond),
	)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	// Leader is not ready during startup; bootstrap was skipped because servers < 3.
	// Now leader becomes available.
	leaderReady.Store(true)

	// Because bootstrap expect was 3 and only 1 peer was discovered (total 2 servers < 3),
	// bootstrap was skipped. The node must launch background auto-join and join the leader.
	assert.Eventually(t, func() bool {
		return node.AutoJoinStatus() == "joined" && joinReceived.Load()
	}, 1*time.Second, 50*time.Millisecond, "node should background auto-join the leader after bootstrap is skipped")
}

func TestSetHTTPPort_NodeRestartWithExistingState_ResolvesLeaderAndSendsUpdate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var joinReceived atomic.Bool
	var updatedHTTPAddr atomic.Value
	leaderServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/join" {
			var req ClusterJoinRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
				joinReceived.Store(true)
				updatedHTTPAddr.Store(req.HTTPAddress)
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer leaderServer.Close()

	// 1. Leader node
	dir1 := t.TempDir()
	nsStore1, err := store.NewNamespaceStore(ctx, dir1)
	require.NoError(t, err)

	cfg1 := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 1,
	}
	node1, err := NewRaftNode(ctx, cfg1, nsStore1, dir1)
	require.NoError(t, err)
	defer func() { _ = node1.Close() }()

	require.Eventually(t, func() bool {
		return node1.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// 2. Follower node with state
	dir2 := t.TempDir()
	nsStore2, err := store.NewNamespaceStore(ctx, dir2)
	require.NoError(t, err)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	raftBind2 := l2.Addr().String()
	require.NoError(t, l2.Close())

	cfg2 := config.Config{
		RaftBind:            raftBind2,
		RaftNodeID:          "node-2",
		RaftBootstrapExpect: 0,
		BindAddr:            "127.0.0.1:0",
		RaftPeers:           []string{node1.RaftAddress()},
		RaftPeerHTTPAddrs:   []string{node1.RaftAddress() + "=" + leaderServer.URL},
		RaftClusterSecret:   "test-secret",
	}

	node2, err := NewRaftNode(ctx, cfg2, nsStore2, dir2)
	require.NoError(t, err)

	// Add node2 to leader so it replicates state
	err = node1.AddVoter("node-2", node2.RaftAddress(), 0, 5*time.Second)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return node2.LeaderAddr() == node1.RaftAddress()
	}, 5*time.Second, 50*time.Millisecond)

	// 3. Shut down node2 cleanly - it now has existing state in dir2
	require.NoError(t, node2.Close())

	// 4. Restart node2 from the same directory (hasState == true)
	nsStore2Restart, err := store.NewNamespaceStore(ctx, dir2)
	require.NoError(t, err)

	node2Restart, err := NewRaftNode(ctx, cfg2, nsStore2Restart, dir2)
	require.NoError(t, err)
	defer func() { _ = node2Restart.Close() }()

	require.Eventually(t, func() bool {
		return node2Restart.LeaderAddr() == node1.RaftAddress()
	}, 5*time.Second, 50*time.Millisecond)

	// Verify lastJoinedLeader is empty on restart with existing state
	assert.Empty(t, node2Restart.LastJoinedLeader())

	// Reset joinReceived flag before calling SetHTTPPort
	joinReceived.Store(false)

	// 5. Dynamic port allocated and configured on restarted node
	node2Restart.SetHTTPPort("54321")

	// 6. Node with existing state must resolve leader and send updated join request
	assert.Eventually(t, func() bool {
		return joinReceived.Load()
	}, 3*time.Second, 50*time.Millisecond, "restarted node with existing state should resolve leader and send updated join request")

	assert.Equal(t, "http://127.0.0.1:54321", updatedHTTPAddr.Load())
}

func TestRaftNode_NodeID_Concurrency(t *testing.T) {
	t.Parallel()

	node := &RaftNode{
		nodeID: "initial-node-id",
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				_ = node.NodeID()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 500; j++ {
			node.mu.Lock()
			node.nodeID = fmt.Sprintf("node-id-%d", j)
			node.mu.Unlock()
		}
	}()

	wg.Wait()
}

func TestSetHTTPPort_LeaderRegistersLocallyWithoutHTTPJoin(t *testing.T) {
	t.Parallel()

	var joinCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&joinCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.Config{
		BindAddr:      ":0",
		RaftAdvertise: "127.0.0.1:9000",
	}
	node := &RaftNode{
		cfg:              cfg,
		nodeID:           "leader-node",
		advAddr:          "127.0.0.1:9000",
		httpAddrs:        make(map[string]string),
		staticHTTPAddrs:  make(map[string]string),
		isLeaderOverride: func() bool { return true },
		lastJoinedLeader: srv.URL,
	}

	node.SetHTTPPort("8080")

	assert.Equal(t, "http://127.0.0.1:8080", node.HTTPAddrFor("leader-node"))
	assert.Equal(t, "http://127.0.0.1:8080", node.HTTPAddrFor("127.0.0.1:9000"))
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(0), atomic.LoadInt32(&joinCalls), "leader must not send HTTP join request to itself")
}

func TestNewRaftNode_InvalidClusterTLSConfig_DNSStabilization_ClosesBoltStore(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	caFile, certFile, keyFile := generateTestCertificates(t, dir)

	cfg := config.Config{
		RaftBind:          "127.0.0.1:0",
		RaftClusterSecret: "test-secret",
		RaftAutoJoin:      true,
		RaftPeers:         []string{"dns:peer.cluster.local:9300"},
		RaftCAFile:        caFile,
		RaftCertFile:      certFile,
		RaftKeyFile:       keyFile,
	}

	// Custom resolver corrupts the CA file when resolving the DNS peer during stabilization check
	corruptOnce := sync.Once{}
	customResolver := newDNSResolver(10*time.Millisecond, func(host string) ([]net.IP, error) {
		corruptOnce.Do(func() {
			_ = os.WriteFile(caFile, []byte("corrupted ca data"), 0600)
		})
		return nil, errors.New("dns resolution failure")
	})

	node, err := NewRaftNode(ctx, cfg, nsStore, dir,
		WithDNSResolver(customResolver),
		WithDNSWaitTimeout(200*time.Millisecond),
		WithDNSRetryInterval(50*time.Millisecond),
	)
	if node != nil {
		_ = node.Close()
	}
	require.Error(t, err)

	// Verify bolt store was cleanly closed and can be reopened without file lock contention
	dbPath := filepath.Join(dir, RaftDirName, RaftDBFileName)
	bs, openErr := raftboltdb.New(raftboltdb.Options{
		Path: dbPath,
		BoltOptions: &bbolt.Options{
			Timeout: 200 * time.Millisecond,
		},
	})
	require.NoError(t, openErr, "boltStore must be cleanly closed after TLS error during DNS stabilization")
	if bs != nil {
		_ = bs.Close()
	}
}

func TestSetHTTPPort_LeaderProposesRegisterNodeHTTPAddr(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:19989",
		RaftNodeID:          "node-lead-test",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	appliedBefore := node.raft.AppliedIndex()

	node.SetHTTPPort("8088")

	require.Eventually(t, func() bool {
		return node.raft.AppliedIndex() > appliedBefore
	}, 5*time.Second, 50*time.Millisecond)

	var lastLog hashiraft.Log
	err = node.logStore.GetLog(node.raft.AppliedIndex(), &lastLog)
	require.NoError(t, err)
	cmd, err := DecodeCommand(lastLog.Data)
	require.NoError(t, err)
	assert.Equal(t, CmdRegisterNodeHTTPAddr, cmd.Type)

	var payload RegisterNodeHTTPAddrPayload
	err = json.Unmarshal(cmd.Payload, &payload)
	require.NoError(t, err)
	assert.Equal(t, "node-lead-test", payload.ServerID)
	assert.Equal(t, "127.0.0.1:19989", payload.Address)
	assert.Equal(t, "http://127.0.0.1:8088", payload.HTTPAddr)

	assert.Equal(t, "http://127.0.0.1:8088", node.HTTPAddrFor("node-lead-test"))
	assert.Equal(t, "http://127.0.0.1:8088", node.HTTPAddrFor("127.0.0.1:19989"))
}

func TestSetHTTPPort_FollowerRetriesWhenLeaderInitiallyDown(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	var attempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cluster/join" {
			current := attempts.Add(1)
			if current <= 4 {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"leader unavailable"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"joined"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		BindAddr:          "127.0.0.1:0",
		RaftAdvertise:     "127.0.0.1:9305",
		RaftClusterSecret: "test-secret",
	}

	node := &RaftNode{
		cfg:              cfg,
		nodeCtx:          ctx,
		nodeCancel:       cancel,
		nodeID:           "follower-node",
		advAddr:          "127.0.0.1:9305",
		lastJoinedLeader: server.URL,
		autoJoinBackoff: func(attempt int) time.Duration {
			return 20 * time.Millisecond
		},
	}

	node.SetHTTPPort("54322")

	// Verify that it retried across failures (including entering background retry) and eventually succeeded
	require.Eventually(t, func() bool {
		return attempts.Load() >= 5
	}, 3*time.Second, 50*time.Millisecond, "should retry beyond fast attempts until registration succeeds")

	// Verify warnings were logged for the failures
	var foundWarn bool
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "failed to update leader with dynamic HTTP address") {
			foundWarn = true
			break
		}
	}
	assert.True(t, foundWarn, "should log warning on failed update attempts")
}

func TestSetHTTPPort_StartupRace_RegistersOnceLeaderElected(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:19990",
		RaftNodeID:          "node-startup-race-test",
		RaftBootstrapExpect: 1,
		RaftClusterSecret:   "test-secret",
		BindAddr:            "127.0.0.1:0",
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	// Call SetHTTPPort BEFORE leadership is established
	node.SetHTTPPort("49152")

	// Wait for cluster leadership
	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// Verify that CmdRegisterNodeHTTPAddr is proposed and applied to the FSM registrar automatically
	require.Eventually(t, func() bool {
		if node.raft == nil {
			return false
		}
		appliedIndex := node.raft.AppliedIndex()
		if appliedIndex == 0 {
			return false
		}
		var lastLog hashiraft.Log
		if err := node.logStore.GetLog(appliedIndex, &lastLog); err != nil {
			return false
		}
		cmd, err := DecodeCommand(lastLog.Data)
		if err != nil {
			return false
		}
		if cmd.Type != CmdRegisterNodeHTTPAddr {
			return false
		}
		var payload RegisterNodeHTTPAddrPayload
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			return false
		}
		return payload.ServerID == "node-startup-race-test" &&
			payload.Address == "127.0.0.1:19990" &&
			payload.HTTPAddr == "http://127.0.0.1:49152"
	}, 5*time.Second, 50*time.Millisecond)

	assert.Equal(t, "http://127.0.0.1:49152", node.HTTPAddrFor("node-startup-race-test"))
	assert.Equal(t, "http://127.0.0.1:49152", node.HTTPAddrFor("127.0.0.1:19990"))
}

func TestCoordinateDynamicHTTPPort_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	node := &RaftNode{
		cfg: config.Config{
			BindAddr: "127.0.0.1:0",
		},
		nodeCtx:  ctx,
		httpPort: "54321",
	}

	done := make(chan struct{})
	go func() {
		node.coordinateDynamicHTTPPort("54321", "http://127.0.0.1:54321", "node-1", "127.0.0.1:9300", nil, nil, "9300", false, true, node.cfg, ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Success: returned promptly on context cancellation without hanging
	case <-time.After(1 * time.Second):
		t.Fatal("coordinateDynamicHTTPPort did not exit promptly upon context cancellation")
	}
}

func TestCoordinateDynamicHTTPPort_FollowerWithoutClusterSecretExitsCleanly(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node := &RaftNode{
		cfg: config.Config{
			BindAddr:          "127.0.0.1:0",
			RaftClusterSecret: "",
		},
		nodeCtx:  ctx,
		httpPort: "54321",
	}

	done := make(chan struct{})
	go func() {
		node.coordinateDynamicHTTPPort("54321", "http://127.0.0.1:54321", "node-1", "127.0.0.1:9300", nil, nil, "9300", false, true, node.cfg, ctx)
		close(done)
	}()

	select {
	case <-done:
		// Success: returned cleanly without hanging
	case <-time.After(500 * time.Millisecond):
		t.Fatal("coordinateDynamicHTTPPort did not exit cleanly when cluster secret was empty")
	}
}

func TestCoordinateDynamicHTTPPort_StaticPortFollowerExitsImmediately(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node := &RaftNode{
		cfg: config.Config{
			BindAddr:          "127.0.0.1:8080",
			RaftClusterSecret: "test-secret",
		},
		nodeCtx:  ctx,
		httpPort: "8080",
	}

	done := make(chan struct{})
	start := time.Now()
	go func() {
		node.coordinateDynamicHTTPPort("8080", "http://127.0.0.1:8080", "node-1", "127.0.0.1:9300", nil, nil, "9300", false, false, node.cfg, ctx)
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		assert.Less(t, elapsed, 50*time.Millisecond, "static port follower should return immediately")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("coordinateDynamicHTTPPort did not exit immediately for static-port follower")
	}
}

func TestCoordinateDynamicHTTPPort_ExitsAfterMaxAttempts(t *testing.T) {
	t.Parallel()

	const secret = "test-secret"
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer "+secret, r.Header.Get("Authorization"))
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node := &RaftNode{
		cfg: config.Config{
			BindAddr:          "127.0.0.1:0",
			RaftClusterSecret: secret,
		},
		nodeCtx:          ctx,
		httpPort:         "54321",
		lastJoinedLeader: server.URL,
		autoJoinBackoff: func(attempt int) time.Duration {
			return 1 * time.Millisecond
		},
	}

	done := make(chan struct{})
	go func() {
		node.coordinateDynamicHTTPPort("54321", "http://127.0.0.1:54321", "node-1", "127.0.0.1:9300", nil, nil, "9300", false, true, node.cfg, ctx)
		close(done)
	}()

	select {
	case <-done:
		assert.Equal(t, int32(30), attempts.Load(), "should have made exactly maxAttempts (30) registration attempts")
	case <-time.After(2 * time.Second):
		t.Fatal("coordinateDynamicHTTPPort hung indefinitely and did not exit after reaching maxAttempts")
	}
}
