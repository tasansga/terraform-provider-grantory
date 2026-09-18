package raft

import (
	"errors"
	"net"
	"testing"
	"time"

	hashiraft "github.com/hashicorp/raft"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sync"
	"sync/atomic"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
)

func TestBuildBootstrapServers_AdvertiseMultiAddressPreserved(t *testing.T) {
	t.Parallel()

	customLookup := func(host string) ([]net.IP, error) {
		switch host {
		case "dualstack-adv.example.com":
			return []net.IP{
				net.ParseIP("192.168.1.10"),
				net.ParseIP("192.168.1.11"),
			}, nil
		case "peer2.example.com":
			return []net.IP{
				net.ParseIP("192.168.1.20"),
			}, nil
		default:
			return nil, errors.New("nxdomain")
		}
	}
	customRes := newDNSResolver(1*time.Minute, customLookup)

	cfg := config.Config{
		RaftBootstrapExpect: 3,
		RaftAdvertise:       "dualstack-adv.example.com:8081",
		RaftPeers:           []string{"node2=peer2.example.com:8081"},
	}

	servers, err := buildBootstrapServers(cfg, "local-node", "127.0.0.1:8081", nil, customRes)
	require.NoError(t, err)

	var addrs []string
	for _, s := range servers {
		addrs = append(addrs, string(s.Address))
	}

	// Verify both resolved IPs from the advertise address are preserved (not just advResolved[0])
	assert.Contains(t, addrs, "192.168.1.10:8081")
	assert.Contains(t, addrs, "192.168.1.11:8081")
	assert.Contains(t, addrs, "192.168.1.20:8081")
	assert.Len(t, addrs, 3)
}

func TestBuildBootstrapServers_AdvertiseIPv6MultiAddressPreserved(t *testing.T) {
	t.Parallel()

	customLookup := func(host string) ([]net.IP, error) {
		switch host {
		case "v6-adv.example.com":
			return []net.IP{
				net.ParseIP("2001:db8::1"),
				net.ParseIP("2001:db8::2"),
			}, nil
		case "peer2.example.com":
			return []net.IP{
				net.ParseIP("2001:db8::3"),
			}, nil
		default:
			return nil, errors.New("nxdomain")
		}
	}
	customRes := newDNSResolver(1*time.Minute, customLookup)

	cfg := config.Config{
		RaftBootstrapExpect: 3,
		RaftBind:            "[::]:8081",
		RaftAdvertise:       "v6-adv.example.com:8081",
		RaftPeers:           []string{"node2=peer2.example.com:8081"},
	}

	servers, err := buildBootstrapServers(cfg, "local-node", "[::1]:8081", nil, customRes)
	require.NoError(t, err)

	var addrs []string
	for _, s := range servers {
		addrs = append(addrs, string(s.Address))
	}

	assert.Contains(t, addrs, "[2001:db8::1]:8081")
	assert.Contains(t, addrs, "[2001:db8::2]:8081")
	assert.Contains(t, addrs, "[2001:db8::3]:8081")
	assert.Len(t, addrs, 3)
}

func TestBuildBootstrapServers_DuplicatePeersWarning(t *testing.T) {
	hook := &warnLogCaptureHook{}
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

	customLookup := func(host string) ([]net.IP, error) {
		switch host {
		case "peer1.example.com":
			return []net.IP{net.ParseIP("192.168.1.10")}, nil
		case "peer2.example.com":
			return []net.IP{net.ParseIP("192.168.1.20")}, nil
		default:
			return nil, errors.New("nxdomain")
		}
	}
	customRes := newDNSResolver(1*time.Minute, customLookup)

	cfg := config.Config{
		RaftBootstrapExpect: 3,
		RaftAdvertise:       "192.168.1.1:8081",
		RaftPeers: []string{
			"node1=peer1.example.com:8081",
			"node1=192.168.1.99:8081", // Duplicate ID node1 with different address
			"node2=peer2.example.com:8081",
			"node2=192.168.1.98:8081", // Duplicate ID node2 with different address
		},
	}

	servers, err := buildBootstrapServers(cfg, "local-node", "192.168.1.1:8081", nil, customRes)
	require.NoError(t, err)

	// Verify deduplicated server list: local-node + node1 + node2 = 3 servers
	assert.Len(t, servers, 3)

	serverIDs := make(map[hashiraft.ServerID]bool)
	serverAddrs := make(map[hashiraft.ServerAddress]bool)
	for _, s := range servers {
		assert.False(t, serverIDs[s.ID], "duplicate server ID in bootstrap servers: %s", s.ID)
		assert.False(t, serverAddrs[s.Address], "duplicate server address in bootstrap servers: %s", s.Address)
		serverIDs[s.ID] = true
		serverAddrs[s.Address] = true
	}

	// Verify warning logs were emitted for duplicates
	hook.mu.Lock()
	defer hook.mu.Unlock()

	var duplicateWarnings []*logrus.Entry
	for _, entry := range hook.entries {
		if entry.Message == "skipping duplicate peer during raft bootstrap server resolution" {
			duplicateWarnings = append(duplicateWarnings, entry)
		}
	}

	require.Len(t, duplicateWarnings, 2, "expected 2 duplicate peer warnings")

	var warnedIDs []hashiraft.ServerID
	for _, w := range duplicateWarnings {
		if id, ok := w.Data["server_id"].(hashiraft.ServerID); ok {
			warnedIDs = append(warnedIDs, id)
		}
	}
	assert.Contains(t, warnedIDs, hashiraft.ServerID("node1"))
	assert.Contains(t, warnedIDs, hashiraft.ServerID("node2"))
}

func TestDNSResolver_SingleflightDeduplication(t *testing.T) {
	t.Parallel()

	var lookupCalls atomic.Int64
	started := make(chan struct{})
	unblock := make(chan struct{})

	lookupIP := func(host string) ([]net.IP, error) {
		if host == "singleflight.example.com" {
			if lookupCalls.Add(1) == 1 {
				close(started)
			}
			<-unblock
			return []net.IP{net.ParseIP("192.168.1.50")}, nil
		}
		return nil, errors.New("nxdomain")
	}

	resolver := newDNSResolver(1*time.Minute, lookupIP)

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			ips, err := resolver.lookup("singleflight.example.com")
			assert.NoError(t, err)
			assert.Equal(t, []net.IP{net.ParseIP("192.168.1.50")}, ips)
		}()
	}

	// Wait until lookupIP is entered by the first call
	<-started
	// Give remaining goroutines time to run and join singleflight
	time.Sleep(50 * time.Millisecond)

	// Unblock lookupIP and wait for all goroutines to complete
	close(unblock)
	wg.Wait()

	assert.Equal(t, int64(1), lookupCalls.Load(), "lookupIP should be called exactly once for concurrent requests")
}

func TestApplyPeerHTTPAddrs_UnmatchedEntriesNotAppended(t *testing.T) {
	t.Parallel()

	peers := []parsedPeerConfig{
		{id: "node1", raftAddr: "192.168.1.10:8081", resolvedIPs: []string{"192.168.1.10:8081"}},
	}
	httpAddrs := []string{
		"node1=http://192.168.1.10:8080",
		"unmatched-node=http://192.168.1.99:8080",
		"phantom-host=http://phantom:8080",
	}

	result := applyPeerHTTPAddrs(peers, httpAddrs)
	assert.Len(t, result, 1, "unmatched entries must not be appended to peers")
	assert.Equal(t, "http://192.168.1.10:8080", result[0].httpAddr)
}

func TestApplyPeerHTTPAddrs_MultiIPHeadlessDNS(t *testing.T) {
	t.Parallel()

	peers := []parsedPeerConfig{
		{
			id:          "headless",
			raftAddr:    "headless.svc:9300",
			resolvedIPs: []string{"10.0.0.1:9300", "10.0.0.2:9300"},
		},
	}
	httpAddrs := []string{
		"10.0.0.1:9300=http://10.0.0.1:8080",
		"10.0.0.2:9300=http://10.0.0.2:8080",
	}

	result := applyPeerHTTPAddrs(peers, httpAddrs)
	require.Len(t, result, 1)
	assert.Equal(t, "http://10.0.0.1:8080", result[0].httpAddr, "fallback httpAddr should remain the first matched address")
	require.NotNil(t, result[0].httpAddrsByIP)
	assert.Equal(t, "http://10.0.0.1:8080", result[0].httpAddrsByIP["10.0.0.1:9300"])
	assert.Equal(t, "http://10.0.0.2:8080", result[0].httpAddrsByIP["10.0.0.2:9300"])
}


func TestBuildBootstrapServers_UnmatchedRaftPeerHTTPAddrs_Ignored(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		RaftBootstrapExpect: 2,
		RaftAdvertise:       "192.168.1.1:8081",
		RaftPeers:           []string{"node1=192.168.1.10:8081"},
		RaftPeerHTTPAddrs: []string{
			"unmatched-node=http://192.168.1.99:8080",
			"phantom-host=http://phantom:8080",
		},
	}

	peers := parsePeers(cfg.RaftPeers, "8081", false, nil)
	peers = applyPeerHTTPAddrs(peers, cfg.RaftPeerHTTPAddrs)

	servers, err := buildBootstrapServers(cfg, "local-node", "192.168.1.1:8081", peers, nil)
	require.NoError(t, err)

	assert.Len(t, servers, 2, "bootstrap servers should only contain local node and matching peer")
	for _, s := range servers {
		assert.NotEqual(t, hashiraft.ServerID("unmatched-node"), s.ID)
		assert.NotEqual(t, hashiraft.ServerID("phantom-host"), s.ID)
	}
}

func TestMatchPeerAddr_PortHandling(t *testing.T) {
	t.Parallel()

	// When both specify ports:
	assert.False(t, matchPeerAddr("127.0.0.1:9301", "127.0.0.1:9302"))
	assert.True(t, matchPeerAddr("127.0.0.1:9301", "127.0.0.1:9301"))

	// When one address lacks a port, compares host to host:
	assert.True(t, matchPeerAddr("127.0.0.1:9301", "127.0.0.1"))
	assert.True(t, matchPeerAddr("127.0.0.1", "127.0.0.1:9301"))
	assert.False(t, matchPeerAddr("127.0.0.1:9301", "127.0.0.2"))
}

func TestMatchPeerAddr_IPv6Brackets(t *testing.T) {
	t.Parallel()

	assert.True(t, matchPeerAddr("[::1]:9300", "[::1]"))
	assert.True(t, matchPeerAddr("[::1]", "[::1]:9300"))
	assert.True(t, matchPeerAddr("[::1]:9300", "::1"))
	assert.True(t, matchPeerAddr("::1", "[::1]:9300"))
	assert.True(t, matchPeerAddr("[::1]", "::1"))
	assert.True(t, matchPeerAddr("::1", "[::1]"))
	assert.False(t, matchPeerAddr("[::1]:9300", "[::2]"))
	assert.True(t, matchPeerAddr("[::1]:9300", "[0:0:0:0:0:0:0:1]"))
}

func TestSplitHost_UnbracketedIPv6WithoutPort(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "2001:db8::1000:2", splitHost("2001:db8::1000:2"))
	assert.Equal(t, "fe80::20c:29ff:fe49:17a7", splitHost("fe80::20c:29ff:fe49:17a7"))

	h, p, err := splitHostAndPort("2001:db8::1000:2")
	assert.Error(t, err)
	assert.Empty(t, h)
	assert.Empty(t, p)

	h, p, err = splitHostAndPort("fe80::20c:29ff:fe49:17a7")
	assert.Error(t, err)
	assert.Empty(t, h)
	assert.Empty(t, p)
}

func TestMatchPeerAddr_UnbracketedIPv6WithoutPort(t *testing.T) {
	t.Parallel()

	assert.True(t, matchPeerAddr("2001:db8::1000:2", "[2001:db8::1000:2]:9300"))
	assert.True(t, matchPeerAddr("[2001:db8::1000:2]:9300", "2001:db8::1000:2"))
	assert.True(t, matchPeerAddr("2001:db8::1000:2", "2001:db8::1000:2"))
	assert.False(t, matchPeerAddr("2001:db8::1000:2", "2001:db8::1000:3"))
}

func TestApplyPeerHTTPAddrs_HeadlessDNS_PeerIDMapsResolvedIPs(t *testing.T) {
	t.Parallel()

	peers := []parsedPeerConfig{
		{
			id:          "headless",
			raftAddr:    "headless.default.svc.cluster.local:9300",
			resolvedIPs: []string{"10.0.0.1:9300", "10.0.0.2:9300", "10.0.0.3:9300"},
		},
	}
	httpAddrs := []string{
		"headless=http://10.0.0.1:8080",
	}

	result := applyPeerHTTPAddrs(peers, httpAddrs)
	require.Len(t, result, 1)
	assert.Equal(t, "http://10.0.0.1:8080", result[0].httpAddr)
	require.NotNil(t, result[0].httpAddrsByIP)
	assert.Equal(t, "http://10.0.0.1:8080", result[0].httpAddrsByIP["headless"])
	assert.Equal(t, "http://10.0.0.1:8080", result[0].httpAddrsByIP["10.0.0.1:9300"])
	assert.Equal(t, "http://10.0.0.1:8080", result[0].httpAddrsByIP["10.0.0.2:9300"])
	assert.Equal(t, "http://10.0.0.1:8080", result[0].httpAddrsByIP["10.0.0.3:9300"])
}

func TestApplyPeerHTTPAddrs_OverridesInlineHTTPAddr(t *testing.T) {
	t.Parallel()

	peers := []parsedPeerConfig{
		{
			id:       "node-1",
			raftAddr: "10.0.0.1:9300",
			httpAddr: "http://10.0.0.1:8080",
		},
	}
	httpAddrs := []string{
		"node-1=http://override-host:8080",
	}

	result := applyPeerHTTPAddrs(peers, httpAddrs)
	require.Len(t, result, 1)
	assert.Equal(t, "http://override-host:8080", result[0].httpAddr, "explicit flag mapping should override inline HTTP address")
}

func TestApplyPeerHTTPAddrs_SpecificIPNotClobberedByGenericPeerID(t *testing.T) {
	t.Parallel()

	peers := []parsedPeerConfig{
		{
			id:          "headless",
			raftAddr:    "headless.svc:9300",
			resolvedIPs: []string{"10.0.0.1:9300", "10.0.0.2:9300"},
		},
	}
	httpAddrs := []string{
		"10.0.0.1:9300=http://10.0.0.1:8080",
		"headless=http://fallback:8080",
	}

	result := applyPeerHTTPAddrs(peers, httpAddrs)
	require.Len(t, result, 1)
	require.NotNil(t, result[0].httpAddrsByIP)
	assert.Equal(t, "http://10.0.0.1:8080", result[0].httpAddrsByIP["10.0.0.1:9300"], "specific IP mapping must not be clobbered by generic peer ID mapping")
	assert.Equal(t, "http://fallback:8080", result[0].httpAddrsByIP["10.0.0.2:9300"], "unmapped resolved IP should receive generic peer ID mapping")
	assert.Equal(t, "http://fallback:8080", result[0].httpAddrsByIP["headless"], "peer ID should receive generic peer ID mapping")
}

func TestIsDNSHostname_And_HasDNSPeer_WithIDPrefix(t *testing.T) {
	t.Parallel()

	assert.False(t, isDNSHostname("node-1=192.168.1.10:9300"))
	assert.False(t, isDNSHostname("node-2=10.0.0.2:9300@http://10.0.0.2:8080"))
	assert.False(t, isDNSHostname("node-3=[2001:db8::1]:9300"))
	assert.True(t, isDNSHostname("node-4=raft.internal.local:9300"))

	assert.False(t, hasDNSPeer([]string{"node-1=192.168.1.10:9300", "node-2=10.0.0.2:9300"}))
	assert.True(t, hasDNSPeer([]string{"node-1=192.168.1.10:9300", "node-4=raft.internal.local:9300"}))
}
