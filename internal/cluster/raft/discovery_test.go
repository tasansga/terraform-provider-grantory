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
