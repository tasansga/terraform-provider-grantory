package raft

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeregisterHTTPAddr_PurgesStaticHTTPAddrs(t *testing.T) {
	node := &RaftNode{
		staticHTTPAddrs: map[string]string{
			"node-peer":       "http://127.0.0.1:8092",
			"127.0.0.1:18092": "http://127.0.0.1:8092",
			"node-extra":      "http://127.0.0.1:8093",
		},
		httpAddrs: map[string]string{
			"node-peer":       "http://127.0.0.1:8092",
			"127.0.0.1:18092": "http://127.0.0.1:8092",
			"node-extra":      "http://127.0.0.1:8093",
		},
		addrByServerID: map[string]string{
			"node-peer": "127.0.0.1:18092",
		},
		serverIDByAddr: map[string]string{
			"127.0.0.1:18092": "node-peer",
		},
	}

	// Verify before deregistration
	assert.Equal(t, "http://127.0.0.1:8092", node.HTTPAddrFor("node-peer"))
	assert.Equal(t, "http://127.0.0.1:8092", node.HTTPAddrFor("127.0.0.1:18092"))
	assert.Equal(t, "http://127.0.0.1:8093", node.HTTPAddrFor("node-extra"))

	// Deregister node-peer by server ID
	node.DeregisterHTTPAddr("node-peer")

	// Both node-peer and its address should be removed from HTTPAddrs immediately
	assert.Empty(t, node.HTTPAddrFor("node-peer"))
	assert.Empty(t, node.HTTPAddrFor("127.0.0.1:18092"))
	assert.Equal(t, "http://127.0.0.1:8093", node.HTTPAddrFor("node-extra"))

	// Calling ResetHTTPAddrs(nil) must NOT repopulate node-peer from staticHTTPAddrs
	node.ResetHTTPAddrs(nil)
	assert.Empty(t, node.HTTPAddrFor("node-peer"), "node-peer must not be resurrected after ResetHTTPAddrs(nil)")
	assert.Empty(t, node.HTTPAddrFor("127.0.0.1:18092"), "127.0.0.1:18092 must not be resurrected after ResetHTTPAddrs(nil)")
	assert.Equal(t, "http://127.0.0.1:8093", node.HTTPAddrFor("node-extra"), "other static addrs should remain")

	// Now deregister node-extra directly
	node.DeregisterHTTPAddr("node-extra")
	assert.Empty(t, node.HTTPAddrFor("node-extra"))
	node.ResetHTTPAddrs(nil)
	assert.Empty(t, node.HTTPAddrFor("node-extra"), "node-extra must not be resurrected")
	assert.Empty(t, node.HTTPAddrs())
}

func TestIsSameOrLoopbackHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		h1       string
		h2       string
		expected bool
	}{
		{"exact match ipv4", "127.0.0.1", "127.0.0.1", true},
		{"loopback ips", "127.0.0.1", "127.0.0.2", true},
		{"localhost and 127.0.0.1", "localhost", "127.0.0.1", true},
		{"ipv6 loopback and 127.0.0.1", "::1", "127.0.0.1", true},
		{"bracketed ipv6 loopback", "[::1]", "127.0.0.1", true},
		{"bracketed ipv6 loopbacks", "[::1]", "[::1]", true},
		{"bracketed ipv4 and ipv6 loopback", "[127.0.0.1]", "::1", true},
		{"whitespace and brackets loopback", "  [::1]  ", "localhost", true},
		{"whitespace inside brackets", "[ ::1 ]", "127.0.0.1", true},
		{"uppercase localhost", "LOCALHOST", "[::1]", true},
		{"expanded ipv6 loopback", "0000:0000:0000:0000:0000:0000:0000:0001", "127.0.0.1", true},
		{"same non-loopback host", "10.0.0.1", "10.0.0.1", true},
		{"same non-loopback host with whitespace", " 10.0.0.1 ", "10.0.0.1", true},
		{"different non-loopback host", "10.0.0.1", "10.0.0.2", false},
		{"hostname and loopback", "example.com", "127.0.0.1", false},
		{"different hostnames", "node1.cluster.local", "node2.cluster.local", false},
		{"same hostname case insensitive", "Node1.Cluster.Local", "node1.cluster.local", true},
		{"ipv6 non-loopback same brackets and case", "[2001:DB8::1]", "2001:db8::1", true},
		{"ipv6 non-loopback different", "2001:db8::1", "2001:db8::2", false},
		{"empty strings", "", "", false},
		{"empty and loopback", "", "127.0.0.1", false},
		{"whitespace and loopback", "   ", "localhost", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := isSameOrLoopbackHost(tt.h1, tt.h2)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestLeaderHTTPAddr_SynthesizedScheme(t *testing.T) {
	t.Parallel()

	t.Run("HTTP fallback returns http scheme", func(t *testing.T) {
		node := &RaftNode{
			httpPort: "8080",
		}
		addr := node.leaderHTTPAddrLocked("192.168.1.10:8081")
		assert.Equal(t, "http://192.168.1.10:8080", addr)
	})

	t.Run("HTTPS fallback returns https scheme", func(t *testing.T) {
		node := &RaftNode{
			httpPort:   "8443",
			tlsEnabled: true,
		}
		addr := node.leaderHTTPAddrLocked("192.168.1.10:8081")
		assert.Equal(t, "https://192.168.1.10:8443", addr)
	})

	t.Run("IPv6 HTTP fallback returns formatted URI", func(t *testing.T) {
		node := &RaftNode{
			httpPort: "8080",
		}
		addr := node.leaderHTTPAddrLocked("[2001:db8::1]:8081")
		assert.Equal(t, "http://[2001:db8::1]:8080", addr)
	})

	t.Run("Mapped address takes precedence and returns URI as-is", func(t *testing.T) {
		node := &RaftNode{
			httpPort: "8080",
			httpAddrs: map[string]string{
				"192.168.1.10:8081": "https://custom.domain:9000",
			},
		}
		addr := node.leaderHTTPAddrLocked("192.168.1.10:8081")
		assert.Equal(t, "https://custom.domain:9000", addr)
	})

	t.Run("Nil node or uninitialized raft returns empty", func(t *testing.T) {
		var nilNode *RaftNode
		assert.Equal(t, "", nilNode.LeaderHTTPAddr())

		emptyNode := &RaftNode{}
		assert.Equal(t, "", emptyNode.LeaderHTTPAddr())
	})
}

func TestDeregisterHTTPAddr_PurgesByAddressAndServerID(t *testing.T) {
	t.Parallel()

	t.Run("purges by address including all alias mappings", func(t *testing.T) {
		node := &RaftNode{
			staticHTTPAddrs: map[string]string{
				"node-1":          "http://10.0.0.1:8080",
				"10.0.0.1:18080": "http://10.0.0.1:8080",
				"10.0.0.2:18080": "http://10.0.0.1:8080",
				"node-other":      "http://10.0.0.9:8080",
			},
			httpAddrs: map[string]string{
				"node-1":          "http://10.0.0.1:8080",
				"10.0.0.1:18080": "http://10.0.0.1:8080",
				"10.0.0.2:18080": "http://10.0.0.1:8080",
				"node-other":      "http://10.0.0.9:8080",
			},
			addrByServerID: map[string]string{
				"node-1":     "10.0.0.1:18080",
				"node-other": "10.0.0.9:18080",
			},
			serverIDByAddr: map[string]string{
				"10.0.0.1:18080": "node-1",
				"10.0.0.2:18080": "node-1",
				"10.0.0.9:18080": "node-other",
			},
		}

		// Deregister by address
		node.DeregisterHTTPAddr("10.0.0.1:18080")

		assert.Empty(t, node.HTTPAddrFor("10.0.0.1:18080"))
		assert.Empty(t, node.HTTPAddrFor("10.0.0.2:18080"))
		assert.Empty(t, node.HTTPAddrFor("node-1"))
		assert.Empty(t, node.AddrByServerID("node-1"))
		assert.Empty(t, node.ServerIDByAddr("10.0.0.1:18080"))
		assert.Empty(t, node.ServerIDByAddr("10.0.0.2:18080"))

		// Check untouched node remains intact
		assert.Equal(t, "http://10.0.0.9:8080", node.HTTPAddrFor("node-other"))
		assert.Equal(t, "10.0.0.9:18080", node.AddrByServerID("node-other"))
		assert.Equal(t, "node-other", node.ServerIDByAddr("10.0.0.9:18080"))

		// Ensure ResetHTTPAddrs does not resurrect purged entries
		node.ResetHTTPAddrs(nil)
		assert.Empty(t, node.HTTPAddrFor("node-1"))
		assert.Empty(t, node.HTTPAddrFor("10.0.0.1:18080"))
		assert.Empty(t, node.HTTPAddrFor("10.0.0.2:18080"))
		assert.Equal(t, "http://10.0.0.9:8080", node.HTTPAddrFor("node-other"))
	})

	t.Run("purges by server ID including all alias mappings", func(t *testing.T) {
		node := &RaftNode{
			staticHTTPAddrs: map[string]string{
				"node-1":          "http://10.0.0.1:8080",
				"10.0.0.1:18080": "http://10.0.0.1:8080",
				"10.0.0.2:18080": "http://10.0.0.1:8080",
			},
			httpAddrs: map[string]string{
				"node-1":          "http://10.0.0.1:8080",
				"10.0.0.1:18080": "http://10.0.0.1:8080",
				"10.0.0.2:18080": "http://10.0.0.1:8080",
			},
			addrByServerID: map[string]string{
				"node-1": "10.0.0.1:18080",
			},
			serverIDByAddr: map[string]string{
				"10.0.0.1:18080": "node-1",
				"10.0.0.2:18080": "node-1",
			},
		}

		node.DeregisterHTTPAddr("node-1")

		assert.Empty(t, node.HTTPAddrFor("node-1"))
		assert.Empty(t, node.HTTPAddrFor("10.0.0.1:18080"))
		assert.Empty(t, node.HTTPAddrFor("10.0.0.2:18080"))
		assert.Empty(t, node.AddrByServerID("node-1"))
		assert.Empty(t, node.ServerIDByAddr("10.0.0.1:18080"))
		assert.Empty(t, node.ServerIDByAddr("10.0.0.2:18080"))
		assert.Empty(t, node.staticHTTPAddrs)
		assert.Empty(t, node.httpAddrs)
	})
}

func TestLookupHTTPAddrLocked(t *testing.T) {
	t.Parallel()

	node := &RaftNode{
		httpAddrs: map[string]string{
			"10.0.0.1:18080": "http://10.0.0.1:8080",
			"node-2":         "http://10.0.0.2:8080",
		},
		serverIDByAddr: map[string]string{
			"10.0.0.2:18080": "node-2",
			"10.0.0.3:18080": "node-3", // node-3 has no httpAddrs entry
		},
	}

	// 1. Direct match on Raft address: returns addr, false
	addr, knownServerID := node.lookupHTTPAddrLocked("10.0.0.1:18080")
	assert.Equal(t, "http://10.0.0.1:8080", addr)
	assert.False(t, knownServerID)

	// 2. Match on Server ID via serverIDByAddr with httpAddrs set: returns addr, true
	addr, knownServerID = node.lookupHTTPAddrLocked("10.0.0.2:18080")
	assert.Equal(t, "http://10.0.0.2:8080", addr)
	assert.True(t, knownServerID)

	// 3. Match on Server ID via serverIDByAddr without httpAddrs set: returns "", true
	addr, knownServerID = node.lookupHTTPAddrLocked("10.0.0.3:18080")
	assert.Empty(t, addr)
	assert.True(t, knownServerID)

	// 4. Unknown leader address: returns "", false
	addr, knownServerID = node.lookupHTTPAddrLocked("10.0.0.4:18080")
	assert.Empty(t, addr)
	assert.False(t, knownServerID)
}

func TestInitStaticPeers_MultiIPHeadlessDNS(t *testing.T) {
	t.Parallel()

	node := &RaftNode{}
	peers := []parsedPeerConfig{
		{
			id:          "peer-headless",
			raftAddr:    "headless.service.local:9300",
			httpAddr:    "http://fallback.service.local:8080",
			resolvedIPs: []string{"10.0.0.1:9300", "10.0.0.2:9300"},
			httpAddrsByIP: map[string]string{
				"10.0.0.1:9300": "http://10.0.0.1:8080",
				"10.0.0.2:9300": "http://10.0.0.2:8080",
			},
		},
	}
	node.initStaticPeers(peers, nil)

	assert.Equal(t, "http://10.0.0.1:8080", node.HTTPAddrFor("10.0.0.1:9300"))
	assert.Equal(t, "http://10.0.0.2:8080", node.HTTPAddrFor("10.0.0.2:9300"))
}
