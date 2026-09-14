package raft

import (
	"fmt"
	"net"
	"strings"
	"time"

	hashiraft "github.com/hashicorp/raft"
	"github.com/sirupsen/logrus"
)

func (n *RaftNode) initStaticPeers(parsedPeers []parsedPeerConfig, peerHTTPAddrs []string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.staticHTTPAddrs == nil {
		n.staticHTTPAddrs = make(map[string]string)
	}
	if n.serverIDByAddr == nil {
		n.serverIDByAddr = make(map[string]string)
	}
	if n.addrByServerID == nil {
		n.addrByServerID = make(map[string]string)
	}

	// Register peer HTTP addresses and server ID mappings from parsedPeers (e.g. node-1=127.0.0.1:8081@http://127.0.0.1:8080)
	for _, p := range parsedPeers {
		if p.raftAddr == "" {
			continue
		}
		if p.httpAddr != "" {
			n.registerHTTPAddrLocked(p.raftAddr, p.httpAddr)
			n.staticHTTPAddrs[p.raftAddr] = p.httpAddr
			if p.id != "" {
				n.registerHTTPAddrLocked(p.id, p.httpAddr)
				n.staticHTTPAddrs[p.id] = p.httpAddr
			}
		}
		if p.id != "" {
			n.serverIDByAddr[p.raftAddr] = p.id
			n.addrByServerID[p.id] = p.raftAddr
		}
		for _, rip := range p.resolvedIPs {
			if p.httpAddr != "" {
				n.registerHTTPAddrLocked(rip, p.httpAddr)
				n.staticHTTPAddrs[rip] = p.httpAddr
			}
			if p.id != "" {
				n.serverIDByAddr[rip] = p.id
			}
		}
	}

	// Register peer HTTP addresses from cfg.RaftPeerHTTPAddrs (e.g. node-1=http://127.0.0.1:8080)
	for _, entry := range peerHTTPAddrs {
		entry = strings.TrimSpace(entry)
		if idx := strings.Index(entry, "="); idx != -1 {
			k := strings.TrimSpace(entry[:idx])
			v := strings.TrimSpace(entry[idx+1:])
			if k != "" && v != "" {
				n.registerHTTPAddrLocked(k, v)
				n.staticHTTPAddrs[k] = v
			}
		}
	}
}

// RegisterHTTPAddr associates a Raft address or node ID with a specific HTTP address.
func (n *RaftNode) RegisterHTTPAddr(raftAddrOrID, httpAddr string) {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.registerHTTPAddrLocked(raftAddrOrID, httpAddr)
}

func (n *RaftNode) registerHTTPAddrLocked(raftAddrOrID, httpAddr string) {
	if n.httpAddrs == nil {
		n.httpAddrs = make(map[string]string)
	}
	n.httpAddrs[raftAddrOrID] = httpAddr
}

// ResetHTTPAddrs resets the registered HTTP addresses with the provided map.
// If addrs is nil or empty, dynamic entries are cleared while preserving
// statically configured peer HTTP addresses. Reciprocal entries from
// addrByServerID and serverIDByAddr are re-aligned when available.
func (n *RaftNode) ResetHTTPAddrs(addrs map[string]string) {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.httpAddrs = make(map[string]string, len(n.staticHTTPAddrs)+len(addrs))
	for k, v := range n.staticHTTPAddrs {
		n.httpAddrs[k] = v
	}
	for k, v := range addrs {
		n.httpAddrs[k] = v
	}
	type entry struct {
		k, v string
	}
	entries := make([]entry, 0, len(n.httpAddrs))
	for k, v := range n.httpAddrs {
		entries = append(entries, entry{k: k, v: v})
	}
	for _, e := range entries {
		if addr, ok := n.addrByServerID[e.k]; ok && addr != "" {
			if _, exists := n.httpAddrs[addr]; !exists {
				n.httpAddrs[addr] = e.v
			}
		}
		if sID, ok := n.serverIDByAddr[e.k]; ok && sID != "" {
			if _, exists := n.httpAddrs[sID]; !exists {
				n.httpAddrs[sID] = e.v
			}
		}
	}
}

// HTTPAddrs returns a copy of the registered HTTP addresses.
func (n *RaftNode) HTTPAddrs() map[string]string {
	if n == nil {
		return nil
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.httpAddrs == nil {
		return nil
	}
	cp := make(map[string]string, len(n.httpAddrs))
	for k, v := range n.httpAddrs {
		cp[k] = v
	}
	return cp
}

// AddrByServerID returns the Raft address associated with the given server ID, or empty string if not found.
func (n *RaftNode) AddrByServerID(id string) string {
	if n == nil {
		return ""
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.addrByServerID[id]
}

// ServerIDByAddr returns the server ID associated with the given Raft address or IP alias, or empty string if not found.
func (n *RaftNode) ServerIDByAddr(addr string) string {
	if n == nil {
		return ""
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.serverIDByAddr[addr]
}

// DeregisterHTTPAddr removes the registered HTTP address for a given Raft address or node ID.
func (n *RaftNode) DeregisterHTTPAddr(raftAddrOrID string) {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.deregisterHTTPAddrLocked(raftAddrOrID)
}

func (n *RaftNode) deregisterHTTPAddrLocked(raftAddrOrID string) {
	keys := map[string]struct{}{raftAddrOrID: {}}
	if addr, ok := n.addrByServerID[raftAddrOrID]; ok && addr != "" {
		keys[addr] = struct{}{}
	}
	if sID, ok := n.serverIDByAddr[raftAddrOrID]; ok && sID != "" {
		keys[sID] = struct{}{}
	}
	for a, sid := range n.serverIDByAddr {
		if _, ok := keys[sid]; ok || sid == raftAddrOrID {
			keys[a] = struct{}{}
		}
	}
	for sid, a := range n.addrByServerID {
		if _, ok := keys[a]; ok || a == raftAddrOrID {
			keys[sid] = struct{}{}
		}
	}

	for k := range keys {
		delete(n.staticHTTPAddrs, k)
		delete(n.httpAddrs, k)
		delete(n.addrByServerID, k)
		delete(n.serverIDByAddr, k)
	}
}

// HTTPAddrFor returns the registered HTTP address for a given Raft address or node ID.
func (n *RaftNode) HTTPAddrFor(key string) string {
	if n == nil {
		return ""
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.httpAddrs[key]
}

func (n *RaftNode) lookupHTTPAddrLocked(leaderAddr string) (string, bool) {
	if addr, ok := n.httpAddrs[leaderAddr]; ok && addr != "" {
		return addr, false
	}
	if srvID, ok := n.serverIDByAddr[leaderAddr]; ok && srvID != "" {
		if addr, ok := n.httpAddrs[srvID]; ok && addr != "" {
			return addr, true
		}
		return "", true
	}
	return "", false
}

// LeaderHTTPAddr returns the HTTP address of the current cluster leader, or empty string if unknown.
// If an explicit mapping was registered via RegisterHTTPAddr, it is returned.
// Otherwise, if an HTTP port is configured, the host portion of the leader's Raft address
// is combined with the HTTP port.
func (n *RaftNode) LeaderHTTPAddr() string {
	if n == nil || n.raft == nil {
		return ""
	}
	leaderAddr := string(n.raft.Leader())
	if leaderAddr == "" {
		return ""
	}

	n.mu.RLock()
	addr, knownServerID := n.lookupHTTPAddrLocked(leaderAddr)
	if addr != "" {
		n.mu.RUnlock()
		return addr
	}

	now := time.Now()
	shouldRefresh := now.Sub(n.lastConfigRefresh) >= 5*time.Second
	if n.httpPort != "" && n.httpPort != "0" && knownServerID {
		shouldRefresh = false
	}
	n.mu.RUnlock()

	if shouldRefresh {
		_, _, _ = n.configRefreshGroup.Do("refresh", func() (interface{}, error) {
			n.mu.RLock()
			if time.Since(n.lastConfigRefresh) < 5*time.Second {
				n.mu.RUnlock()
				return nil, nil
			}
			n.mu.RUnlock()

			var configFuture hashiraft.ConfigurationFuture
			if n.getConfigOverride != nil {
				configFuture = n.getConfigOverride()
			} else {
				configFuture = n.raft.GetConfiguration()
			}
			if err := configFuture.Error(); err != nil {
				n.mu.Lock()
				n.lastConfigRefresh = time.Now()
				n.mu.Unlock()
				return nil, err
			}

			newServerIDByAddr := make(map[string]string)
			newAddrByServerID := make(map[string]string)
			activeServerIDs := make(map[string]bool)
			for _, srv := range configFuture.Configuration().Servers {
				sID := string(srv.ID)
				sAddr := string(srv.Address)
				activeServerIDs[sID] = true
				newServerIDByAddr[sAddr] = sID
				newAddrByServerID[sID] = sAddr
				for _, rip := range n.resolveHostPort(sAddr) {
					newServerIDByAddr[rip] = sID
				}
			}

			n.mu.Lock()
			for oldAddr, oldSID := range n.serverIDByAddr {
				if activeServerIDs[oldSID] {
					if _, exists := newServerIDByAddr[oldAddr]; !exists {
						newServerIDByAddr[oldAddr] = oldSID
					}
				}
			}
			n.serverIDByAddr = newServerIDByAddr
			n.addrByServerID = newAddrByServerID
			n.lastConfigRefresh = time.Now()
			n.mu.Unlock()
			return nil, nil
		})
	}

	n.mu.RLock()
	defer n.mu.RUnlock()

	return n.leaderHTTPAddrLocked(leaderAddr)
}

func (n *RaftNode) leaderHTTPAddrLocked(leaderAddr string) string {
	if addr, _ := n.lookupHTTPAddrLocked(leaderAddr); addr != "" {
		return addr
	}

	// 3. Map Raft host to HTTP port
	if n.httpPort != "" && n.httpPort != "0" {
		host, _, err := net.SplitHostPort(leaderAddr)
		if err != nil {
			host = leaderAddr
		}

		if n.transport != nil && string(n.transport.LocalAddr()) != leaderAddr {
			localHost, _, err := net.SplitHostPort(string(n.transport.LocalAddr()))
			if err != nil {
				localHost = string(n.transport.LocalAddr())
			}
			if isSameOrLoopbackHost(host, localHost) {
				logrus.WithField("leader_raft_addr", leaderAddr).
					WithField("local_raft_addr", string(n.transport.LocalAddr())).
					Warn("cannot synthesize HTTP address for co-located leader on shared IP address or loopback interface; configure --raft-peer-http-addrs")
				return ""
			}
		}

		scheme := "http"
		if n.tlsEnabled {
			scheme = "https"
		}
		return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, n.httpPort))
	}

	return ""
}

func isSameOrLoopbackHost(h1, h2 string) bool {
	h1 = strings.TrimSpace(strings.Trim(strings.TrimSpace(h1), "[]"))
	h2 = strings.TrimSpace(strings.Trim(strings.TrimSpace(h2), "[]"))
	if h1 == "" || h2 == "" {
		return false
	}
	if strings.EqualFold(h1, h2) {
		return true
	}
	ip1 := net.ParseIP(h1)
	ip2 := net.ParseIP(h2)
	if ip1 != nil && ip2 != nil {
		if ip1.Equal(ip2) {
			return true
		}
		if ip1.IsLoopback() && ip2.IsLoopback() {
			return true
		}
	}
	isH1Loopback := (ip1 != nil && ip1.IsLoopback()) || strings.EqualFold(h1, "localhost")
	isH2Loopback := (ip2 != nil && ip2.IsLoopback()) || strings.EqualFold(h2, "localhost")
	return isH1Loopback && isH2Loopback
}
