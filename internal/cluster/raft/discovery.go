package raft

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	hashiraft "github.com/hashicorp/raft"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
)

const defaultDNSCacheMaxEntries = 512

func defaultRaftPort(cfg config.Config) string {
	for _, addr := range []string{cfg.RaftAdvertise, cfg.RaftBind} {
		if addr == "" {
			continue
		}
		_, port, err := net.SplitHostPort(addr)
		if err == nil && port != "" && port != "0" {
			return port
		}
	}
	return ""
}

func isIPv6Listener(cfg config.Config) bool {
	for _, addr := range []string{cfg.RaftAdvertise, cfg.RaftBind} {
		if addr == "" {
			continue
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(host)
		if ip != nil && ip.To4() == nil {
			return true
		}
	}
	return false
}

func filterIPs(ips []net.IP, preferIPv6 bool) []net.IP {
	var v4, v6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	if preferIPv6 {
		if len(v6) > 0 {
			return v6
		}
		return v4
	}
	if len(v4) > 0 {
		return v4
	}
	return v6
}

type dnsCacheEntry struct {
	ips       []net.IP
	expiresAt time.Time
}

type dnsResolver struct {
	mu         sync.RWMutex
	cache      map[string]dnsCacheEntry
	group      singleflight.Group
	ttl        time.Duration
	maxEntries int
	lookupIP   func(host string) ([]net.IP, error)
}

func newDNSResolver(ttl time.Duration, lookupIP func(string) ([]net.IP, error)) *dnsResolver {
	return newDNSResolverWithCapacity(ttl, defaultDNSCacheMaxEntries, lookupIP)
}

func newDNSResolverWithCapacity(ttl time.Duration, maxEntries int, lookupIP func(string) ([]net.IP, error)) *dnsResolver {
	if lookupIP == nil {
		lookupIP = net.LookupIP
	}
	if maxEntries <= 0 {
		maxEntries = defaultDNSCacheMaxEntries
	}
	return &dnsResolver{
		cache:      make(map[string]dnsCacheEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
		lookupIP:   lookupIP,
	}
}

func copyIPs(ips []net.IP) []net.IP {
	res := make([]net.IP, len(ips))
	for i, ip := range ips {
		res[i] = append(net.IP(nil), ip...)
	}
	return res
}

func (r *dnsResolver) lookup(host string) ([]net.IP, error) {
	r.mu.RLock()
	if entry, ok := r.cache[host]; ok && time.Now().Before(entry.expiresAt) {
		r.mu.RUnlock()
		return copyIPs(entry.ips), nil
	}
	r.mu.RUnlock()

	val, err, _ := r.group.Do(host, func() (any, error) {
		r.mu.RLock()
		if entry, ok := r.cache[host]; ok && time.Now().Before(entry.expiresAt) {
			r.mu.RUnlock()
			return copyIPs(entry.ips), nil
		}
		r.mu.RUnlock()

		ips, err := r.lookupIP(host)
		if err != nil {
			return nil, err
		}

		r.mu.Lock()
		maxEntries := r.maxEntries
		if maxEntries <= 0 {
			maxEntries = defaultDNSCacheMaxEntries
		}
		if len(r.cache) >= maxEntries {
			now := time.Now()
			for k, entry := range r.cache {
				if now.After(entry.expiresAt) {
					delete(r.cache, k)
				}
			}
			if len(r.cache) >= maxEntries {
				clear(r.cache)
			}
		}
		r.cache[host] = dnsCacheEntry{
			ips:       copyIPs(ips),
			expiresAt: time.Now().Add(r.ttl),
		}
		r.mu.Unlock()

		return copyIPs(ips), nil
	})
	if err != nil {
		return nil, err
	}
	return copyIPs(val.([]net.IP)), nil
}

func (r *dnsResolver) flush() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.cache)
}

var defaultDNSResolver = newDNSResolver(30*time.Second, net.LookupIP)

func getResolver(r []*dnsResolver) *dnsResolver {
	if len(r) > 0 && r[0] != nil {
		return r[0]
	}
	return defaultDNSResolver
}

func resolveHostPort(target string, defPort string, preferV6 bool, resolver ...*dnsResolver) []string {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = ""
	}
	if port == "" {
		port = defPort
	}

	trimmedHost := strings.Trim(host, "[]")
	if ip := net.ParseIP(trimmedHost); ip != nil {
		if port != "" {
			return []string{net.JoinHostPort(ip.String(), port)}
		}
		return []string{ip.String()}
	}

	res := getResolver(resolver)

	var ips []net.IP
	var errLookup error
	if res != nil {
		ips, errLookup = res.lookup(trimmedHost)
	} else {
		ips, errLookup = net.LookupIP(trimmedHost)
	}
	if errLookup == nil && len(ips) > 0 {
		filtered := filterIPs(ips, preferV6)
		var out []string
		for _, ip := range filtered {
			if port != "" {
				out = append(out, net.JoinHostPort(ip.String(), port))
			} else {
				out = append(out, ip.String())
			}
		}
		return out
	}

	if port != "" {
		return []string{net.JoinHostPort(host, port)}
	}
	return []string{host}
}

type parsedPeerConfig struct {
	id          string
	raftAddr    string
	httpAddr    string
	resolvedIPs []string
}

func parsePeerConfig(raw string, defPort string, preferV6 bool, resolver ...*dnsResolver) parsedPeerConfig {
	raw = strings.TrimSpace(raw)
	var p parsedPeerConfig
	if raw == "" {
		return p
	}
	target := raw
	if idx := strings.Index(raw, "="); idx != -1 {
		p.id = strings.TrimSpace(raw[:idx])
		target = strings.TrimSpace(raw[idx+1:])
	}
	if atIdx := strings.Index(target, "@"); atIdx != -1 {
		p.raftAddr = strings.TrimSpace(target[:atIdx])
		p.httpAddr = strings.TrimSpace(target[atIdx+1:])
	} else {
		p.raftAddr = target
	}
	if p.raftAddr != "" {
		if _, _, err := net.SplitHostPort(p.raftAddr); err != nil && defPort != "" {
			p.raftAddr = net.JoinHostPort(strings.Trim(p.raftAddr, "[]"), defPort)
		}
		p.resolvedIPs = resolveHostPort(p.raftAddr, defPort, preferV6, getResolver(resolver))
	}
	return p
}

func parsePeers(peers []string, defPort string, preferV6 bool, resolver ...*dnsResolver) []parsedPeerConfig {
	res := getResolver(resolver)
	parsedPeers := make([]parsedPeerConfig, 0, len(peers))
	for _, raw := range peers {
		parsedPeers = append(parsedPeers, parsePeerConfig(raw, defPort, preferV6, res))
	}
	return parsedPeers
}

func resolveParsedPeers(peers []parsedPeerConfig) []string {
	var resolved []string
	seen := make(map[string]bool)

	for _, p := range peers {
		for _, addr := range p.resolvedIPs {
			if !seen[addr] {
				seen[addr] = true
				resolved = append(resolved, addr)
			}
		}
	}
	return resolved
}

func isDNSHostname(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	if idx := strings.Index(target, "="); idx != -1 {
		target = strings.TrimSpace(target[idx+1:])
	}
	if atIdx := strings.Index(target, "@"); atIdx != -1 {
		target = strings.TrimSpace(target[:atIdx])
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || strings.EqualFold(host, "localhost") {
		return false
	}
	return net.ParseIP(host) == nil
}

func hasDNSPeer(peers []string) bool {
	for _, p := range peers {
		if isDNSHostname(p) {
			return true
		}
	}
	return false
}

// isLocalAddress determines whether the candidate address resolves or matches
// any of the known local alias addresses for this node.
func isLocalAddress(addr string, localAliases map[string]bool, defPort string, preferV6 bool, resolver ...*dnsResolver) bool {
	res := getResolver(resolver)
	if localAliases[addr] {
		return true
	}
	for _, rip := range resolveHostPort(addr, defPort, preferV6, res) {
		if localAliases[rip] {
			return true
		}
	}
	return false
}

func buildBootstrapServers(cfg config.Config, localID string, localAddr string, parsedPeers []parsedPeerConfig, resolver ...*dnsResolver) ([]hashiraft.Server, error) {
	res := getResolver(resolver)
	advAddr := cfg.RaftAdvertise
	if advAddr == "" {
		advAddr = localAddr
	}
	if advAddr == "" {
		advAddr = cfg.RaftBind
	}

	defPort := defaultRaftPort(cfg)
	if _, _, err := net.SplitHostPort(advAddr); err != nil && defPort != "" {
		advAddr = net.JoinHostPort(strings.Trim(advAddr, "[]"), defPort)
	}
	preferV6 := isIPv6Listener(cfg)

	if len(parsedPeers) == 0 {
		parsedPeers = parsePeers(cfg.RaftPeers, defPort, preferV6, res)
	}

	idMap := make(map[string]string)
	for _, p := range parsedPeers {
		if p.id != "" && p.raftAddr != "" {
			idMap[p.raftAddr] = p.id
			for _, rip := range p.resolvedIPs {
				idMap[rip] = p.id
			}
		}
	}

	localAliases := make(map[string]bool)
	addLocal := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return
		}
		if _, _, err := net.SplitHostPort(addr); err != nil && defPort != "" {
			addr = net.JoinHostPort(strings.Trim(addr, "[]"), defPort)
		}
		localAliases[addr] = true
		for _, rip := range resolveHostPort(addr, defPort, preferV6, res) {
			localAliases[rip] = true
		}
	}
	addLocal(advAddr)
	addLocal(cfg.RaftBind)
	addLocal(localAddr)

	if cfg.RaftBootstrapExpect == 1 {
		serverID := hashiraft.ServerID(localID)
		if cfg.RaftNodeID != "" {
			serverID = hashiraft.ServerID(cfg.RaftNodeID)
		} else if id, ok := idMap[advAddr]; ok {
			serverID = hashiraft.ServerID(id)
		} else if id, ok := idMap[localAddr]; ok {
			serverID = hashiraft.ServerID(id)
		} else if id, ok := idMap[cfg.RaftBind]; ok {
			serverID = hashiraft.ServerID(id)
		} else {
			for _, rip := range resolveHostPort(advAddr, defPort, preferV6, res) {
				if id, ok := idMap[rip]; ok {
					serverID = hashiraft.ServerID(id)
					break
				}
			}
		}
		return []hashiraft.Server{
			{
				ID:       serverID,
				Address:  hashiraft.ServerAddress(advAddr),
				Suffrage: hashiraft.Voter,
			},
		}, nil
	}

	resolved := resolveParsedPeers(parsedPeers)

	hasLocal := false
	for _, p := range resolved {
		if isLocalAddress(p, localAliases, defPort, preferV6, res) {
			hasLocal = true
			break
		}
	}
	if !hasLocal && advAddr != "" {
		advResolved := resolveHostPort(advAddr, defPort, preferV6, res)
		if len(advResolved) > 0 {
			resolved = append(resolved, advResolved...)
		} else {
			resolved = append(resolved, advAddr)
		}
	}

	var deduped []string
	seen := make(map[string]bool)
	for _, p := range resolved {
		if !seen[p] {
			seen[p] = true
			deduped = append(deduped, p)
		}
	}
	sort.Strings(deduped)

	var servers []hashiraft.Server
	seenServerIDs := make(map[hashiraft.ServerID]bool)
	seenServerAddrs := make(map[hashiraft.ServerAddress]bool)

	for _, addr := range deduped {
		serverID := hashiraft.ServerID(addr)
		if cfg.RaftNodeID != "" && isLocalAddress(addr, localAliases, defPort, preferV6, res) {
			serverID = hashiraft.ServerID(cfg.RaftNodeID)
		} else if id, ok := idMap[addr]; ok {
			serverID = hashiraft.ServerID(id)
		} else {
			for _, rip := range resolveHostPort(addr, defPort, preferV6, res) {
				if id, ok := idMap[rip]; ok {
					serverID = hashiraft.ServerID(id)
					break
				}
			}
		}

		sAddr := hashiraft.ServerAddress(addr)
		if seenServerAddrs[sAddr] || seenServerIDs[serverID] {
			logrus.WithFields(logrus.Fields{
				"server_id":   serverID,
				"server_addr": sAddr,
			}).Warn("skipping duplicate peer during raft bootstrap server resolution")
			continue
		}
		seenServerAddrs[sAddr] = true
		seenServerIDs[serverID] = true

		servers = append(servers, hashiraft.Server{
			ID:       serverID,
			Address:  sAddr,
			Suffrage: hashiraft.Voter,
		})
	}

	return servers, nil
}
