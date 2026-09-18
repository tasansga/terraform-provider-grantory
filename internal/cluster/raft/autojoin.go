package raft

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
)

const (
	defaultLocalHTTPPort = "8080"
	defaultLocalTLSPort  = "8443"
)

// BuildClusterHTTPClient constructs an HTTP client configured with TLS settings for Raft peer communication.
func BuildClusterHTTPClient(cfg config.Config) (*http.Client, error) {
	tlsConfig, err := config.BuildClusterTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build cluster TLS config: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 5 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}, nil
}

func isClusterLeader(status *ClusterStatusResponse) bool {
	return status != nil && status.IsLeader && status.Role == "leader" && strings.TrimSpace(status.LeaderAddr) != ""
}

// DiscoverActiveLeader probes peer HTTP addresses to discover if an active Raft cluster exists.
// If an active leader is found, its HTTP address is returned.
func DiscoverActiveLeader(ctx context.Context, cfg config.Config, peers []parsedPeerConfig, localAliases map[string]bool, resolver *dnsResolver, optionalClient ...*http.Client) string {
	var client *http.Client
	if len(optionalClient) > 0 && optionalClient[0] != nil {
		client = optionalClient[0]
	}
	return discoverActiveLeaderWithClient(ctx, client, cfg, peers, localAliases, resolver)
}

// discoverActiveLeaderWithClient probes peer HTTP addresses concurrently using an existing HTTP client to discover if an active Raft cluster exists.
func discoverActiveLeaderWithClient(ctx context.Context, client *http.Client, cfg config.Config, peers []parsedPeerConfig, localAliases map[string]bool, resolver *dnsResolver, httpPort ...string) string {
	if len(peers) == 0 {
		return ""
	}
	if client == nil {
		var err error
		client, err = BuildClusterHTTPClient(cfg)
		if err != nil {
			logrus.WithError(err).Error("failed to build cluster HTTP client for leader discovery")
			return ""
		}
		defer client.CloseIdleConnections()
	}
	defPort := defaultRaftPort(cfg)
	preferV6 := isIPv6Listener(cfg)

	probeCtx, probeCancel := context.WithCancel(ctx)
	defer probeCancel()

	var (
		mu          sync.Mutex
		cond        = sync.NewCond(&mu)
		inFlight    int
		queried     = make(map[string]bool)
		leaderFound sync.Once
		leaderURL   string
	)

	var probeURL func(u string)
	probeURL = func(u string) {
		mu.Lock()
		if probeCtx.Err() != nil || queried[u] {
			mu.Unlock()
			return
		}
		queried[u] = true
		inFlight++
		mu.Unlock()

		go func(targetURL string) {
			defer func() {
				mu.Lock()
				inFlight--
				if inFlight == 0 {
					cond.Broadcast()
				}
				mu.Unlock()
			}()

			if probeCtx.Err() != nil {
				return
			}

			reqCtx, reqCancel := context.WithTimeout(probeCtx, 3*time.Second)
			status, err := queryClusterStatus(reqCtx, client, targetURL, cfg.RaftClusterSecret)
			reqCancel()

			if probeCtx.Err() != nil {
				return
			}
			if err != nil {
				if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "unauthorized") {
					logrus.WithError(err).WithField("target", targetURL).Warn("cluster status query unauthorized (check --raft-cluster-secret)")
				} else {
					logrus.WithError(err).WithField("target", targetURL).Debug("failed to query cluster status")
				}
				return
			}

			if isClusterLeader(status) {
				leaderFound.Do(func() {
					leaderURL = targetURL
					probeCancel()
				})
				return
			}

			if strings.TrimSpace(status.LeaderAddr) != "" {
				leaderCandidates := resolveLeaderCandidateURLs(status.LeaderAddr, peers, cfg, localAliases, httpPort...)
				for _, candURL := range leaderCandidates {
					probeURL(candURL)
				}
			}
		}(u)
	}

	for _, p := range peers {
		endpoints := p.resolvedIPs
		if len(endpoints) == 0 && p.raftAddr != "" {
			endpoints = []string{p.raftAddr}
		}

		for _, ep := range endpoints {
			if isLocalAddress(ep, localAliases, defPort, preferV6, resolver) {
				continue
			}
			targetURLs := candidateHTTPURLsForEndpoint(p, ep, cfg, localAliases, httpPort...)
			for _, u := range targetURLs {
				probeURL(u)
			}
		}
	}

	mu.Lock()
	for inFlight > 0 {
		cond.Wait()
	}
	mu.Unlock()

	return leaderURL
}

// candidateHTTPURLsForAddr synthesizes candidate HTTP and HTTPS URLs for a given Raft address
// using the ports configured locally in cfg.TLSBind and cfg.BindAddr.
// Note: Synthesized URLs assume uniform/homogeneous HTTP/TLS ports across cluster members
// unless explicitly mapped via --raft-peer-http-addrs.
func candidateHTTPURLsForAddr(addr string, cfg config.Config) []string {
	var urls []string
	host := splitHost(addr)
	if host != "" {
		tlsPort := config.ExtractPort(cfg.TLSBind)
		if tlsPort == "" || tlsPort == "0" {
			tlsPort = defaultLocalTLSPort
		}
		httpPort := config.ExtractPort(cfg.BindAddr)
		if httpPort == "" || httpPort == "0" {
			httpPort = defaultLocalHTTPPort
		}

		tlsActive := cfg.IsTLSEnabled() || cfg.RaftCAFile != "" || cfg.TLSCert != ""
		if tlsActive && cfg.TLSBind != "" && !strings.EqualFold(strings.TrimSpace(cfg.TLSBind), "off") {
			urls = append(urls, fmt.Sprintf("https://%s", net.JoinHostPort(host, tlsPort)))
		}
		if !strings.EqualFold(strings.TrimSpace(cfg.BindAddr), "off") {
			urls = append(urls, fmt.Sprintf("http://%s", net.JoinHostPort(host, httpPort)))
		}
	}
	return urls
}

func extractHostAndPort(rawURL string) (string, string) {
	rawURL = strings.TrimSpace(rawURL)
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return normalizeHost(u.Hostname()), u.Port()
	}
	raw := strings.TrimPrefix(rawURL, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	if h, p, err := net.SplitHostPort(raw); err == nil {
		return normalizeHost(h), p
	}
	return normalizeHost(raw), ""
}

func isLocalHostOrIP(host string, localAliases map[string]bool) bool {
	if len(localAliases) == 0 || host == "" {
		return false
	}
	targetHost := normalizeHost(host)
	if targetHost == "" {
		return false
	}
	if localAliases[targetHost] {
		return true
	}

	for alias := range localAliases {
		if matchHostOrIP(targetHost, splitHost(alias)) {
			return true
		}
	}
	return false
}

func isLocalHTTPAddr(rawURL string, cfg config.Config, localAliases map[string]bool, httpPort ...string) bool {
	if len(localAliases) == 0 || rawURL == "" {
		return false
	}
	targetHost, targetPort := extractHostAndPort(rawURL)
	if !isLocalHostOrIP(targetHost, localAliases) {
		return false
	}

	boundPort := ""
	if len(httpPort) > 0 && httpPort[0] != "" && httpPort[0] != "0" {
		boundPort = httpPort[0]
	}

	localHTTPPort := config.ExtractPort(cfg.BindAddr)
	if boundPort != "" {
		localHTTPPort = boundPort
	} else if localHTTPPort == "" && !strings.EqualFold(strings.TrimSpace(cfg.BindAddr), "off") {
		localHTTPPort = defaultLocalHTTPPort
	}

	localTLSPort := ""
	tlsActive := cfg.IsTLSEnabled() || cfg.RaftCAFile != "" || cfg.TLSCert != ""
	if tlsActive || cfg.TLSBind != "" {
		localTLSPort = config.ExtractPort(cfg.TLSBind)
		if localTLSPort == "0" {
			localTLSPort = boundPort
		} else if localTLSPort == "" && boundPort != "" && cfg.IsTLSEnabled() {
			localTLSPort = boundPort
		} else if localTLSPort == "" && !strings.EqualFold(strings.TrimSpace(cfg.TLSBind), "off") {
			localTLSPort = defaultLocalTLSPort
		}
	}

	if targetPort == "" {
		if strings.HasPrefix(strings.ToLower(rawURL), "https://") {
			targetPort = "443"
		} else {
			targetPort = "80"
		}
	}

	if (localHTTPPort != "" && targetPort == localHTTPPort) || (localTLSPort != "" && targetPort == localTLSPort) {
		return true
	}

	return false
}

func newURLAccumulator(cfg config.Config, localAliases map[string]bool, httpPort ...string) (func(string), func() []string) {
	var urls []string
	seen := make(map[string]bool)
	addURL := func(u string) {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		if u == "" {
			return
		}
		lower := strings.ToLower(u)
		if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
			if cfg.IsTLSEnabled() || cfg.RaftCAFile != "" || cfg.TLSCert != "" {
				u = "https://" + u
			} else {
				u = "http://" + u
			}
		}
		if !seen[u] {
			seen[u] = true
			if !isLocalHTTPAddr(u, cfg, localAliases, httpPort...) {
				urls = append(urls, u)
			}
		}
	}
	getURLs := func() []string {
		return urls
	}
	return addURL, getURLs
}

func candidateHTTPURLsForEndpoint(p parsedPeerConfig, ep string, cfg config.Config, localAliases map[string]bool, httpPort ...string) []string {
	addURL, getURLs := newURLAccumulator(cfg, localAliases, httpPort...)

	endpointHTTP := ""
	if p.httpAddrsByIP != nil && p.httpAddrsByIP[ep] != "" {
		endpointHTTP = p.httpAddrsByIP[ep]
	}
	if endpointHTTP == "" && p.httpAddr != "" {
		endpointHTTP = p.httpAddr
	}
	if endpointHTTP != "" {
		addURL(endpointHTTP)
	}

	for _, u := range candidateHTTPURLsForAddr(ep, cfg) {
		addURL(u)
	}
	return getURLs()
}

func resolveLeaderCandidateURLs(leaderAddr string, peers []parsedPeerConfig, cfg config.Config, localAliases map[string]bool, httpPort ...string) []string {
	addURL, getURLs := newURLAccumulator(cfg, localAliases, httpPort...)

	for _, candidate := range peers {
		if candidate.httpAddrsByIP != nil {
			if u := candidate.httpAddrsByIP[leaderAddr]; u != "" {
				addURL(u)
				continue
			}
		}
		if candidate.httpAddr == "" {
			continue
		}
		if len(candidate.httpAddrsByIP) > 0 && len(candidate.resolvedIPs) > 1 && !matchPeerAddr(candidate.raftAddr, leaderAddr) {
			continue
		}
		if matchPeerAddr(candidate.raftAddr, leaderAddr) {
			addURL(candidate.httpAddr)
		}
		for _, rip := range candidate.resolvedIPs {
			if matchPeerAddr(rip, leaderAddr) {
				addURL(candidate.httpAddr)
			}
		}
	}

	for _, u := range candidateHTTPURLsForAddr(leaderAddr, cfg) {
		addURL(u)
	}

	return getURLs()
}

func queryClusterStatus(ctx context.Context, client *http.Client, baseURL string, clusterSecret string) (*ClusterStatusResponse, error) {
	reqURL := strings.TrimRight(baseURL, "/") + "/api/v1/cluster/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	ApplyClusterAuth(req, clusterSecret)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_, _ = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return nil, err
	}
	var status ClusterStatusResponse
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// RequestClusterJoin sends a join request to the specified cluster leader HTTP endpoint.
func RequestClusterJoin(ctx context.Context, client *http.Client, leaderURL, nodeID, raftAddr, httpAddr, clusterSecret string) error {
	reqURL := strings.TrimRight(leaderURL, "/") + "/api/v1/cluster/join"
	payload := ClusterJoinRequest{
		NodeID:      nodeID,
		Address:     raftAddr,
		HTTPAddress: httpAddr,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal join payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create join request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	ApplyClusterAuth(req, clusterSecret)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("join request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("join request failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (n *RaftNode) determineLocalHTTPAddr(parsedPeers []parsedPeerConfig, localAliases map[string]bool, defPort string, preferV6 bool, advAddr string) string {
	tlsEnabled := (n.IsTLS() || n.cfg.IsTLSEnabled()) && !strings.EqualFold(strings.TrimSpace(n.cfg.TLSBind), "off")
	for _, p := range parsedPeers {
		matched := isLocalAddress(p.raftAddr, localAliases, defPort, preferV6, n.resolver)
		if !matched {
			for _, rip := range p.resolvedIPs {
				if isLocalAddress(rip, localAliases, defPort, preferV6, n.resolver) {
					matched = true
					break
				}
			}
		}
		if matched {
			var addr string
			if p.httpAddrsByIP != nil {
				if p.httpAddrsByIP[advAddr] != "" {
					addr = p.httpAddrsByIP[advAddr]
				} else {
					aliasKeys := make([]string, 0, len(localAliases))
					for a := range localAliases {
						aliasKeys = append(aliasKeys, a)
					}
					sort.Strings(aliasKeys)
					for _, a := range aliasKeys {
						if p.httpAddrsByIP[a] != "" {
							addr = p.httpAddrsByIP[a]
							break
						}
					}
				}
			}
			if addr == "" {
				addr = p.httpAddr
			}
			if addr != "" {
				if !strings.HasPrefix(strings.ToLower(addr), "http://") && !strings.HasPrefix(strings.ToLower(addr), "https://") {
					if tlsEnabled {
						addr = "https://" + addr
					} else {
						addr = "http://" + addr
					}
				}
				return addr
			}
		}
	}
	host := splitHost(n.cfg.RaftAdvertise)
	if host == "" {
		host = splitHost(n.cfg.RaftBind)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		if advAddr != "" {
			host = splitHost(advAddr)
		}
	}
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return ""
	}

	if tlsEnabled {
		port := n.HTTPPort()
		if port == "" || port == "0" {
			cfgPort := config.ExtractPort(n.cfg.TLSBind)
			if cfgPort == "0" {
				return ""
			}
			port = cfgPort
		}
		if port == "" || port == "0" {
			port = "8443"
		}
		return fmt.Sprintf("https://%s", net.JoinHostPort(host, port))
	}

	if strings.EqualFold(strings.TrimSpace(n.cfg.BindAddr), "off") {
		return ""
	}

	port := n.HTTPPort()
	if port == "" || port == "0" {
		cfgPort := config.ExtractPort(n.cfg.BindAddr)
		if cfgPort == "0" {
			return ""
		}
		port = cfgPort
	}
	if port == "" || port == "0" {
		port = "8080"
	}
	return fmt.Sprintf("http://%s", net.JoinHostPort(host, port))
}

func (n *RaftNode) cloneParsedPeersLocked() []parsedPeerConfig {
	if n == nil || len(n.parsedPeers) == 0 {
		return nil
	}
	peers := make([]parsedPeerConfig, len(n.parsedPeers))
	copy(peers, n.parsedPeers)
	for i := range peers {
		if peers[i].httpAddrsByIP != nil {
			m := make(map[string]string, len(peers[i].httpAddrsByIP))
			for k, v := range peers[i].httpAddrsByIP {
				m[k] = v
			}
			peers[i].httpAddrsByIP = m
		}
		if len(peers[i].resolvedIPs) > 0 {
			rips := make([]string, len(peers[i].resolvedIPs))
			copy(rips, peers[i].resolvedIPs)
			peers[i].resolvedIPs = rips
		}
	}
	return peers
}

func (n *RaftNode) cloneLocalAliasesLocked() map[string]bool {
	if n == nil || len(n.localAliases) == 0 {
		return nil
	}
	aliases := make(map[string]bool, len(n.localAliases))
	for k, v := range n.localAliases {
		aliases[k] = v
	}
	return aliases
}

func (n *RaftNode) getParsedPeers() []parsedPeerConfig {
	if n == nil {
		return nil
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.cloneParsedPeersLocked()
}

func (n *RaftNode) getLocalAliases() map[string]bool {
	if n == nil {
		return nil
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.cloneLocalAliasesLocked()
}

func (n *RaftNode) startAutoJoinRetry(leaderURL, nodeID, raftAddr, httpAddr string) {
	n.setAutoJoinStatus("joining")
	n.mu.Lock()
	if nodeID != "" && n.nodeID == "" {
		n.nodeID = nodeID
	}
	if raftAddr != "" && n.advAddr == "" {
		n.advAddr = raftAddr
	}
	if leaderURL != "" && n.lastJoinedLeader == "" {
		n.lastJoinedLeader = leaderURL
	}
	n.mu.Unlock()

	client, err := BuildClusterHTTPClient(n.cfg)
	if err != nil {
		logrus.WithError(err).Error("failed to build cluster HTTP client for auto-join retry")
		return
	}
	defer client.CloseIdleConnections()
	currentLeader := leaderURL
	maxRetries := 30

	checkJoined := func() bool {
		if n.raft != nil {
			cfgFuture := n.raft.GetConfiguration()
			if cfgFuture.Error() == nil {
				for _, srv := range cfgFuture.Configuration().Servers {
					if string(srv.ID) == nodeID && string(srv.Address) == raftAddr {
						logrus.WithField("leader", currentLeader).Info("node successfully joined Raft cluster")
						n.setAutoJoinStatus("joined")
						n.mu.Lock()
						if currentLeader != "" {
							n.lastJoinedLeader = currentLeader
						}
						n.mu.Unlock()
						return true
					}
				}
			}
		}
		return false
	}

	isDynamicPort := config.ExtractPort(n.cfg.TLSBind) == "0" || config.ExtractPort(n.cfg.BindAddr) == "0"

	attemptJoin := func(leader string, attempt int) bool {
		if leader == "" {
			return false
		}
		currentHTTPAddr := httpAddr
		if currentHTTPAddr == "" || isDynamicPort || strings.HasSuffix(currentHTTPAddr, ":0") {
			if evaluated := n.determineLocalHTTPAddr(n.getParsedPeers(), n.getLocalAliases(), n.defPort, n.preferV6, raftAddr); evaluated != "" {
				currentHTTPAddr = evaluated
			}
		}
		ctx, cancel := context.WithTimeout(n.nodeCtx, 5*time.Second)
		err := RequestClusterJoin(ctx, client, leader, nodeID, raftAddr, currentHTTPAddr, n.cfg.RaftClusterSecret)
		cancel()

		if err == nil {
			logrus.WithField("leader", leader).Info("successfully registered with Raft cluster leader")
			n.setAutoJoinStatus("joined")
			n.mu.Lock()
			n.lastJoinedLeader = leader
			n.mu.Unlock()
			return true
		}

		logEntry := logrus.WithError(err).WithField("leader", leader)
		if attempt >= 0 {
			logEntry.WithField("attempt", attempt+1).Warn("failed to auto-join Raft cluster leader; retrying")
		} else {
			logEntry.Debug("failed to auto-join Raft cluster leader during steady-state retry")
		}
		return false
	}

	discoverLeader := func(attempt int) bool {
		if hasDNSPeer(n.cfg.RaftPeers) {
			if n.resolver != nil {
				n.resolver.flush()
			}
			updated := parsePeers(n.cfg.RaftPeers, n.defPort, n.preferV6, n.resolver)
			updated = applyPeerHTTPAddrs(updated, n.cfg.RaftPeerHTTPAddrs)
			n.mu.Lock()
			n.parsedPeers = updated
			n.mu.Unlock()
		}
		peers := n.getParsedPeers()
		aliases := n.getLocalAliases()
		if len(peers) > 0 {
			peerTimeout := time.Duration(len(peers)) * 3 * time.Second
			if peerTimeout < 3*time.Second {
				peerTimeout = 3 * time.Second
			} else if peerTimeout > 15*time.Second {
				peerTimeout = 15 * time.Second
			}
			discCtx, discCancel := context.WithTimeout(n.nodeCtx, peerTimeout)
			newLeader := discoverActiveLeaderWithClient(discCtx, client, n.cfg, peers, aliases, n.resolver, n.HTTPPort())
			discCancel()
			if newLeader != "" && newLeader != currentLeader {
				logrus.WithFields(logrus.Fields{
					"old_leader": currentLeader,
					"new_leader": newLeader,
				}).Info("discovered new active Raft cluster leader during join retry")
				currentLeader = newLeader
				n.mu.Lock()
				n.lastJoinedLeader = newLeader
				n.mu.Unlock()
				if attemptJoin(currentLeader, attempt) {
					return true
				}
			}
		}
		return false
	}

	for i := 0; i < maxRetries; i++ {
		select {
		case <-n.nodeCtx.Done():
			return
		default:
		}

		if checkJoined() {
			return
		}

		if currentLeader != "" {
			if attemptJoin(currentLeader, i) {
				return
			}
		}

		if discoverLeader(i) {
			return
		}

		backoff := time.Duration(1+i) * 500 * time.Millisecond
		if n.autoJoinBackoff != nil {
			backoff = n.autoJoinBackoff(i)
		}
		timer := time.NewTimer(backoff)
		select {
		case <-n.nodeCtx.Done():
			timer.Stop()
			return
		case <-timer.C:
			timer.Stop()
		}
	}

	n.setAutoJoinStatus("exhausted")
	logrus.WithField("leader", currentLeader).Error("exhausted retries trying to auto-join Raft cluster leader")

	steadyInterval := 30 * time.Second
	for {
		select {
		case <-n.nodeCtx.Done():
			return
		default:
		}

		if checkJoined() {
			return
		}

		if currentLeader != "" {
			if attemptJoin(currentLeader, -1) {
				return
			}
		}

		if discoverLeader(-1) {
			return
		}

		interval := steadyInterval
		if n.autoJoinBackoff != nil {
			interval = n.autoJoinBackoff(maxRetries)
		}
		timer := time.NewTimer(interval)
		select {
		case <-n.nodeCtx.Done():
			timer.Stop()
			return
		case <-timer.C:
			timer.Stop()
		}
	}
}
