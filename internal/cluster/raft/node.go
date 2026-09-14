package raft

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	hashiraft "github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
	"github.com/tasansga/terraform-provider-grantory/internal/store"
)

const (
	// RaftDirName is the directory name where Raft database and snapshots are stored.
	RaftDirName = "raft"
	// SnapshotsDirName is the directory name under RaftDirName for snapshot archives.
	SnapshotsDirName = "snapshots"
	// StagingDirName is the directory name under RaftDirName for transient snapshot staging directories.
	StagingDirName = "staging"
	// RaftDBFileName is the filename of the BoltDB store holding Raft logs and stable state.
	RaftDBFileName = "raft.db"
)

var (
	randRead                         = cryptorand.Read
	ErrNotFound                      = errors.New("server not found in cluster")
	defaultBootstrapDNSWaitTimeout   = 15 * time.Second
	defaultBootstrapDNSRetryInterval = 500 * time.Millisecond
)

// RaftNode manages the lifecycle, network transport, storage, and state replication
// for a node participating in the Grantory Raft cluster.
type RaftNode struct {
	cfg           config.Config
	nodeID        string
	resolver      *dnsResolver
	raft          *hashiraft.Raft
	fsm           *FSM
	transport     hashiraft.Transport
	logStore      hashiraft.LogStore
	stableStore   hashiraft.StableStore
	snapshotStore hashiraft.SnapshotStore
	nsStore       *store.NamespaceStore
	boltStore     *raftboltdb.BoltStore
	hopSecret     [32]byte

	mu                 sync.RWMutex
	httpPort           string
	tlsEnabled         bool
	httpAddrs          map[string]string
	staticHTTPAddrs    map[string]string
	serverIDByAddr     map[string]string
	addrByServerID     map[string]string
	lastConfigRefresh  time.Time
	configRefreshGroup singleflight.Group
	getConfigOverride  func() hashiraft.ConfigurationFuture
	shutdownOverride   func() error
	barrierOverride    func(time.Duration) hashiraft.Future
	isLeaderOverride   func() bool
	stepDownOverride   func() error
	barrierMu          sync.Mutex
	activeBarrier      *barrierRound
	pendingBarrier     *barrierRound

	nodeCtx    context.Context
	nodeCancel context.CancelFunc

	closeOnce sync.Once
	closeErr  error
}

// RaftNodeOption configures a RaftNode during creation.
type RaftNodeOption func(*nodeOptions)

type nodeOptions struct {
	resolver         *dnsResolver
	dnsWaitTimeout   time.Duration
	dnsRetryInterval time.Duration
}

// WithDNSResolver configures a custom DNS resolver for peer resolution.
func WithDNSResolver(r *dnsResolver) RaftNodeOption {
	return func(o *nodeOptions) {
		if r != nil {
			o.resolver = r
		}
	}
}

// WithDNSWaitTimeout configures the maximum time to wait for headless DNS stabilization.
func WithDNSWaitTimeout(d time.Duration) RaftNodeOption {
	return func(o *nodeOptions) {
		if d > 0 {
			o.dnsWaitTimeout = d
		}
	}
}

// WithDNSRetryInterval configures the retry polling interval for headless DNS stabilization.
func WithDNSRetryInterval(d time.Duration) RaftNodeOption {
	return func(o *nodeOptions) {
		if d > 0 {
			o.dnsRetryInterval = d
		}
	}
}

// NewRaftNode initializes and boots a Raft node with BoltDB log storage,
// file snapshot storage, and custom network transport.
func NewRaftNode(ctx context.Context, cfg config.Config, nsStore *store.NamespaceStore, dataDir string, opts ...RaftNodeOption) (*RaftNode, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if storage.IsPostgresDSN(dataDir) || storage.IsPostgresDSN(cfg.Database) {
		return nil, errors.New("raft clustering is not supported with postgresql backend")
	}
	if dataDir == "" {
		return nil, errors.New("dataDir is required")
	}

	nOpts := nodeOptions{
		resolver:         newDNSResolver(30*time.Second, net.LookupIP),
		dnsWaitTimeout:   defaultBootstrapDNSWaitTimeout,
		dnsRetryInterval: defaultBootstrapDNSRetryInterval,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&nOpts)
		}
	}

	nodeCtx, nodeCancel := context.WithCancel(context.Background())
	success := false
	defer func() {
		if !success {
			nodeCancel()
		}
	}()

	raftDir := filepath.Join(dataDir, RaftDirName)
	if err := os.MkdirAll(raftDir, 0o755); err != nil {
		return nil, fmt.Errorf("create raft directory %q: %w", raftDir, err)
	}

	stagingDirs := []string{filepath.Join(dataDir, RaftDirName, StagingDirName)}
	if cfg.Database != "" && !storage.IsPostgresDSN(cfg.Database) && cfg.Database != dataDir {
		stagingDirs = append(stagingDirs, filepath.Join(cfg.Database, RaftDirName, StagingDirName))
	}
	CleanupStagingDirs(append(stagingDirs, dataDir, cfg.Database)...)

	snapshotDir := filepath.Join(raftDir, SnapshotsDirName)
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return nil, fmt.Errorf("create snapshot directory %q: %w", snapshotDir, err)
	}

	dbPath := filepath.Join(raftDir, RaftDBFileName)
	boltStore, err := raftboltdb.NewBoltStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open bolt store %q: %w", dbPath, err)
	}

	snapshotStore, err := hashiraft.NewFileSnapshotStore(snapshotDir, 3, newRaftLogWriter(logrus.WithField("component", "raft"), logrus.InfoLevel))
	if err != nil {
		_ = boltStore.Close()
		return nil, fmt.Errorf("create snapshot store %q: %w", snapshotDir, err)
	}

	transport, err := NewTransport(cfg)
	if err != nil {
		_ = boltStore.Close()
		return nil, fmt.Errorf("create raft transport: %w", err)
	}

	var hopSecret [32]byte
	if cfg.RaftClusterSecret != "" {
		mac := hmac.New(sha256.New, []byte(cfg.RaftClusterSecret))
		mac.Write([]byte("grantory-cluster-hop-secret"))
		copy(hopSecret[:], mac.Sum(nil))
	} else if _, err := randRead(hopSecret[:]); err != nil {
		_ = transport.Close()
		_ = boltStore.Close()
		return nil, fmt.Errorf("generate hop secret: %w", err)
	}

	fsm := NewFSM(nodeCtx, nsStore)

	hasState, err := hashiraft.HasExistingState(boltStore, boltStore, snapshotStore)
	if err != nil {
		_ = transport.Close()
		_ = boltStore.Close()
		return nil, fmt.Errorf("check existing raft state: %w", err)
	}

	advAddr := cfg.RaftAdvertise
	if advAddr == "" {
		advAddr = string(transport.LocalAddr())
	}
	if advAddr == "" {
		advAddr = cfg.RaftBind
	}

	defPort := defaultRaftPort(cfg)
	if _, _, err := net.SplitHostPort(advAddr); err != nil && defPort != "" {
		advAddr = net.JoinHostPort(strings.Trim(advAddr, "[]"), defPort)
	}

	var httpPort string
	tlsEnabled := cfg.IsTLSEnabled()
	if tlsEnabled {
		httpPort = config.ExtractPort(cfg.TLSBind)
	} else if cfg.BindAddr != "" && !strings.EqualFold(cfg.BindAddr, "off") {
		httpPort = config.ExtractPort(cfg.BindAddr)
	}
	if httpPort == "0" {
		httpPort = ""
	}

	node := &RaftNode{
		cfg:               cfg,
		resolver:          nOpts.resolver,
		fsm:               fsm,
		transport:         transport,
		logStore:          boltStore,
		stableStore:       boltStore,
		snapshotStore:     snapshotStore,
		nsStore:           nsStore,
		boltStore:         boltStore,
		hopSecret:         hopSecret,
		httpPort:          httpPort,
		tlsEnabled:        tlsEnabled,
		httpAddrs:         make(map[string]string),
		staticHTTPAddrs:   make(map[string]string),
		serverIDByAddr:    make(map[string]string),
		addrByServerID:    make(map[string]string),
		lastConfigRefresh: time.Now(),
		nodeCtx:           nodeCtx,
		nodeCancel:        nodeCancel,
	}

	preferV6 := isIPv6Listener(cfg)
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
		for _, rip := range resolveHostPort(addr, defPort, preferV6, node.resolver) {
			localAliases[rip] = true
		}
	}
	addLocal(advAddr)
	addLocal(cfg.RaftBind)
	if transport != nil {
		addLocal(string(transport.LocalAddr()))
	}

	parsedPeers := parsePeers(cfg.RaftPeers, defPort, preferV6, node.resolver)

	localID := cfg.RaftNodeID
	if localID == "" {
		for _, p := range parsedPeers {
			if p.id != "" {
				if isLocalAddress(p.raftAddr, localAliases, defPort, preferV6, node.resolver) {
					localID = p.id
					break
				}
				for _, rip := range p.resolvedIPs {
					if isLocalAddress(rip, localAliases, defPort, preferV6, node.resolver) {
						localID = p.id
						break
					}
				}
				if localID != "" {
					break
				}
			}
		}
	}
	if localID == "" {
		localID = advAddr
	}
	node.nodeID = localID

	raftConfig := hashiraft.DefaultConfig()
	raftConfig.LocalID = hashiraft.ServerID(localID)
	raftConfig.LogLevel = getRaftLogLevel(cfg.LogLevel)
	raftConfig.LogOutput = newRaftLogWriter(logrus.WithField("component", "raft"), logrus.InfoLevel)

	if cfg.RaftSnapshotThreshold > 0 {
		raftConfig.SnapshotThreshold = cfg.RaftSnapshotThreshold
	}
	if cfg.RaftTrailingLogs > 0 {
		raftConfig.TrailingLogs = cfg.RaftTrailingLogs
	}

	if !hasState && cfg.RaftBootstrapExpect > 0 {
		servers, err := buildBootstrapServers(cfg, localID, string(transport.LocalAddr()), parsedPeers, node.resolver)
		if err != nil {
			_ = transport.Close()
			_ = boltStore.Close()
			return nil, fmt.Errorf("build bootstrap configuration: %w", err)
		}

		if len(servers) < cfg.RaftBootstrapExpect && cfg.RaftBootstrapExpect > 1 && hasDNSPeer(cfg.RaftPeers) {
			logrus.WithField("discovered", len(servers)).
				WithField("expected", cfg.RaftBootstrapExpect).
				Info("waiting for headless DNS discovery stabilization before bootstrap")

			var ctxDone <-chan struct{}
			if ctx != nil {
				ctxDone = ctx.Done()
			}

			timer := time.NewTimer(nOpts.dnsWaitTimeout)
			defer timer.Stop()
			ticker := time.NewTicker(nOpts.dnsRetryInterval)
			defer ticker.Stop()

		retryLoop:
			for {
				select {
				case <-ctxDone:
					_ = transport.Close()
					_ = boltStore.Close()
					return nil, fmt.Errorf("wait for DNS bootstrap peers: %w", ctx.Err())
				case <-timer.C:
					break retryLoop
				case <-ticker.C:
					node.resolver.flush()
					updatedPeers := parsePeers(cfg.RaftPeers, defPort, preferV6, node.resolver)
					newServers, err := buildBootstrapServers(cfg, localID, string(transport.LocalAddr()), updatedPeers, node.resolver)
					if err == nil {
						servers = newServers
						parsedPeers = updatedPeers
						if len(servers) >= cfg.RaftBootstrapExpect {
							break retryLoop
						}
					}
				}
			}
		}

		if len(servers) >= cfg.RaftBootstrapExpect {
			for _, s := range servers {
				if string(s.ID) == localID || isLocalAddress(string(s.Address), localAliases, defPort, preferV6, node.resolver) {
					raftConfig.LocalID = s.ID
					localID = string(s.ID)
					node.nodeID = localID
					break
				}
			}

			conf := hashiraft.Configuration{Servers: servers}
			if err := hashiraft.BootstrapCluster(raftConfig, boltStore, boltStore, snapshotStore, transport, conf); err != nil {
				_ = transport.Close()
				_ = boltStore.Close()
				return nil, fmt.Errorf("bootstrap cluster: %w", err)
			}
		} else {
			logrus.WithField("discovered", len(servers)).
				WithField("expected", cfg.RaftBootstrapExpect).
				Info("skipping cluster auto-bootstrap: discovered servers less than bootstrap-expect")
		}
	}

	// Initialize static peer HTTP addresses and server ID mappings before
	// registering with FSM so that snapshot restore during hashiraft.NewRaft
	// preserves static peer HTTP addresses.
	node.initStaticPeers(parsedPeers, cfg.RaftPeerHTTPAddrs)

	// Register registrar before initializing Raft so that snapshot restore
	// occurring during hashiraft.NewRaft captures dynamic HTTP mappings.
	fsm.SetRegistrar(node)

	raftInstance, err := hashiraft.NewRaft(raftConfig, fsm, boltStore, boltStore, snapshotStore, transport)
	if err != nil {
		_ = transport.Close()
		_ = boltStore.Close()
		return nil, fmt.Errorf("create raft instance: %w", err)
	}

	node.raft = raftInstance
	success = true

	node.mu.Lock()
	// Populate initial configuration into cache if available
	configFuture := raftInstance.GetConfiguration()
	if err := configFuture.Error(); err == nil {
		for _, srv := range configFuture.Configuration().Servers {
			sID := string(srv.ID)
			sAddr := string(srv.Address)
			node.serverIDByAddr[sAddr] = sID
			node.addrByServerID[sID] = sAddr
			for _, rip := range node.resolveHostPort(sAddr) {
				node.serverIDByAddr[rip] = sID
			}
		}
		node.lastConfigRefresh = time.Now()
	}
	node.mu.Unlock()

	return node, nil
}

// IsLeader reports whether this node is currently the cluster leader.
func (n *RaftNode) IsLeader() bool {
	if n == nil {
		return false
	}
	if n.isLeaderOverride != nil {
		return n.isLeaderOverride()
	}
	if n.raft == nil {
		return false
	}
	return n.raft.State() == hashiraft.Leader
}

// StepDown initiates leadership transfer away from this node to another cluster member.
// It returns an error if the node is nil, uninitialized, or not the active leader.
func (n *RaftNode) StepDown() error {
	if n == nil || (n.raft == nil && n.stepDownOverride == nil) {
		return errors.New("raft not initialized")
	}
	if !n.IsLeader() {
		return errors.New("not the cluster leader")
	}
	if n.stepDownOverride != nil {
		return n.stepDownOverride()
	}
	future := n.raft.LeadershipTransfer()
	return future.Error()
}

// LeaderAddr returns the address of the current cluster leader, or empty string if unknown.
func (n *RaftNode) LeaderAddr() string {
	if n == nil || n.raft == nil {
		return ""
	}
	return string(n.raft.Leader())
}

// NodeID returns the identifier of this Raft node.
func (n *RaftNode) NodeID() string {
	if n == nil {
		return ""
	}
	return n.nodeID
}

// RaftAddress returns the local network address used by this Raft node's transport.
func (n *RaftNode) RaftAddress() string {
	if n == nil || n.transport == nil {
		return ""
	}
	return string(n.transport.LocalAddr())
}

// RaftAdvertise returns the configured advertise address for Raft communication, or empty string if not configured.
func (n *RaftNode) RaftAdvertise() string {
	if n == nil {
		return ""
	}
	return n.cfg.RaftAdvertise
}

// Stats returns a map of runtime statistics from the underlying Raft node.
func (n *RaftNode) Stats() map[string]string {
	if n == nil || n.raft == nil {
		return nil
	}
	return n.raft.Stats()
}

// Role reports the current Raft role ("leader", "follower", "candidate", "shutdown").
func (n *RaftNode) Role() string {
	if n == nil || n.raft == nil {
		return "standalone"
	}
	return strings.ToLower(n.raft.State().String())
}

// HopSecret returns the node's local secret used for hop loop detection authentication.
func (n *RaftNode) HopSecret() [32]byte {
	if n == nil {
		return [32]byte{}
	}
	return n.hopSecret
}

// resolveHostPort resolves target using the node's instance-scoped DNS resolver.
func (n *RaftNode) resolveHostPort(target string) []string {
	if n == nil {
		return nil
	}
	return resolveHostPort(target, defaultRaftPort(n.cfg), isIPv6Listener(n.cfg), n.resolver)
}

// AddVoter registers a new voting member in the Raft cluster configuration.
func (n *RaftNode) AddVoter(id string, addr string, prevIndex uint64, timeout time.Duration) error {
	if n == nil || n.raft == nil {
		return errors.New("raft not initialized")
	}
	future := n.raft.AddVoter(hashiraft.ServerID(id), hashiraft.ServerAddress(addr), prevIndex, timeout)
	if err := future.Error(); err != nil {
		if IsMembershipConflict(err) {
			cfgFuture := n.raft.GetConfiguration()
			if cfgFuture.Error() == nil {
				for _, srv := range cfgFuture.Configuration().Servers {
					if string(srv.ID) == id && string(srv.Address) == addr {
						n.mu.Lock()
						if n.serverIDByAddr == nil {
							n.serverIDByAddr = make(map[string]string)
						}
						if n.addrByServerID == nil {
							n.addrByServerID = make(map[string]string)
						}
						n.serverIDByAddr[addr] = id
						n.addrByServerID[id] = addr
						for _, rip := range n.resolveHostPort(addr) {
							n.serverIDByAddr[rip] = id
						}
						n.mu.Unlock()
						return nil
					}
				}
			}
		}
		return err
	}
	n.mu.Lock()
	if n.serverIDByAddr == nil {
		n.serverIDByAddr = make(map[string]string)
	}
	if n.addrByServerID == nil {
		n.addrByServerID = make(map[string]string)
	}
	n.serverIDByAddr[addr] = id
	n.addrByServerID[id] = addr
	for _, rip := range n.resolveHostPort(addr) {
		n.serverIDByAddr[rip] = id
	}
	n.mu.Unlock()
	return nil
}

// AddNonvoter registers a non-voting member in the Raft cluster configuration.
func (n *RaftNode) AddNonvoter(id string, addr string, prevIndex uint64, timeout time.Duration) error {
	if n == nil || n.raft == nil {
		return errors.New("raft not initialized")
	}
	future := n.raft.AddNonvoter(hashiraft.ServerID(id), hashiraft.ServerAddress(addr), prevIndex, timeout)
	if err := future.Error(); err != nil {
		return err
	}
	n.mu.Lock()
	if n.serverIDByAddr == nil {
		n.serverIDByAddr = make(map[string]string)
	}
	if n.addrByServerID == nil {
		n.addrByServerID = make(map[string]string)
	}
	n.serverIDByAddr[addr] = id
	n.addrByServerID[id] = addr
	for _, rip := range n.resolveHostPort(addr) {
		n.serverIDByAddr[rip] = id
	}
	n.mu.Unlock()
	return nil
}

// RemoveServer removes a member from the Raft cluster configuration.
func (n *RaftNode) RemoveServer(id string, prevIndex uint64, timeout time.Duration) error {
	if n == nil || n.raft == nil {
		return errors.New("raft not initialized")
	}
	cfgFuture := n.raft.GetConfiguration()
	if err := cfgFuture.Error(); err != nil {
		return err
	}
	var targetServer *hashiraft.Server
	for _, srv := range cfgFuture.Configuration().Servers {
		if string(srv.ID) == id || string(srv.Address) == id {
			s := srv
			targetServer = &s
			break
		}
	}
	if targetServer == nil {
		return ErrNotFound
	}
	localAddr := n.RaftAddress()
	if (string(targetServer.ID) == n.nodeID || (n.cfg.RaftAdvertise != "" && string(targetServer.Address) == n.cfg.RaftAdvertise) || (localAddr != "" && string(targetServer.Address) == localAddr)) && n.IsLeader() {
		return errors.New("cannot remove active cluster leader; step down leadership via /api/v1/cluster/step-down or stop the node to elect a new leader before removal")
	}
	future := n.raft.RemoveServer(targetServer.ID, prevIndex, timeout)
	if err := future.Error(); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return fmt.Errorf("%w: %v", ErrNotFound, err)
		}
		return err
	}
	n.mu.Lock()
	n.deregisterHTTPAddrLocked(string(targetServer.ID))
	n.deregisterHTTPAddrLocked(id)
	n.mu.Unlock()
	return nil
}

// ServerInfo describes a member server in the Raft cluster configuration.
type ServerInfo struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Suffrage string `json:"suffrage"`
}

// ClusterServers returns the list of member servers in the current Raft cluster configuration.
// Returns nil if Raft is not initialized or the configuration cannot be retrieved.
func (n *RaftNode) ClusterServers() []ServerInfo {
	if n == nil {
		return nil
	}

	n.mu.RLock()
	getOverride := n.getConfigOverride
	r := n.raft
	n.mu.RUnlock()

	var configFuture hashiraft.ConfigurationFuture
	if getOverride != nil {
		configFuture = getOverride()
	} else if r != nil {
		configFuture = r.GetConfiguration()
	} else {
		return nil
	}

	if err := configFuture.Error(); err != nil {
		return nil
	}

	rawServers := configFuture.Configuration().Servers
	servers := make([]ServerInfo, 0, len(rawServers))
	for _, srv := range rawServers {
		var suffrage string
		switch srv.Suffrage {
		case hashiraft.Nonvoter:
			suffrage = "nonvoter"
		case hashiraft.Staging:
			suffrage = "staging"
		default:
			suffrage = "voter"
		}
		servers = append(servers, ServerInfo{
			ID:       string(srv.ID),
			Address:  string(srv.Address),
			Suffrage: suffrage,
		})
	}
	return servers
}

// IsMembershipConflict checks whether an error returned from Raft membership mutation operations
// indicates that the node or configuration already exists or is in conflict.
func IsMembershipConflict(err error) bool {
	if err == nil {
		return false
	}
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "already exists") ||
		strings.Contains(errMsg, "conflict") ||
		strings.Contains(errMsg, "already part of") ||
		strings.Contains(errMsg, "duplicate")
}

// SetHTTPPort configures the HTTP port used to resolve the leader's HTTP address.
func (n *RaftNode) SetHTTPPort(port string) {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.httpPort = port
}

// HTTPPort returns the configured HTTP port.
func (n *RaftNode) HTTPPort() string {
	if n == nil {
		return ""
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.httpPort
}

// SetTLS dynamically configures whether the HTTP listener uses TLS, primarily
// used for test harnesses and dynamic listener reconfiguration.
func (n *RaftNode) SetTLS(enabled bool) {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tlsEnabled = enabled
}

// IsTLS reports whether HTTP communication uses TLS.
func (n *RaftNode) IsTLS() bool {
	if n == nil {
		return false
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.tlsEnabled
}

// Propose applies a state mutation command through Raft consensus to the FSM.
// Note that once submitted via n.raft.Apply(), the Raft proposal cannot be aborted
// in the underlying consensus engine; if ctx.Done() returns ctx.Err(), the proposal
// may still commit and apply in the background.
func (n *RaftNode) Propose(ctx context.Context, cmd RaftCommand) (ApplyResponse, error) {
	if n == nil || n.raft == nil {
		return ApplyResponse{}, errors.New("raft not initialized")
	}

	if n.nodeCtx != nil && n.nodeCtx.Err() != nil {
		return ApplyResponse{}, n.nodeCtx.Err()
	}

	data, err := cmd.Encode()
	if err != nil {
		return ApplyResponse{}, fmt.Errorf("encode command: %w", err)
	}

	timeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			return ApplyResponse{}, context.DeadlineExceeded
		}
	}

	if err := ctx.Err(); err != nil {
		return ApplyResponse{}, err
	}

	future := n.raft.Apply(data, timeout)

	if ctx.Done() == nil {
		if err := future.Error(); err != nil {
			return ApplyResponse{}, err
		}
	} else {
		errCh := make(chan error, 1)
		go func() {
			errCh <- future.Error()
		}()

		select {
		case <-ctx.Done():
			return ApplyResponse{}, ctx.Err()
		case err := <-errCh:
			if err != nil {
				return ApplyResponse{}, err
			}
		}
	}

	res := future.Response()
	if res == nil {
		return ApplyResponse{}, nil
	}

	applyResp, ok := res.(ApplyResponse)
	if !ok {
		return ApplyResponse{}, fmt.Errorf("unexpected apply response type: %T", res)
	}
	return applyResp, nil
}

// Close gracefully terminates the Raft node, transport, and durable stores.
func (n *RaftNode) Close() error {
	if n == nil {
		return nil
	}

	n.closeOnce.Do(func() {
		if n.shutdownOverride != nil {
			if err := n.shutdownOverride(); err != nil && n.closeErr == nil {
				n.closeErr = err
			}
		} else if n.raft != nil {
			future := n.raft.Shutdown()
			if err := future.Error(); err != nil && n.closeErr == nil {
				n.closeErr = err
			}
		}
		if n.nodeCancel != nil {
			nodeCancel := n.nodeCancel
			n.nodeCancel = nil
			nodeCancel()
		}
		if n.transport != nil {
			if closer, ok := n.transport.(interface{ Close() error }); ok {
				if err := closer.Close(); err != nil && n.closeErr == nil {
					n.closeErr = err
				}
			}
		}
		if n.boltStore != nil {
			if err := n.boltStore.Close(); err != nil && n.closeErr == nil {
				n.closeErr = err
			}
		}
	})
	return n.closeErr
}

// Raft returns the underlying *hashiraft.Raft instance.
func (n *RaftNode) Raft() *hashiraft.Raft {
	if n == nil {
		return nil
	}
	return n.raft
}

// FSM returns the FSM attached to this node.
func (n *RaftNode) FSM() *FSM {
	if n == nil {
		return nil
	}
	return n.fsm
}

// Transport returns the network transport used by this node.
func (n *RaftNode) Transport() hashiraft.Transport {
	if n == nil {
		return nil
	}
	return n.transport
}

// NamespaceStore returns the NamespaceStore associated with this node.
func (n *RaftNode) NamespaceStore() *store.NamespaceStore {
	if n == nil {
		return nil
	}
	return n.nsStore
}

func getRaftLogLevel(level logrus.Level) string {
	switch level {
	case logrus.TraceLevel, logrus.DebugLevel:
		return "DEBUG"
	case logrus.WarnLevel:
		return "WARN"
	case logrus.ErrorLevel, logrus.FatalLevel:
		return "ERROR"
	case logrus.PanicLevel:
		return "ERROR"
	default:
		return "INFO"
	}
}

// CleanupStagingDirs removes transient staging directories (prefixed with snap-stage- or grantory-restore-)
// from the provided directories. Non-existent directories and Postgres DSNs are safely ignored.
func CleanupStagingDirs(dirs ...string) {
	for _, dir := range dirs {
		if dir == "" || storage.IsPostgresDSN(dir) {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() && (strings.HasPrefix(entry.Name(), "snap-stage-") || strings.HasPrefix(entry.Name(), "grantory-restore-")) {
				_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
			}
		}
	}
}
