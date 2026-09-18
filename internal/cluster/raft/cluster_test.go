package raft

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	hashiraft "github.com/hashicorp/raft"
	"github.com/sirupsen/logrus"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
	"github.com/tasansga/terraform-provider-grantory/internal/store"
)

func getFreeClusterPorts(t *testing.T, count int) []string {
	t.Helper()
	listeners := make([]net.Listener, count)
	ports := make([]string, count)
	for i := 0; i < count; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		listeners[i] = l
		ports[i] = l.Addr().String()
	}
	for _, l := range listeners {
		require.NoError(t, l.Close())
	}
	return ports
}

func TestThreeNodeClusterBootstrapAndElection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ports := getFreeClusterPorts(t, 3)
	nodes := make([]*RaftNode, 3)

	for i := 0; i < 3; i++ {
		dir := t.TempDir()
		nsStore, err := store.NewNamespaceStore(ctx, dir)
		require.NoError(t, err)

		cfg := config.Config{
			RaftBind:            ports[i],
			RaftAdvertise:       ports[i],
			RaftNodeID:          ports[i],
			RaftBootstrapExpect: 3,
			RaftPeers:           ports,
		}

		node, err := NewRaftNode(ctx, cfg, nsStore, dir)
		require.NoError(t, err)
		nodes[i] = node
		defer func() { _ = node.Close() }()
	}

	// Wait for leader election
	require.Eventually(t, func() bool {
		leaders := 0
		for _, node := range nodes {
			if node.IsLeader() {
				leaders++
			}
		}
		return leaders == 1
	}, 10*time.Second, 100*time.Millisecond)

	var leader *RaftNode
	for _, node := range nodes {
		if node.IsLeader() {
			leader = node
			break
		}
	}
	require.NotNil(t, leader)

	// Propose a command on leader
	cmd, err := NewCommand("default", CmdCreateHost, time.Now().UTC(), storage.Host{ID: "replicated-host"})
	require.NoError(t, err)
	resp, err := leader.Propose(ctx, cmd)
	require.NoError(t, err)
	require.NoError(t, resp.Error)

	// Assert replication across all 3 nodes
	for _, node := range nodes {
		require.Eventually(t, func() bool {
			st, err := node.nsStore.StoreFor(ctx, "default")
			if err != nil {
				return false
			}
			_, err = st.GetHost(ctx, "replicated-host")
			return err == nil
		}, 5*time.Second, 100*time.Millisecond)
	}
}

func TestSingleNodeClusterBootstrapAndBarrier(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	// Wait for leader election
	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	require.NotEmpty(t, node.LeaderAddr())
	require.NotNil(t, node.Raft())
	require.NotNil(t, node.FSM())
	require.NotNil(t, node.Transport())
	require.NotNil(t, node.NamespaceStore())

	// Test Barrier on leader
	err = node.Barrier(ctx)
	require.NoError(t, err)

	// Propose a mutation
	cmd, err := NewCommand("tenant1", CmdCreateHost, time.Now().UTC(), storage.Host{ID: "host-single"})
	require.NoError(t, err)
	resp, err := node.Propose(ctx, cmd)
	require.NoError(t, err)
	require.NoError(t, resp.Error)

	st, err := node.NamespaceStore().StoreFor(ctx, "tenant1")
	require.NoError(t, err)
	host, err := st.GetHost(ctx, "host-single")
	require.NoError(t, err)
	require.Equal(t, "host-single", host.ID)

	// Propose with context.Background() (ctx.Done() == nil optimization path)
	cmd2, err := NewCommand("tenant1", CmdCreateHost, time.Now().UTC(), storage.Host{ID: "host-bg"})
	require.NoError(t, err)
	resp2, err := node.Propose(context.Background(), cmd2)
	require.NoError(t, err)
	require.NoError(t, resp2.Error)

	host2, err := st.GetHost(ctx, "host-bg")
	require.NoError(t, err)
	require.Equal(t, "host-bg", host2.ID)
}

func TestRaftNodeValidationAndCloseIdempotent(t *testing.T) {
	ctx := context.Background()

	// Empty dataDir error
	_, err := NewRaftNode(ctx, config.Config{RaftBind: "127.0.0.1:0"}, nil, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "dataDir is required")

	// Empty bind address error
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)
	_, err = NewRaftNode(ctx, config.Config{}, nsStore, dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "raft bind address must not be empty")

	// Nil receiver safety
	var nilNode *RaftNode
	require.False(t, nilNode.IsLeader())
	require.Empty(t, nilNode.LeaderAddr())
	require.Nil(t, nilNode.Raft())
	require.Nil(t, nilNode.FSM())
	require.Nil(t, nilNode.Transport())
	require.Nil(t, nilNode.NamespaceStore())
	require.NoError(t, nilNode.Close())

	_, err = nilNode.Propose(ctx, RaftCommand{})
	require.Error(t, err)
	err = nilNode.Barrier(ctx)
	require.Error(t, err)

	// Idempotent close
	validNode, err := NewRaftNode(ctx, config.Config{RaftBind: "127.0.0.1:0", RaftBootstrapExpect: 1}, nsStore, t.TempDir())
	require.NoError(t, err)
	require.NoError(t, validNode.Close())
	require.NoError(t, validNode.Close())
}

func TestNewRaftNode_HopSecretFailureDoesNotLeakRaft(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	origRandRead := randRead
	defer func() { randRead = origRandRead }()

	randRead = func(p []byte) (int, error) {
		return 0, errors.New("entropy source failed")
	}

	node, err := NewRaftNode(ctx, config.Config{RaftBind: "127.0.0.1:0", RaftBootstrapExpect: 1}, nsStore, t.TempDir())
	require.Error(t, err)
	require.Nil(t, node)
	require.Contains(t, err.Error(), "generate hop secret")

	// Inspect running goroutine stacks
	buf := make([]byte, 64*1024)
	n := runtime.Stack(buf, true)
	stackTrace := string(buf[:n])

	assert.NotContains(t, stackTrace, "github.com/hashicorp/raft.(*Raft).run",
		"Raft background goroutines must not be running if hop secret generation failed")
}

func TestTransportValidationAndMTLS(t *testing.T) {
	// 1. Missing bind address
	_, err := NewTransport(config.Config{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "raft bind address must not be empty")

	// 2. Incomplete mTLS configuration
	_, err = NewTransport(config.Config{
		RaftBind:   "127.0.0.1:0",
		RaftCAFile: "ca.pem",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "raft TLS requires all of --raft-ca-file, --raft-cert-file, and --raft-key-file to be set")

	// 3. Valid mTLS configuration
	tmpDir := t.TempDir()
	caFile, certFile, keyFile := generateTestCertificates(t, tmpDir)

	cfg := config.Config{
		RaftBind:     "127.0.0.1:0",
		RaftCAFile:   caFile,
		RaftCertFile: certFile,
		RaftKeyFile:  keyFile,
	}

	transport, err := NewTransport(cfg)
	require.NoError(t, err)
	require.NotNil(t, transport)
	defer func() { _ = transport.Close() }()
}

func TestTransport_RaftTLSServerName(t *testing.T) {
	tmpDir := t.TempDir()
	caFile, certFile, keyFile := generateTestCertificates(t, tmpDir)

	cfg := config.Config{
		RaftBind:          "127.0.0.1:0",
		RaftCAFile:        caFile,
		RaftCertFile:      certFile,
		RaftKeyFile:       keyFile,
		RaftTLSServerName: "raft.peer.node",
	}

	stream, err := newStreamLayer(cfg)
	require.NoError(t, err)
	require.NotNil(t, stream)
	defer func() { _ = stream.Close() }()

	require.NotNil(t, stream.clientTLS)
	assert.Equal(t, "raft.peer.node", stream.clientTLS.ServerName)

	transport, err := NewTransport(cfg)
	require.NoError(t, err)
	require.NotNil(t, transport)
	defer func() { _ = transport.Close() }()
}

func generateTestCertificates(t *testing.T, dir string) (caFile, certFile, keyFile string) {
	t.Helper()

	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	require.NoError(t, err)

	caFile = filepath.Join(dir, "ca.pem")
	caOut, err := os.Create(caFile)
	require.NoError(t, err)
	defer func() { _ = caOut.Close() }()
	require.NoError(t, pem.Encode(caOut, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes}))

	certPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, caTemplate, &certPriv.PublicKey, caPriv)
	require.NoError(t, err)

	certFile = filepath.Join(dir, "cert.pem")
	certOut, err := os.Create(certFile)
	require.NoError(t, err)
	defer func() { _ = certOut.Close() }()
	require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}))

	keyFile = filepath.Join(dir, "key.pem")
	keyOut, err := os.Create(keyFile)
	require.NoError(t, err)
	defer func() { _ = keyOut.Close() }()
	require.NoError(t, pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certPriv)}))

	return caFile, certFile, keyFile
}

func resolvePeers(peers []string, cfg config.Config) []string {
	defPort := defaultRaftPort(cfg)
	preferV6 := isIPv6Listener(cfg)
	return resolveParsedPeers(parsePeers(peers, defPort, preferV6))
}

func TestResolvePeersPortDefaultingAndIPFiltering(t *testing.T) {
	// 1. Bare IP without port defaults port from RaftBind
	cfgV4 := config.Config{
		RaftBind: "0.0.0.0:18080",
	}
	resolved := resolvePeers([]string{"127.0.0.1"}, cfgV4)
	require.Equal(t, []string{"127.0.0.1:18080"}, resolved)

	// 2. Hostname without port defaults port from RaftAdvertise
	cfgAdv := config.Config{
		RaftAdvertise: "192.168.1.10:19000",
	}
	resolvedAdv := resolvePeers([]string{"127.0.0.1"}, cfgAdv)
	require.Equal(t, []string{"127.0.0.1:19000"}, resolvedAdv)

	// 3. Localhost on IPv4 listener resolves to IPv4 only (no duplicate [::1])
	resolvedLocalhost := resolvePeers([]string{"localhost"}, cfgV4)
	require.Contains(t, resolvedLocalhost, "127.0.0.1:18080")
	for _, addr := range resolvedLocalhost {
		require.NotContains(t, addr, "::1", "IPv6 should be filtered out when listener is IPv4")
	}

	// 4. Localhost on IPv6 listener prefers IPv6
	cfgV6 := config.Config{
		RaftBind: "[::1]:18080",
	}
	resolvedV6 := resolvePeers([]string{"localhost"}, cfgV6)
	hasV6 := false
	for _, addr := range resolvedV6 {
		if strings.Contains(addr, "::1") || strings.Contains(addr, "[::1]") {
			hasV6 = true
		}
	}
	require.True(t, hasV6, "IPv6 should be preferred when listener is IPv6")

	// 5. Explicit port preserved
	resolvedExplicit := resolvePeers([]string{"127.0.0.1:20000"}, cfgV4)
	require.Equal(t, []string{"127.0.0.1:20000"}, resolvedExplicit)
}

func TestConsistentBootstrapConfiguration(t *testing.T) {
	peers := []string{"127.0.0.1:18081", "127.0.0.1:18082", "127.0.0.1:18083"}

	cfg1 := config.Config{
		RaftBind:            "127.0.0.1:18081",
		RaftAdvertise:       "127.0.0.1:18081",
		RaftBootstrapExpect: 3,
		RaftPeers:           peers,
	}
	cfg2 := config.Config{
		RaftBind:            "127.0.0.1:18082",
		RaftAdvertise:       "127.0.0.1:18082",
		RaftBootstrapExpect: 3,
		RaftPeers:           peers,
	}
	cfg3 := config.Config{
		RaftBind:            "127.0.0.1:18083",
		RaftAdvertise:       "127.0.0.1:18083",
		RaftBootstrapExpect: 3,
		RaftPeers:           peers,
	}

	s1, err := buildBootstrapServers(cfg1, "127.0.0.1:18081", "127.0.0.1:18081", nil)
	require.NoError(t, err)
	s2, err := buildBootstrapServers(cfg2, "127.0.0.1:18082", "127.0.0.1:18082", nil)
	require.NoError(t, err)
	s3, err := buildBootstrapServers(cfg3, "127.0.0.1:18083", "127.0.0.1:18083", nil)
	require.NoError(t, err)

	require.Equal(t, s1, s2, "Node 1 and Node 2 must generate identical bootstrap server configurations")
	require.Equal(t, s2, s3, "Node 2 and Node 3 must generate identical bootstrap server configurations")

	for _, s := range s1 {
		require.Equal(t, string(s.Address), string(s.ID), "Static peer addresses should use address as ServerID")
	}

	// Test ID mapping consistency
	mappedPeers := []string{"node-a=127.0.0.1:18081", "node-b=127.0.0.1:18082"}
	cfgMap1 := config.Config{
		RaftBind:            "127.0.0.1:18081",
		RaftBootstrapExpect: 2,
		RaftPeers:           mappedPeers,
	}
	cfgMap2 := config.Config{
		RaftBind:            "127.0.0.1:18082",
		RaftBootstrapExpect: 2,
		RaftPeers:           mappedPeers,
	}
	sm1, err := buildBootstrapServers(cfgMap1, "node-a", "127.0.0.1:18081", nil)
	require.NoError(t, err)
	sm2, err := buildBootstrapServers(cfgMap2, "node-b", "127.0.0.1:18082", nil)
	require.NoError(t, err)
	require.Equal(t, sm1, sm2, "ID mapped peer configurations must match across all nodes")
}

func TestFSMCancelsOnNodeContextCancellation(t *testing.T) {
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(context.Background(), dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(context.Background(), cfg, nsStore, dir)
	require.NoError(t, err)

	// Wait for leader
	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// Close the node, which cancels the internal node lifecycle context
	require.NoError(t, node.Close())

	// FSM Apply should fail because node lifecycle context is cancelled on close
	cmd, err := NewCommand("test-ns", CmdCreateHost, time.Now().UTC(), storage.Host{ID: "cancelled-host"})
	require.NoError(t, err)
	cmdBytes, err := cmd.Encode()
	require.NoError(t, err)

	res := node.FSM().Apply(&hashiraft.Log{
		Index: 1,
		Term:  1,
		Data:  cmdBytes,
	})
	resp, ok := res.(ApplyResponse)
	require.True(t, ok)
	require.Error(t, resp.Error, "FSM Apply should fail when node context is cancelled on close")
	assert.Contains(t, resp.Error.Error(), "context canceled")
}

func TestNodeRestartPersistedConfiguration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Assert buildBootstrapServers respects cfg.RaftNodeID
	testCfg := config.Config{
		RaftBind:            "127.0.0.1:18081",
		RaftAdvertise:       "127.0.0.1:18081",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 1,
		RaftPeers:           []string{"127.0.0.1:18081"},
	}
	bootstrapServers, err := buildBootstrapServers(testCfg, "node-1", "127.0.0.1:18081", nil)
	require.NoError(t, err)
	require.Len(t, bootstrapServers, 1)
	require.Equal(t, hashiraft.ServerID("node-1"), bootstrapServers[0].ID, "bootstrap server for local node must use cfg.RaftNodeID")

	// 2. Assert clean node restart with persisted configuration in BoltDB
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	port := getFreeClusterPorts(t, 1)[0]
	cfg := config.Config{
		RaftBind:            port,
		RaftAdvertise:       port,
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 1,
		RaftPeers:           []string{port},
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	require.Equal(t, "node-1", node.NodeID())

	future := node.Raft().GetConfiguration()
	require.NoError(t, future.Error())
	servers := future.Configuration().Servers
	require.Len(t, servers, 1)
	require.Equal(t, hashiraft.ServerID("node-1"), servers[0].ID)

	require.NoError(t, node.Close())

	// Restart node from same directory with hasState == true
	nsStoreRestart, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	nodeRestart, err := NewRaftNode(ctx, cfg, nsStoreRestart, dir)
	require.NoError(t, err)
	defer func() { _ = nodeRestart.Close() }()

	require.Equal(t, "node-1", nodeRestart.NodeID())

	futureRestart := nodeRestart.Raft().GetConfiguration()
	require.NoError(t, futureRestart.Error())
	serversRestart := futureRestart.Configuration().Servers

	require.Eventually(t, func() bool {
		return nodeRestart.IsLeader()
	}, 8*time.Second, 100*time.Millisecond)

	require.Len(t, serversRestart, 1)
	require.Equal(t, hashiraft.ServerID("node-1"), serversRestart[0].ID)
}

func TestMultiNodeBootstrapServersAssignsLocalNodeID(t *testing.T) {
	testCfg := config.Config{
		RaftBind:            "127.0.0.1:18081",
		RaftAdvertise:       "127.0.0.1:18081",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"127.0.0.1:18081", "127.0.0.1:18082", "127.0.0.1:18083"},
	}
	bootstrapServers, err := buildBootstrapServers(testCfg, "node-1", "127.0.0.1:18081", nil)
	require.NoError(t, err)
	require.Len(t, bootstrapServers, 3)

	var localFound bool
	for _, s := range bootstrapServers {
		if s.Address == "127.0.0.1:18081" {
			require.Equal(t, hashiraft.ServerID("node-1"), s.ID, "multi-node bootstrap server for local node must use cfg.RaftNodeID")
			localFound = true
		}
	}
	require.True(t, localFound, "local node address should be present in bootstrap servers")
}

func TestLeaderHTTPAddrCachedResolution(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-lead",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// Register HTTP address by node ID rather than Raft address
	node.RegisterHTTPAddr("node-lead", "http://127.0.0.1:8080")

	// LeaderHTTPAddr should resolve via the in-memory cache mapping leaderAddr -> "node-lead"
	httpAddr := node.LeaderHTTPAddr()
	require.Equal(t, "http://127.0.0.1:8080", httpAddr)

	// Check that serverIDByAddr is populated
	node.mu.RLock()
	cachedID, ok := node.serverIDByAddr[node.LeaderAddr()]
	node.mu.RUnlock()
	require.True(t, ok)
	require.Equal(t, "node-lead", cachedID)

	// Test AddVoter updates cache
	err = node.AddVoter("peer-2", "127.0.0.1:19092", 0, time.Second)
	require.NoError(t, err)
	node.mu.RLock()
	require.Equal(t, "peer-2", node.serverIDByAddr["127.0.0.1:19092"])
	require.Equal(t, "127.0.0.1:19092", node.addrByServerID["peer-2"])
	node.mu.RUnlock()

	// Test RemoveServer removes voter; cache cleaned via replicated FSM command
	err = node.RemoveServer("peer-2", 0, time.Second)
	require.NoError(t, err)
	cmd, err := NewCommand("", CmdDeregisterNodeHTTPAddr, time.Now().UTC(), DeregisterNodeHTTPAddrPayload{
		ServerID: "peer-2",
		Address:  "127.0.0.1:19092",
	})
	require.NoError(t, err)
	applyResp, err := node.Propose(ctx, cmd)
	require.NoError(t, err)
	require.NoError(t, applyResp.Error)
	node.mu.RLock()
	_, foundAddr := node.serverIDByAddr["127.0.0.1:19092"]
	_, foundID := node.addrByServerID["peer-2"]
	node.mu.RUnlock()
	require.False(t, foundAddr)
	require.False(t, foundID)
}

func TestAddVoter_PopulatesResolvedIPAddresses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-lead",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// AddVoter with hostname resolves and maps all resolved IPs
	err = node.AddVoter("voter-node", "localhost:19095", 0, time.Second)
	require.NoError(t, err)

	node.mu.RLock()
	assert.Equal(t, "voter-node", node.serverIDByAddr["localhost:19095"])
	assert.Equal(t, "voter-node", node.serverIDByAddr["127.0.0.1:19095"])
	assert.Equal(t, "localhost:19095", node.addrByServerID["voter-node"])
	node.mu.RUnlock()

	var nilNode *RaftNode
	assert.Error(t, nilNode.AddVoter("nil-id", "localhost:19097", 0, time.Second))
}

func TestAddNonvoter_PopulatesResolvedIPAddresses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-lead",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// AddNonvoter with hostname resolves and maps all resolved IPs
	err = node.AddNonvoter("nonvoter-node", "localhost:19096", 0, time.Second)
	require.NoError(t, err)

	node.mu.RLock()
	assert.Equal(t, "nonvoter-node", node.serverIDByAddr["localhost:19096"])
	assert.Equal(t, "nonvoter-node", node.serverIDByAddr["127.0.0.1:19096"])
	assert.Equal(t, "localhost:19096", node.addrByServerID["nonvoter-node"])
	node.mu.RUnlock()

	var nilNode *RaftNode
	assert.Error(t, nilNode.AddNonvoter("nil-id", "localhost:19098", 0, time.Second))
}

func TestConcurrentBarrierCoalescing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// Execute 30 concurrent barriers
	const numCallers = 30
	var wg sync.WaitGroup
	errs := make([]error, numCallers)

	for i := 0; i < numCallers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = node.Barrier(ctx)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "caller %d barrier failed", i)
	}

	// Test early context cancellation returns ctx.Err() without breaking barrier
	cancelCtx, cancelFn := context.WithCancel(context.Background())
	cancelFn() // immediately cancelled
	err = node.Barrier(cancelCtx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestLeaderHTTPAddrRefreshOptimizations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-lead",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// 1. Verify that when httpPort is set and leaderAddr is known in serverIDByAddr,
	// refresh is skipped even after 5s cooldown
	node.SetHTTPPort("8080")
	node.mu.Lock()
	oldRefresh := time.Now().Add(-10 * time.Second)
	node.lastConfigRefresh = oldRefresh
	node.mu.Unlock()

	httpAddr := node.LeaderHTTPAddr()
	require.Contains(t, httpAddr, ":8080")

	node.mu.RLock()
	currentRefresh := node.lastConfigRefresh
	node.mu.RUnlock()
	require.Equal(t, oldRefresh, currentRefresh, "configuration refresh should be skipped when httpPort is set and leader is already mapped in serverIDByAddr")

	// 2. If leaderAddr is NOT mapped in serverIDByAddr and httpAddrs is unpopulated,
	// refresh is triggered. Even if GetConfiguration() fails (e.g. invalid state), lastConfigRefresh must update.
	node.mu.Lock()
	delete(node.serverIDByAddr, node.LeaderAddr())
	delete(node.httpAddrs, node.LeaderAddr())
	delete(node.httpAddrs, node.nodeID)
	node.lastConfigRefresh = oldRefresh
	node.mu.Unlock()

	_ = node.LeaderHTTPAddr()
	node.mu.RLock()
	refreshedTime := node.lastConfigRefresh
	node.mu.RUnlock()
	require.True(t, refreshedTime.After(oldRefresh), "lastConfigRefresh should be updated after refresh attempt")
}

func TestBarrierConcurrentShortDeadlineDoesNotFailCoalesced(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(2)

	var err1, err2 error

	// Caller 1 has an expired deadline (-1ms) and cancels early
	expiredCtx, expiredCancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Millisecond))
	defer expiredCancel()

	healthyCtx, healthyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer healthyCancel()

	go func() {
		defer wg.Done()
		err1 = node.Barrier(expiredCtx)
	}()

	go func() {
		defer wg.Done()
		err2 = node.Barrier(healthyCtx)
	}()

	wg.Wait()

	require.ErrorIs(t, err1, context.DeadlineExceeded, "caller with 1ms expired deadline must cancel early with DeadlineExceeded")
	require.NoError(t, err2, "healthy caller must succeed even if coalesced with short deadline caller")
}

func TestRemoveServer_CleansUpHTTPAddrs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	peerAddr := "127.0.0.1:54321"
	peerID := "node-2"
	peerHTTP := "http://127.0.0.1:8082"

	// Register peer and its HTTP address
	require.NoError(t, node.AddNonvoter(peerID, peerAddr, 0, 5*time.Second))
	node.RegisterHTTPAddr(peerID, peerHTTP)
	node.RegisterHTTPAddr(peerAddr, peerHTTP)

	// Verify registered
	assert.Equal(t, peerHTTP, node.HTTPAddrFor(peerID))
	assert.Equal(t, peerHTTP, node.HTTPAddrFor(peerAddr))

	// Remove peer from Raft cluster configuration: prunes address maps and HTTP addrs locally
	require.NoError(t, node.RemoveServer(peerID, 0, 5*time.Second))
	assert.Empty(t, node.HTTPAddrFor(peerID))

	// Replicated HTTP address cleanup is executed via CmdDeregisterNodeHTTPAddr through FSM
	cmd, err := NewCommand("", CmdDeregisterNodeHTTPAddr, time.Now().UTC(), DeregisterNodeHTTPAddrPayload{
		ServerID: peerID,
		Address:  peerAddr,
	})
	require.NoError(t, err)
	applyResp, err := node.Propose(ctx, cmd)
	require.NoError(t, err)
	require.NoError(t, applyResp.Error)

	// Verify both ID and Addr mappings are cleaned up from httpAddrs and mapping tables
	assert.Empty(t, node.HTTPAddrFor(peerID))
	assert.Empty(t, node.HTTPAddrFor(peerAddr))
	node.mu.RLock()
	_, idInAddrByServerID := node.addrByServerID[peerID]
	_, addrInServerIDByAddr := node.serverIDByAddr[peerAddr]
	node.mu.RUnlock()
	assert.False(t, idInAddrByServerID)
	assert.False(t, addrInServerIDByAddr)
}

func TestRemoveServer_PrunesAddressMaps(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	peerAddr := "127.0.0.1:54321"
	peerID := "node-2"
	aliasAddr1 := "10.0.0.2:54321"
	aliasAddr2 := "192.168.1.10:54321"
	peerHTTP := "http://127.0.0.1:8082"

	// Register peer
	require.NoError(t, node.AddNonvoter(peerID, peerAddr, 0, 5*time.Second))

	// Register aliases and HTTP addresses
	node.mu.Lock()
	node.serverIDByAddr[aliasAddr1] = peerID
	node.serverIDByAddr[aliasAddr2] = peerID
	node.mu.Unlock()

	node.RegisterHTTPAddr(peerID, peerHTTP)
	node.RegisterHTTPAddr(peerAddr, peerHTTP)
	node.RegisterHTTPAddr(aliasAddr1, peerHTTP)

	// Verify mappings exist in addrByServerID, serverIDByAddr, and httpAddrs
	node.mu.RLock()
	assert.Equal(t, peerAddr, node.addrByServerID[peerID])
	assert.Equal(t, peerID, node.serverIDByAddr[peerAddr])
	assert.Equal(t, peerID, node.serverIDByAddr[aliasAddr1])
	assert.Equal(t, peerID, node.serverIDByAddr[aliasAddr2])
	assert.Equal(t, peerHTTP, node.httpAddrs[peerID])
	assert.Equal(t, peerHTTP, node.httpAddrs[peerAddr])
	assert.Equal(t, peerHTTP, node.httpAddrs[aliasAddr1])
	node.mu.RUnlock()
	assert.Equal(t, peerHTTP, node.HTTPAddrFor(peerID))
	assert.Equal(t, peerHTTP, node.HTTPAddrFor(peerAddr))
	assert.Equal(t, peerHTTP, node.HTTPAddrFor(aliasAddr1))

	// RemoveServer should immediately purge addrByServerID, serverIDByAddr (including IP aliases), and httpAddrs
	require.NoError(t, node.RemoveServer(peerID, 0, 5*time.Second))

	node.mu.RLock()
	_, idExists := node.addrByServerID[peerID]
	_, addrExists := node.serverIDByAddr[peerAddr]
	_, alias1Exists := node.serverIDByAddr[aliasAddr1]
	_, alias2Exists := node.serverIDByAddr[aliasAddr2]
	_, httpIDExists := node.httpAddrs[peerID]
	_, httpAddrExists := node.httpAddrs[peerAddr]
	_, httpAliasExists := node.httpAddrs[aliasAddr1]
	node.mu.RUnlock()

	assert.False(t, idExists, "addrByServerID should not contain removed server ID")
	assert.False(t, addrExists, "serverIDByAddr should not contain removed server address")
	assert.False(t, alias1Exists, "serverIDByAddr should not contain IP alias 1")
	assert.False(t, alias2Exists, "serverIDByAddr should not contain IP alias 2")
	assert.False(t, httpIDExists, "httpAddrs should not contain removed server ID")
	assert.False(t, httpAddrExists, "httpAddrs should not contain removed server address")
	assert.False(t, httpAliasExists, "httpAddrs should not contain removed alias address")
	assert.Empty(t, node.AddrByServerID(peerID))
	assert.Empty(t, node.HTTPAddrFor(peerID))
	assert.Empty(t, node.HTTPAddrFor(peerAddr))
	assert.Empty(t, node.HTTPAddrFor(aliasAddr1))
}

func TestLeaderHTTPAddr_ConcurrentRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-lead",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	node.RegisterHTTPAddr("node-lead", "http://127.0.0.1:8080")

	// Invalidate cache to force refresh
	node.mu.Lock()
	node.lastConfigRefresh = time.Now().Add(-10 * time.Second)
	delete(node.serverIDByAddr, node.LeaderAddr())
	node.mu.Unlock()

	// Concurrently call LeaderHTTPAddr across 20 goroutines
	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	addrs := make([]string, goroutines)
	for i := 0; i < goroutines; i++ {
		idx := i
		go func() {
			defer wg.Done()
			addrs[idx] = node.LeaderHTTPAddr()
		}()
	}
	wg.Wait()

	for _, addr := range addrs {
		assert.NotEmpty(t, addr)
	}

	// Verify that lastConfigRefresh was updated recently and matches across callers
	node.mu.RLock()
	lastRefresh := node.lastConfigRefresh
	node.mu.RUnlock()
	assert.True(t, time.Since(lastRefresh) < 2*time.Second)
}

func TestLeaderHTTPAddr_SharedHostSelfProxyGuard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ports := getFreeClusterPorts(t, 3)
	nodes := make([]*RaftNode, 3)

	for i := 0; i < 3; i++ {
		dir := t.TempDir()
		nsStore, err := store.NewNamespaceStore(ctx, dir)
		require.NoError(t, err)

		cfg := config.Config{
			RaftBind:            ports[i],
			RaftAdvertise:       ports[i],
			RaftNodeID:          ports[i],
			RaftBootstrapExpect: 3,
			RaftPeers:           ports,
		}

		node, err := NewRaftNode(ctx, cfg, nsStore, dir)
		require.NoError(t, err)
		nodes[i] = node
		defer func() { _ = node.Close() }()
	}

	require.Eventually(t, func() bool {
		leaders := 0
		for _, node := range nodes {
			if node.IsLeader() {
				leaders++
			}
		}
		return leaders == 1
	}, 10*time.Second, 100*time.Millisecond)

	var follower *RaftNode
	for _, node := range nodes {
		if !node.IsLeader() {
			follower = node
			break
		}
	}
	require.NotNil(t, follower)
	follower.SetHTTPPort("18084")

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

	// Leader is on 127.0.0.1 without registered HTTP address.
	// Follower's own HTTP port is 18084. Deriving leader's HTTP endpoint by combining
	// leader's host with follower's httpPort would yield follower's own HTTP endpoint ("127.0.0.1:18084").
	// Guard must detect this and return "" to prevent self-proxying loops.
	addr := follower.LeaderHTTPAddr()
	require.Equal(t, "", addr, "expected empty string to prevent self-proxying loop on shared host topology")

	hook.mu.Lock()
	defer hook.mu.Unlock()
	var found bool
	for _, entry := range hook.entries {
		if strings.Contains(entry.Message, "cannot synthesize HTTP address for co-located leader on shared IP address or loopback interface") {
			found = true
			assert.NotEmpty(t, entry.Data["leader_raft_addr"])
			assert.NotEmpty(t, entry.Data["local_raft_addr"])
			break
		}
	}
	assert.True(t, found, "expected warning log about co-located leader on shared IP address or loopback interface")
}

type warnLogCaptureHook struct {
	mu      sync.Mutex
	entries []*logrus.Entry
}

func (h *warnLogCaptureHook) Levels() []logrus.Level {
	return []logrus.Level{logrus.WarnLevel}
}

func (h *warnLogCaptureHook) Fire(entry *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, entry)
	return nil
}

func TestLeaderHTTPAddr_EmptyWhenNoHTTPPortAndNoMapping(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-test",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// With n.httpPort == "" and no explicit RegisterHTTPAddr mapping,
	// LeaderHTTPAddr must return "" rather than raw Raft TCP peer address.
	addr := node.LeaderHTTPAddr()
	assert.Equal(t, "", addr, "expected empty string when HTTP port and mapping are not configured")
}

func TestLeaderHTTPAddr_DoesNotReturnPortZero(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		BindAddr:            "127.0.0.1:0",
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-zero",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// Verify HTTPPort was normalized to "" instead of "0"
	assert.Equal(t, "", node.HTTPPort(), "expected HTTPPort to be normalized to empty string when configured as 0")

	// LeaderHTTPAddr must return "" rather than "127.0.0.1:0"
	addr := node.LeaderHTTPAddr()
	assert.Equal(t, "", addr, "expected empty string, not port 0")

	// Even if SetHTTPPort("0") is explicitly called, LeaderHTTPAddr should ignore port 0
	node.SetHTTPPort("0")
	assert.Equal(t, "", node.LeaderHTTPAddr(), "LeaderHTTPAddr should return empty string when httpPort is 0")
}



func TestBarrierRoundBatchingLinearizability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	port := getFreeClusterPorts(t, 1)[0]
	cfg := config.Config{
		RaftBind:            port,
		RaftAdvertise:       port,
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// 1. Verify context cancellation returns ctx.Err() without waiting or blocking
	cancelledCtx, cancelFunc := context.WithCancel(ctx)
	cancelFunc()
	err = node.Barrier(cancelledCtx)
	require.ErrorIs(t, err, context.Canceled)

	// 2. Verify single barrier execution
	err = node.Barrier(ctx)
	require.NoError(t, err)

	// After barrier completes, active and pending barriers should be cleared
	node.barrierMu.Lock()
	assert.Nil(t, node.activeBarrier)
	assert.Nil(t, node.pendingBarrier)
	node.barrierMu.Unlock()

	// 3. Verify batching of concurrent barrier calls
	const concurrentCount = 10
	var wg sync.WaitGroup
	errs := make([]error, concurrentCount)

	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			errs[idx] = node.Barrier(ctx)
		}()
	}
	wg.Wait()

	for _, err := range errs {
		assert.NoError(t, err)
	}

	// Active and pending barriers should be cleared after all complete
	node.barrierMu.Lock()
	assert.Nil(t, node.activeBarrier)
	assert.Nil(t, node.pendingBarrier)
	node.barrierMu.Unlock()

	// 4. Verify round isolation (newly arriving requests queue for next round)
	// We simulate this by holding barrierMu, creating an active barrier, then queuing a pending barrier
	node.barrierMu.Lock()
	fakeActive := &barrierRound{done: make(chan struct{})}
	node.activeBarrier = fakeActive
	node.barrierMu.Unlock()

	// A call to Barrier while fakeActive is running must join pendingBarrier, not fakeActive
	barrierCh := make(chan error, 1)
	go func() {
		barrierCh <- node.Barrier(ctx)
	}()

	// Wait briefly for the goroutine to enter Barrier and set pendingBarrier
	require.Eventually(t, func() bool {
		node.barrierMu.Lock()
		defer node.barrierMu.Unlock()
		return node.pendingBarrier != nil
	}, 2*time.Second, 10*time.Millisecond)

	node.barrierMu.Lock()
	pendingRound := node.pendingBarrier
	node.barrierMu.Unlock()
	require.NotNil(t, pendingRound)

	// When fakeActive finishes, pendingBarrier should be promoted to active and executed
	close(fakeActive.done)
	node.barrierMu.Lock()
	node.activeBarrier = node.pendingBarrier
	node.pendingBarrier = nil
	if node.activeBarrier != nil {
		go node.runBarrierRound(node.activeBarrier)
	}
	node.barrierMu.Unlock()

	select {
	case err := <-barrierCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for pending barrier round to complete")
	}

	node.barrierMu.Lock()
	assert.Nil(t, node.activeBarrier)
	assert.Nil(t, node.pendingBarrier)
	node.barrierMu.Unlock()
}

func TestIPv6PortDefaultingNoDoubleBrackets(t *testing.T) {
	cfg := config.Config{
		RaftBind:            "[::]:8081",
		RaftAdvertise:       "[::1]",
		RaftBootstrapExpect: 1,
		RaftPeers:           []string{"node-2=[fe80::2]"},
	}

	servers, err := buildBootstrapServers(cfg, "node-1", "", nil)
	require.NoError(t, err)
	require.Len(t, servers, 1)
	assert.Equal(t, hashiraft.ServerAddress("[::1]:8081"), servers[0].Address)
	assert.NotEqual(t, hashiraft.ServerAddress("[[::1]]:8081"), servers[0].Address)

	cfgMulti := config.Config{
		RaftBind:            "[::]:8081",
		RaftAdvertise:       "[::1]",
		RaftBootstrapExpect: 2,
		RaftPeers:           []string{"node-1=[::1]", "node-2=[fe80::2]"},
	}
	multiServers, err := buildBootstrapServers(cfgMulti, "node-1", "", nil)
	require.NoError(t, err)
	for _, s := range multiServers {
		assert.False(t, strings.Contains(string(s.Address), "[["), "address %q contains double brackets", s.Address)
	}
}

type infoLogCaptureHook struct {
	mu      sync.Mutex
	entries []*logrus.Entry
}

func (h *infoLogCaptureHook) Levels() []logrus.Level {
	return []logrus.Level{logrus.InfoLevel}
}

func (h *infoLogCaptureHook) Fire(entry *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, entry)
	return nil
}

func TestBootstrapExpectDeferralLogging(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hook := &infoLogCaptureHook{}
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

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"node-1=127.0.0.1:0"},
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	assert.False(t, node.IsLeader())

	hook.mu.Lock()
	defer hook.mu.Unlock()

	var foundEntry *logrus.Entry
	for _, entry := range hook.entries {
		if strings.Contains(entry.Message, "skipping cluster auto-bootstrap: discovered servers less than bootstrap-expect") {
			foundEntry = entry
			break
		}
	}
	require.NotNil(t, foundEntry, "expected bootstrap deferral log entry to be emitted")
	assert.Equal(t, 1, foundEntry.Data["discovered"])
	assert.Equal(t, 3, foundEntry.Data["expected"])
}

func TestBuildBootstrapServers_HostnameResolutionAndDeduplication(t *testing.T) {
	t.Run("HostnameAdvertise_HostnamePeers", func(t *testing.T) {
		cfg := config.Config{
			RaftBind:            "0.0.0.0:8081",
			RaftAdvertise:       "localhost:8081",
			RaftNodeID:          "node-1",
			RaftBootstrapExpect: 2,
			RaftPeers: []string{
				"node-1=localhost:8081",
				"node-2=localhost:8082",
			},
		}

		servers, err := buildBootstrapServers(cfg, "node-1", "", nil)
		require.NoError(t, err)
		require.Len(t, servers, 2, "expected exactly 2 servers without local node duplication")

		idMap := make(map[string]string)
		for _, s := range servers {
			idMap[string(s.ID)] = string(s.Address)
		}

		assert.Contains(t, idMap, "node-1", "node-1 ID must match configured ID, not raw IP")
		assert.Contains(t, idMap, "node-2", "node-2 ID must match configured ID, not raw IP")
		assert.NotContains(t, idMap, "127.0.0.1:8081")
		assert.NotContains(t, idMap, "127.0.0.1:8082")
	})

	t.Run("HostnameAdvertise_IPPeers", func(t *testing.T) {
		cfg := config.Config{
			RaftBind:            "0.0.0.0:8081",
			RaftAdvertise:       "localhost:8081",
			RaftBootstrapExpect: 2,
			RaftPeers: []string{
				"node-1=127.0.0.1:8081",
				"node-2=127.0.0.1:8082",
			},
		}

		servers, err := buildBootstrapServers(cfg, "node-1", "", nil)
		require.NoError(t, err)
		require.Len(t, servers, 2, "expected exactly 2 servers without local node duplication")

		idMap := make(map[string]string)
		for _, s := range servers {
			idMap[string(s.ID)] = string(s.Address)
		}

		assert.Contains(t, idMap, "node-1")
		assert.Contains(t, idMap, "node-2")
	})

	t.Run("IPAdvertise_HostnamePeers", func(t *testing.T) {
		cfg := config.Config{
			RaftBind:            "0.0.0.0:8081",
			RaftAdvertise:       "127.0.0.1:8081",
			RaftBootstrapExpect: 2,
			RaftPeers: []string{
				"node-1=localhost:8081",
				"node-2=localhost:8082",
			},
		}

		servers, err := buildBootstrapServers(cfg, "node-1", "", nil)
		require.NoError(t, err)
		require.Len(t, servers, 2, "expected exactly 2 servers without local node duplication")

		idMap := make(map[string]string)
		for _, s := range servers {
			idMap[string(s.ID)] = string(s.Address)
		}

		assert.Contains(t, idMap, "node-1")
		assert.Contains(t, idMap, "node-2")
	})
}

func TestNewRaftNode_HostnameAdvertise_ResolvesLocalIDFromIPPeers(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	ports := getFreeClusterPorts(t, 2)
	_, portStr1, err := net.SplitHostPort(ports[0])
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "0.0.0.0:" + portStr1,
		RaftAdvertise:       "localhost:" + portStr1,
		RaftBootstrapExpect: 3, // Defer auto-bootstrap
		RaftPeers: []string{
			"node-1=127.0.0.1:" + portStr1,
			"node-2=" + ports[1],
		},
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	assert.Equal(t, "node-1", node.NodeID(), "node ID should resolve to node-1 from IP peer list even when advertise is localhost and bind is 0.0.0.0")
}

func TestDNSLookupMemoization(t *testing.T) {
	t.Parallel()

	var lookupCount int
	resolver := newDNSResolver(30*time.Second, func(host string) ([]net.IP, error) {
		lookupCount++
		return []net.IP{net.ParseIP("192.168.1.50")}, nil
	})

	// First call should invoke lookupIP
	ips1, err := resolver.lookup("custom-peer.local")
	require.NoError(t, err)
	require.Equal(t, []net.IP{net.ParseIP("192.168.1.50")}, ips1)
	require.Equal(t, 1, lookupCount)

	// Second call with same host should use cache and NOT increment lookupCount
	ips2, err := resolver.lookup("custom-peer.local")
	require.NoError(t, err)
	require.Equal(t, []net.IP{net.ParseIP("192.168.1.50")}, ips2)
	require.Equal(t, 1, lookupCount)

	// Third call with same host should also use cache
	ips3, err := resolver.lookup("custom-peer.local")
	require.NoError(t, err)
	require.Equal(t, []net.IP{net.ParseIP("192.168.1.50")}, ips3)
	require.Equal(t, 1, lookupCount)
}

func TestDNSLookupExpiration(t *testing.T) {
	t.Parallel()

	var lookupCount int
	ip1 := net.ParseIP("192.168.1.50")
	ip2 := net.ParseIP("192.168.1.60")

	currentIP := ip1
	resolver := newDNSResolver(10*time.Millisecond, func(host string) ([]net.IP, error) {
		lookupCount++
		return []net.IP{currentIP}, nil
	})

	// First call resolves IP1
	ips1, err := resolver.lookup("custom-peer.local")
	require.NoError(t, err)
	require.Equal(t, []net.IP{ip1}, ips1)
	require.Equal(t, 1, lookupCount)

	// Second call before TTL returns cached IP1 without calling lookup
	ipsCached, err := resolver.lookup("custom-peer.local")
	require.NoError(t, err)
	require.Equal(t, []net.IP{ip1}, ipsCached)
	require.Equal(t, 1, lookupCount)

	// Sleep past TTL
	time.Sleep(25 * time.Millisecond)
	currentIP = ip2

	// Third call after TTL expires must call lookup again and return IP2
	ips2, err := resolver.lookup("custom-peer.local")
	require.NoError(t, err)
	require.Equal(t, []net.IP{ip2}, ips2)
	require.Equal(t, 2, lookupCount)
}

func TestDNSLookupDeepCopy(t *testing.T) {
	t.Parallel()

	ip := net.ParseIP("192.168.1.50")
	resolver := newDNSResolver(30*time.Second, func(host string) ([]net.IP, error) {
		return []net.IP{ip}, nil
	})

	ips1, err := resolver.lookup("deep-copy.local")
	require.NoError(t, err)
	require.Len(t, ips1, 1)

	// Mutate the returned IP bytes
	ips1[0][len(ips1[0])-1] = 99

	// Retrieve again, cached entry should remain unaltered
	ips2, err := resolver.lookup("deep-copy.local")
	require.NoError(t, err)
	require.Len(t, ips2, 1)
	require.Equal(t, net.ParseIP("192.168.1.50"), ips2[0])
}

func TestDNSResolverCacheCapacityAndEviction(t *testing.T) {
	t.Parallel()

	ip := net.ParseIP("192.168.1.1")
	resolver := newDNSResolverWithCapacity(1*time.Hour, 3, func(host string) ([]net.IP, error) {
		return []net.IP{ip}, nil
	})

	// Fill to capacity (3 entries)
	for i := 1; i <= 3; i++ {
		_, err := resolver.lookup(fmt.Sprintf("host-%d.local", i))
		require.NoError(t, err)
	}

	resolver.mu.RLock()
	assert.Equal(t, 3, len(resolver.cache))
	resolver.mu.RUnlock()

	// Insert 4th entry without expired entries -> clears saturated cache and keeps only the new entry
	_, err := resolver.lookup("host-4.local")
	require.NoError(t, err)

	resolver.mu.RLock()
	assert.Equal(t, 1, len(resolver.cache), "cache should be cleared when saturated with no expired entries")
	_, hasHost4 := resolver.cache["host-4.local"]
	assert.True(t, hasHost4, "newly added host-4.local should be present in cache")
	resolver.mu.RUnlock()

	// Test eviction of expired entries first when cache is full
	resolverExp := newDNSResolverWithCapacity(10*time.Millisecond, 2, func(host string) ([]net.IP, error) {
		return []net.IP{ip}, nil
	})

	_, err = resolverExp.lookup("expiring.local")
	require.NoError(t, err)

	// Fill to capacity with a long-lived entry
	resolverExp.mu.Lock()
	resolverExp.ttl = 1 * time.Hour
	resolverExp.mu.Unlock()

	_, err = resolverExp.lookup("long-lived.local")
	require.NoError(t, err)

	resolverExp.mu.RLock()
	assert.Equal(t, 2, len(resolverExp.cache))
	resolverExp.mu.RUnlock()

	// Wait for expiring.local to expire
	time.Sleep(20 * time.Millisecond)

	// Now cache is at capacity (2), with 1 expired entry and 1 active entry.
	// Inserting a new entry must purge expiring.local, leaving long-lived.local untouched.
	_, err = resolverExp.lookup("fresh-1.local")
	require.NoError(t, err)

	resolverExp.mu.RLock()
	assert.Equal(t, 2, len(resolverExp.cache))
	_, hasExpired := resolverExp.cache["expiring.local"]
	assert.False(t, hasExpired, "expired entry must be swept when cache is full")
	_, hasLongLived := resolverExp.cache["long-lived.local"]
	assert.True(t, hasLongLived, "unexpired entry should not be evicted when expired entries exist")
	_, hasFresh1 := resolverExp.cache["fresh-1.local"]
	assert.True(t, hasFresh1, "new entry must be present in cache")
	resolverExp.mu.RUnlock()
}


func TestRunBarrierRoundPanicRecovery(t *testing.T) {
	node := &RaftNode{
		raft: nil,
	}
	round := &barrierRound{done: make(chan struct{})}
	pending := &barrierRound{done: make(chan struct{})}

	node.activeBarrier = round
	node.pendingBarrier = pending

	require.NotPanics(t, func() {
		node.runBarrierRound(round)
	})

	select {
	case <-round.done:
		require.Error(t, round.err)
		assert.Contains(t, round.err.Error(), "barrier panic:")
	case <-time.After(2 * time.Second):
		t.Fatal("round.done was not closed after panic")
	}

	select {
	case <-pending.done:
		require.Error(t, pending.err)
		assert.Contains(t, pending.err.Error(), "barrier panic:")
	case <-time.After(2 * time.Second):
		t.Fatal("pending.done was not closed after promotion")
	}

	node.barrierMu.Lock()
	assert.Nil(t, node.activeBarrier)
	assert.Nil(t, node.pendingBarrier)
	node.barrierMu.Unlock()
}

func TestFSMUnaffectedByStartupContextCancellation(t *testing.T) {
	startupCtx, startupCancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(context.Background(), dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(startupCtx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	// Cancel startup context immediately after startup
	startupCancel()

	// Wait for leader election
	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// Propose a command and verify that fsm.Apply succeeds without failing with context canceled
	proposeCtx, proposeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer proposeCancel()

	cmd, err := NewCommand("default", CmdCreateHost, time.Now().UTC(), storage.Host{ID: "host-fsm-decoupled"})
	require.NoError(t, err)

	resp, err := node.Propose(proposeCtx, cmd)
	require.NoError(t, err)
	require.NoError(t, resp.Error)

	st, err := node.NamespaceStore().StoreFor(proposeCtx, "default")
	require.NoError(t, err)
	h, err := st.GetHost(proposeCtx, "host-fsm-decoupled")
	require.NoError(t, err)
	assert.Equal(t, "host-fsm-decoupled", h.ID)
}

func TestDynamicRaftPortDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "",
		RaftBootstrapExpect: 1,
		BindAddr:            "127.0.0.1:8080",
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	localAddr := string(node.Transport().LocalAddr())
	require.NotEmpty(t, localAddr)
	assert.False(t, strings.HasSuffix(localAddr, ":0"), "transport local address should have dynamic non-zero port")

	host, port, err := net.SplitHostPort(localAddr)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", host)
	assert.NotEqual(t, "0", port)

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	leaderAddr := node.LeaderAddr()
	assert.Equal(t, localAddr, leaderAddr)

	leaderHTTP := node.LeaderHTTPAddr()
	assert.NotEmpty(t, leaderHTTP)
	assert.Equal(t, "http://127.0.0.1:8080", leaderHTTP)

	// Explicit registration should also take effect and resolve
	node.RegisterHTTPAddr(localAddr, "http://127.0.0.1:9090")
	assert.Equal(t, "http://127.0.0.1:9090", node.LeaderHTTPAddr())
}

func TestRaftLogWriterPrefixStripping(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := logrus.New()
	logger.SetOutput(buf)
	logger.SetLevel(logrus.DebugLevel)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})

	writer := NewRaftLogWriter(logrus.NewEntry(logger), logrus.InfoLevel)
	require.NotNil(t, writer)

	tests := []struct {
		name            string
		input           string
		expectedLevel   string
		expectedMessage string
		strippedPrefix  string
	}{
		{
			name:            "debug prefix stripped",
			input:           "[DEBUG] raft: heartbeat sent to peer",
			expectedLevel:   "level=debug",
			expectedMessage: "raft: heartbeat sent to peer",
			strippedPrefix:  "[DEBUG]",
		},
		{
			name:            "info prefix stripped",
			input:           "[INFO] raft: entering leader state",
			expectedLevel:   "level=info",
			expectedMessage: "raft: entering leader state",
			strippedPrefix:  "[INFO]",
		},
		{
			name:            "warn prefix stripped",
			input:           "[WARN] raft: election timeout reached",
			expectedLevel:   "level=warning",
			expectedMessage: "raft: election timeout reached",
			strippedPrefix:  "[WARN]",
		},
		{
			name:            "err prefix stripped",
			input:           "[ERR] raft: failed to contact peer",
			expectedLevel:   "level=error",
			expectedMessage: "raft: failed to contact peer",
			strippedPrefix:  "[ERR]",
		},
		{
			name:            "error prefix stripped",
			input:           "[ERROR] raft: quorum loss detected",
			expectedLevel:   "level=error",
			expectedMessage: "raft: quorum loss detected",
			strippedPrefix:  "[ERROR]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			n, err := writer.Write([]byte(tc.input + "\n"))
			require.NoError(t, err)
			assert.Equal(t, len(tc.input+"\n"), n)

			output := buf.String()
			assert.Contains(t, output, tc.expectedLevel)
			assert.Contains(t, output, "msg=\""+tc.expectedMessage+"\"")
			assert.NotContains(t, output, tc.strippedPrefix)
		})
	}
}

func TestParsePeerConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		raw          string
		defPort      string
		preferV6     bool
		expectedID   string
		expectedRaft string
		expectedHTTP string
		checkIPs     func(t *testing.T, ips []string)
	}{
		{
			name:         "empty string",
			raw:          "",
			defPort:      "18080",
			expectedID:   "",
			expectedRaft: "",
			expectedHTTP: "",
			checkIPs: func(t *testing.T, ips []string) {
				assert.Empty(t, ips)
			},
		},
		{
			name:         "whitespace string",
			raw:          "   \t\n",
			defPort:      "18080",
			expectedID:   "",
			expectedRaft: "",
			expectedHTTP: "",
			checkIPs: func(t *testing.T, ips []string) {
				assert.Empty(t, ips)
			},
		},
		{
			name:         "bare IP without port uses default port",
			raw:          "127.0.0.1",
			defPort:      "18080",
			expectedID:   "",
			expectedRaft: "127.0.0.1:18080",
			expectedHTTP: "",
			checkIPs: func(t *testing.T, ips []string) {
				assert.Contains(t, ips, "127.0.0.1:18080")
			},
		},
		{
			name:         "explicit port preserved",
			raw:          "127.0.0.1:19000",
			defPort:      "18080",
			expectedID:   "",
			expectedRaft: "127.0.0.1:19000",
			expectedHTTP: "",
			checkIPs: func(t *testing.T, ips []string) {
				assert.Contains(t, ips, "127.0.0.1:19000")
			},
		},
		{
			name:         "ID and raft address",
			raw:          "node-1=127.0.0.1:18081",
			defPort:      "18080",
			expectedID:   "node-1",
			expectedRaft: "127.0.0.1:18081",
			expectedHTTP: "",
			checkIPs: func(t *testing.T, ips []string) {
				assert.Contains(t, ips, "127.0.0.1:18081")
			},
		},
		{
			name:         "ID, raft address and http address",
			raw:          "node-1=127.0.0.1:18081@http://127.0.0.1:8080",
			defPort:      "18080",
			expectedID:   "node-1",
			expectedRaft: "127.0.0.1:18081",
			expectedHTTP: "http://127.0.0.1:8080",
			checkIPs: func(t *testing.T, ips []string) {
				assert.Contains(t, ips, "127.0.0.1:18081")
			},
		},
		{
			name:         "raft address and http address without ID",
			raw:          "127.0.0.1:18081@http://127.0.0.1:8080",
			defPort:      "18080",
			expectedID:   "",
			expectedRaft: "127.0.0.1:18081",
			expectedHTTP: "http://127.0.0.1:8080",
			checkIPs: func(t *testing.T, ips []string) {
				assert.Contains(t, ips, "127.0.0.1:18081")
			},
		},
		{
			name:         "whitespace trimming around delimiter tokens",
			raw:          "  node-2  =  127.0.0.1:18082  @  http://127.0.0.1:8082  ",
			defPort:      "18080",
			expectedID:   "node-2",
			expectedRaft: "127.0.0.1:18082",
			expectedHTTP: "http://127.0.0.1:8082",
			checkIPs: func(t *testing.T, ips []string) {
				assert.Contains(t, ips, "127.0.0.1:18082")
			},
		},
		{
			name:         "ID and bare host gets default port",
			raw:          "node-3=10.0.0.1",
			defPort:      "18080",
			expectedID:   "node-3",
			expectedRaft: "10.0.0.1:18080",
			expectedHTTP: "",
			checkIPs: func(t *testing.T, ips []string) {
				assert.Contains(t, ips, "10.0.0.1:18080")
			},
		},
		{
			name:         "bracketed IPv6 with port",
			raw:          "node-v6=[::1]:18081@http://[::1]:8080",
			defPort:      "18080",
			preferV6:     true,
			expectedID:   "node-v6",
			expectedRaft: "[::1]:18081",
			expectedHTTP: "http://[::1]:8080",
			checkIPs: func(t *testing.T, ips []string) {
				assert.NotEmpty(t, ips)
			},
		},
		{
			name:         "IPv6 without port with defPort",
			raw:          "::1",
			defPort:      "18080",
			preferV6:     true,
			expectedID:   "",
			expectedRaft: "[::1]:18080",
			expectedHTTP: "",
			checkIPs: func(t *testing.T, ips []string) {
				assert.NotEmpty(t, ips)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := parsePeerConfig(tc.raw, tc.defPort, tc.preferV6)
			assert.Equal(t, tc.expectedID, p.id)
			assert.Equal(t, tc.expectedRaft, p.raftAddr)
			assert.Equal(t, tc.expectedHTTP, p.httpAddr)
			if tc.checkIPs != nil {
				tc.checkIPs(t, p.resolvedIPs)
			}
		})
	}
}

type mockErrConfigFuture struct {
	err error
}

func (m *mockErrConfigFuture) Error() error {
	return m.err
}

func (m *mockErrConfigFuture) Configuration() hashiraft.Configuration {
	return hashiraft.Configuration{}
}

func (m *mockErrConfigFuture) Index() uint64 {
	return 0
}

func TestRaftNodeRestartWithSnapshotPreservesHTTPAddrs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-snap-1",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// Register dynamic HTTP address mapping
	dynamicID := "node-dynamic-worker"
	dynamicHTTP := "http://192.168.10.50:8080"
	node.RegisterHTTPAddr(dynamicID, dynamicHTTP)

	// Commit a command via Raft so there are logs for Raft to snapshot
	cmd, err := NewCommand(store.DefaultNamespace, CmdCreateHost, time.Now().UTC(), storage.Host{ID: "host-snap-test"})
	require.NoError(t, err)
	applyResp, err := node.Propose(ctx, cmd)
	require.NoError(t, err)
	require.NoError(t, applyResp.Error)

	// Trigger snapshot via Raft
	snapFuture := node.Raft().Snapshot()
	require.NoError(t, snapFuture.Error())

	// Close node cleanly
	require.NoError(t, node.Close())

	// Restart node from the same dataDir.
	// During NewRaftNode, hashiraft.NewRaft restores the snapshot,
	// which invokes fsm.Restore and populates node.HTTPAddrs via the pre-registered registrar.
	nsStoreRestart, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	nodeRestart, err := NewRaftNode(ctx, cfg, nsStoreRestart, dir)
	require.NoError(t, err)
	defer func() { _ = nodeRestart.Close() }()

	// Verify that dynamic HTTP mappings stored in cluster_http_addrs.json were restored
	restoredAddrs := nodeRestart.HTTPAddrs()
	require.Equal(t, dynamicHTTP, restoredAddrs[dynamicID], "restored node must preserve dynamic HTTP address mapping from snapshot")
}

func TestLeaderHTTPAddrThrottleConfigRefreshOnError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-err",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	leaderAddr := node.LeaderAddr()
	require.NotEmpty(t, leaderAddr)

	// Set up config override to simulate Raft configuration fetch failure (e.g. election in progress)
	var getCfgCalls int
	node.getConfigOverride = func() hashiraft.ConfigurationFuture {
		getCfgCalls++
		return &mockErrConfigFuture{err: errors.New("simulated raft config error")}
	}

	// Ensure leaderAddr is unmapped and set lastConfigRefresh in the past
	node.mu.Lock()
	delete(node.serverIDByAddr, leaderAddr)
	delete(node.httpAddrs, leaderAddr)
	delete(node.httpAddrs, "node-err")
	pastRefresh := time.Now().Add(-10 * time.Second)
	node.lastConfigRefresh = pastRefresh
	node.mu.Unlock()

	// 1. First call to LeaderHTTPAddr should attempt refresh, fail GetConfiguration(),
	// and update lastConfigRefresh so we don't spin.
	res1 := node.LeaderHTTPAddr()
	assert.Empty(t, res1)
	require.Equal(t, 1, getCfgCalls, "GetConfiguration should be invoked on initial refresh attempt")

	node.mu.RLock()
	refreshedTime := node.lastConfigRefresh
	node.mu.RUnlock()

	require.True(t, refreshedTime.After(pastRefresh), "lastConfigRefresh must be updated even when GetConfiguration fails")
	require.WithinDuration(t, time.Now(), refreshedTime, 2*time.Second)

	// 2. Subsequent call within 5 seconds must not re-attempt refresh.
	res2 := node.LeaderHTTPAddr()
	assert.Empty(t, res2)
	require.Equal(t, 1, getCfgCalls, "subsequent call within 5s cooldown must not re-invoke GetConfiguration")

	node.mu.RLock()
	afterSecondCall := node.lastConfigRefresh
	node.mu.RUnlock()

	require.Equal(t, refreshedTime, afterSecondCall, "lastConfigRefresh must remain unchanged during cooldown")
}

func TestTransport_NormalizeRaftAdvertisePort(t *testing.T) {
	cfg := config.Config{
		RaftBind:      "127.0.0.1:7000",
		RaftAdvertise: "10.0.0.1",
	}
	transport, err := NewTransport(cfg)
	require.NoError(t, err)
	require.NotNil(t, transport)
	defer func() { _ = transport.Close() }()

	assert.Equal(t, "10.0.0.1:7000", string(transport.LocalAddr()))

	// Dynamic port fallback test
	cfgDyn := config.Config{
		RaftBind:      "127.0.0.1:0",
		RaftAdvertise: "10.0.0.2",
	}
	transportDyn, err := NewTransport(cfgDyn)
	require.NoError(t, err)
	require.NotNil(t, transportDyn)
	defer func() { _ = transportDyn.Close() }()

	_, dynPort, err := net.SplitHostPort(string(transportDyn.LocalAddr()))
	require.NoError(t, err)
	assert.NotEmpty(t, dynPort)
	assert.True(t, strings.HasPrefix(string(transportDyn.LocalAddr()), "10.0.0.2:"))
}

func TestDeregisterHTTPAddr_PrunesNodeMappings(t *testing.T) {
	node := &RaftNode{
		httpAddrs:      make(map[string]string),
		addrByServerID: make(map[string]string),
		serverIDByAddr: make(map[string]string),
	}

	// Case 1: Deregister by node ID
	node.addrByServerID["node-1"] = "127.0.0.1:7001"
	node.serverIDByAddr["127.0.0.1:7001"] = "node-1"
	node.httpAddrs["node-1"] = "http://127.0.0.1:8081"
	node.httpAddrs["127.0.0.1:7001"] = "http://127.0.0.1:8081"

	node.DeregisterHTTPAddr("node-1")

	node.mu.RLock()
	_, okAddr := node.serverIDByAddr["127.0.0.1:7001"]
	_, okID := node.addrByServerID["node-1"]
	_, okHTTPID := node.httpAddrs["node-1"]
	_, okHTTPAddr := node.httpAddrs["127.0.0.1:7001"]
	node.mu.RUnlock()

	assert.False(t, okAddr, "serverIDByAddr entry should be pruned when deregistering by node ID")
	assert.False(t, okID, "addrByServerID entry should be pruned when deregistering by node ID")
	assert.False(t, okHTTPID, "httpAddrs node ID entry should be pruned")
	assert.False(t, okHTTPAddr, "httpAddrs raft addr entry should be pruned")

	// Case 2: Deregister by Raft address
	node.addrByServerID["node-2"] = "127.0.0.1:7002"
	node.serverIDByAddr["127.0.0.1:7002"] = "node-2"
	node.httpAddrs["node-2"] = "http://127.0.0.1:8082"
	node.httpAddrs["127.0.0.1:7002"] = "http://127.0.0.1:8082"

	node.DeregisterHTTPAddr("127.0.0.1:7002")

	node.mu.RLock()
	_, okAddr2 := node.serverIDByAddr["127.0.0.1:7002"]
	_, okID2 := node.addrByServerID["node-2"]
	_, okHTTPID2 := node.httpAddrs["node-2"]
	_, okHTTPAddr2 := node.httpAddrs["127.0.0.1:7002"]
	node.mu.RUnlock()

	assert.False(t, okAddr2, "serverIDByAddr entry should be pruned when deregistering by Raft address")
	assert.False(t, okID2, "addrByServerID entry should be pruned when deregistering by Raft address")
	assert.False(t, okHTTPID2, "httpAddrs node ID entry should be pruned")
	assert.False(t, okHTTPAddr2, "httpAddrs raft addr entry should be pruned")
}

type mockServersConfigFuture struct {
	servers []hashiraft.Server
}

func (m *mockServersConfigFuture) Error() error {
	return nil
}

func (m *mockServersConfigFuture) Configuration() hashiraft.Configuration {
	return hashiraft.Configuration{
		Servers: m.servers,
	}
}

func (m *mockServersConfigFuture) Index() uint64 {
	return 1
}

func TestLeaderHTTPAddr_PurgesDecommissionedServersOnConfigRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-lead",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	leaderAddr := node.LeaderAddr()
	require.NotEmpty(t, leaderAddr)

	// Pre-populate stale/decommissioned node mappings in cache
	node.mu.Lock()
	node.serverIDByAddr["127.0.0.1:9999"] = "decommissioned-node"
	node.addrByServerID["decommissioned-node"] = "127.0.0.1:9999"
	// Set lastConfigRefresh back in time to trigger refresh
	node.lastConfigRefresh = time.Now().Add(-10 * time.Second)
	// Clear direct HTTP address mappings so LeaderHTTPAddr executes the refresh branch
	delete(node.httpAddrs, leaderAddr)
	delete(node.httpAddrs, "node-lead")
	node.mu.Unlock()

	// Configure mock config override that only includes the active leader
	node.getConfigOverride = func() hashiraft.ConfigurationFuture {
		return &mockServersConfigFuture{
			servers: []hashiraft.Server{
				{
					ID:      hashiraft.ServerID("node-lead"),
					Address: hashiraft.ServerAddress(leaderAddr),
				},
			},
		}
	}

	// Trigger LeaderHTTPAddr, which performs GetConfiguration() refresh
	_ = node.LeaderHTTPAddr()

	// Verify that decommissioned server mappings were purged
	node.mu.RLock()
	_, foundStaleID := node.addrByServerID["decommissioned-node"]
	_, foundStaleAddr := node.serverIDByAddr["127.0.0.1:9999"]
	cachedLeadID, foundLeadAddr := node.serverIDByAddr[leaderAddr]
	cachedLeadAddr, foundLeadID := node.addrByServerID["node-lead"]
	node.mu.RUnlock()

	assert.False(t, foundStaleID, "decommissioned node ID should be purged from addrByServerID")
	assert.False(t, foundStaleAddr, "decommissioned address should be purged from serverIDByAddr")
	assert.True(t, foundLeadAddr, "active leader address should be in serverIDByAddr")
	assert.Equal(t, "node-lead", cachedLeadID)
	assert.True(t, foundLeadID, "active leader ID should be in addrByServerID")
	assert.Equal(t, leaderAddr, cachedLeadAddr)
}

func TestLeaderHTTPAddr_ConfigRefresh_PreservesIPAliases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-lead",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	leaderAddr := node.LeaderAddr()
	require.NotEmpty(t, leaderAddr)

	node.mu.Lock()
	// Pre-populate an IP alias mapped during startup/DNS resolution for an active peer
	node.serverIDByAddr["127.0.0.1:18092"] = "node-peer"
	node.addrByServerID["node-peer"] = "node-peer.local:18092"
	// Also populate a stale alias for a node that will not be in the refreshed config
	node.serverIDByAddr["127.0.0.1:19999"] = "stale-peer"
	node.addrByServerID["stale-peer"] = "stale-peer.local:19999"
	// Register HTTP address for node-peer and its resolved IP alias
	node.httpAddrs["node-peer"] = "http://127.0.0.1:8092"
	node.httpAddrs["127.0.0.1:18092"] = "http://127.0.0.1:8092"

	// Age lastConfigRefresh so refresh will execute
	node.lastConfigRefresh = time.Now().Add(-10 * time.Second)
	// Clear direct HTTP address for leaderAddr so LeaderHTTPAddr executes refresh branch
	delete(node.httpAddrs, leaderAddr)
	delete(node.httpAddrs, "node-lead")
	node.mu.Unlock()

	// Refreshed configuration contains node-lead and node-peer (as localhost:18092)
	node.getConfigOverride = func() hashiraft.ConfigurationFuture {
		return &mockServersConfigFuture{
			servers: []hashiraft.Server{
				{
					ID:      hashiraft.ServerID("node-lead"),
					Address: hashiraft.ServerAddress(leaderAddr),
				},
				{
					ID:      hashiraft.ServerID("node-peer"),
					Address: hashiraft.ServerAddress("localhost:18092"),
				},
			},
		}
	}

	// Trigger LeaderHTTPAddr refresh
	_ = node.LeaderHTTPAddr()

	node.mu.RLock()
	// 1. IP alias for active peer should remain intact
	peerSID, peerAliasFound := node.serverIDByAddr["127.0.0.1:18092"]
	// 2. IP alias for decommissioned/stale peer should be purged
	_, staleAliasFound := node.serverIDByAddr["127.0.0.1:19999"]
	// 3. Resolved localhost address should also map to node-peer
	localhostSID, localhostFound := node.serverIDByAddr["localhost:18092"]
	node.mu.RUnlock()

	assert.True(t, peerAliasFound, "IP alias for active server ID must be preserved after config refresh")
	assert.Equal(t, "node-peer", peerSID)
	assert.False(t, staleAliasFound, "IP alias for decommissioned server must be purged")
	assert.True(t, localhostFound, "address from config must be present in serverIDByAddr")
	assert.Equal(t, "node-peer", localhostSID)

	// Functional test: verify that looking up HTTP addr using the IP alias succeeds
	assert.Equal(t, "http://127.0.0.1:8092", node.HTTPAddrFor("127.0.0.1:18092"), "HTTPAddrFor IP alias must remain functional after config refresh")
}

func TestBuildBootstrapServers_OmittedNodeID_ConsistentServerIDs(t *testing.T) {
	peers := []string{"127.0.0.1:18081", "127.0.0.1:18082", "127.0.0.1:18083"}

	cfg1 := config.Config{
		RaftNodeID:          "", // omitted
		RaftBind:            "127.0.0.1:18081",
		RaftAdvertise:       "127.0.0.1:18081",
		RaftBootstrapExpect: 3,
		RaftPeers:           peers,
	}

	cfg2 := config.Config{
		RaftNodeID:          "", // omitted
		RaftBind:            "127.0.0.1:18082",
		RaftAdvertise:       "127.0.0.1:18082",
		RaftBootstrapExpect: 3,
		RaftPeers:           peers,
	}

	cfg3 := config.Config{
		RaftNodeID:          "", // omitted
		RaftBind:            "127.0.0.1:18083",
		RaftAdvertise:       "127.0.0.1:18083",
		RaftBootstrapExpect: 3,
		RaftPeers:           peers,
	}

	servers1, err1 := buildBootstrapServers(cfg1, "127.0.0.1:18081", "127.0.0.1:18081", nil)
	require.NoError(t, err1)

	servers2, err2 := buildBootstrapServers(cfg2, "127.0.0.1:18082", "127.0.0.1:18082", nil)
	require.NoError(t, err2)

	servers3, err3 := buildBootstrapServers(cfg3, "127.0.0.1:18083", "127.0.0.1:18083", nil)
	require.NoError(t, err3)

	require.Len(t, servers1, 3)
	require.Len(t, servers2, 3)
	require.Len(t, servers3, 3)

	assert.Equal(t, servers1, servers2, "bootstrap servers for node 1 and node 2 must be 100% identical")
	assert.Equal(t, servers1, servers3, "bootstrap servers for node 1 and node 3 must be 100% identical")

	for _, s := range servers1 {
		assert.Equal(t, string(s.Address), string(s.ID), "server ID must match server address when raft-node-id is omitted")
	}

	// Also verify when nodes advertise addresses that resolve to IPs (e.g. hostnames)
	hostPeers := []string{"localhost:18081", "localhost:18082", "localhost:18083"}
	cfgHost1 := config.Config{
		RaftNodeID:          "", // omitted
		RaftBind:            "127.0.0.1:18081",
		RaftAdvertise:       "localhost:18081",
		RaftBootstrapExpect: 3,
		RaftPeers:           hostPeers,
	}
	cfgHost2 := config.Config{
		RaftNodeID:          "", // omitted
		RaftBind:            "127.0.0.1:18082",
		RaftAdvertise:       "localhost:18082",
		RaftBootstrapExpect: 3,
		RaftPeers:           hostPeers,
	}

	sHost1, err := buildBootstrapServers(cfgHost1, "localhost:18081", "127.0.0.1:18081", nil)
	require.NoError(t, err)

	sHost2, err := buildBootstrapServers(cfgHost2, "localhost:18082", "127.0.0.1:18082", nil)
	require.NoError(t, err)

	assert.Equal(t, sHost1, sHost2, "hostname bootstrap configurations must be 100% identical across simulated nodes")
}

type blockingConfigFuture struct {
	servers  []hashiraft.Server
	calledCh chan struct{}
	blockCh  chan struct{}
}

func (b *blockingConfigFuture) Error() error {
	return nil
}

func (b *blockingConfigFuture) Configuration() hashiraft.Configuration {
	select {
	case b.calledCh <- struct{}{}:
	default:
	}
	<-b.blockCh
	return hashiraft.Configuration{
		Servers: b.servers,
	}
}

func (b *blockingConfigFuture) Index() uint64 {
	return 1
}

func TestLeaderHTTPAddr_ConcurrentReadAccessDuringConfigRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-lead",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	leaderAddr := node.LeaderAddr()
	require.NotEmpty(t, leaderAddr)

	node.RegisterHTTPAddr("node-lead", "http://127.0.0.1:8080")

	calledCh := make(chan struct{}, 1)
	blockCh := make(chan struct{})

	node.getConfigOverride = func() hashiraft.ConfigurationFuture {
		return &blockingConfigFuture{
			servers: []hashiraft.Server{
				{
					ID:      hashiraft.ServerID("node-lead"),
					Address: hashiraft.ServerAddress(leaderAddr),
				},
				{
					ID:      hashiraft.ServerID("node-peer"),
					Address: hashiraft.ServerAddress("localhost:18092"),
				},
			},
			calledCh: calledCh,
			blockCh:  blockCh,
		}
	}

	// Invalidate cache and clear direct HTTP addr so LeaderHTTPAddr executes the refresh block
	node.mu.Lock()
	node.lastConfigRefresh = time.Now().Add(-10 * time.Second)
	delete(node.httpAddrs, leaderAddr)
	delete(node.httpAddrs, "node-lead")
	node.mu.Unlock()

	// Run LeaderHTTPAddr in background goroutine to trigger refresh
	refreshDone := make(chan struct{})
	go func() {
		defer close(refreshDone)
		_ = node.LeaderHTTPAddr()
	}()

	// Wait until background refresh reaches Configuration() (which is executed outside mutex lock)
	select {
	case <-calledCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for config future to be called")
	}

	// Verify that concurrent read access to the node is NOT blocked by an exclusive mutex lock
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		// Concurrent reader can acquire read lock
		assert.True(t, node.mu.TryRLock(), "mutex TryRLock must succeed while config refresh is in progress")
		node.mu.RUnlock()

		// Methods that acquire RLock should complete immediately
		_ = node.AddrByServerID("node-lead")
		_ = node.HTTPAddrFor(leaderAddr)
		_ = node.IsLeader()
	}()

	select {
	case <-readDone:
		// Succeeded without blocking!
	case <-time.After(2 * time.Second):
		close(blockCh)
		t.Fatal("concurrent read blocked while config refresh / DNS resolution was in flight")
	}

	// Now unblock the config refresh
	close(blockCh)

	select {
	case <-refreshDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for LeaderHTTPAddr to finish")
	}

	// Verify refreshed state was applied
	node.mu.RLock()
	peerSID := node.serverIDByAddr["localhost:18092"]
	node.mu.RUnlock()
	assert.Equal(t, "node-peer", peerSID)
}

func TestHasDNSPeer(t *testing.T) {
	// False cases: empty, IP addresses, IPv6, localhost
	assert.False(t, hasDNSPeer(nil))
	assert.False(t, hasDNSPeer([]string{}))
	assert.False(t, hasDNSPeer([]string{""}))
	assert.False(t, hasDNSPeer([]string{"127.0.0.1:18081"}))
	assert.False(t, hasDNSPeer([]string{"10.0.0.1:18081", "192.168.1.1:18082"}))
	assert.False(t, hasDNSPeer([]string{"[::1]:18081"}))
	assert.False(t, hasDNSPeer([]string{"::1"}))
	assert.False(t, hasDNSPeer([]string{"localhost:18081"}))
	assert.False(t, hasDNSPeer([]string{"localhost"}))
	assert.False(t, hasDNSPeer([]string{"node-1=127.0.0.1:18081@http://127.0.0.1:8081"}))
	assert.False(t, hasDNSPeer([]string{"node-1=localhost:18081"}))

	// True cases: DNS hostnames
	assert.True(t, hasDNSPeer([]string{"headless.default.svc.cluster.local:18081"}))
	assert.True(t, hasDNSPeer([]string{"headless.default.svc.cluster.local"}))
	assert.True(t, hasDNSPeer([]string{"127.0.0.1:18081", "headless.default.svc.cluster.local:18081"}))
	assert.True(t, hasDNSPeer([]string{"node-1=grantory-0.headless:18081@http://grantory-0:8080"}))
	assert.True(t, hasDNSPeer([]string{"example.com"}))
}

func TestBootstrapDNSStabilization_Success(t *testing.T) {
	var lookups int
	var mu sync.Mutex
	mockLookup := func(host string) ([]net.IP, error) {
		mu.Lock()
		defer mu.Unlock()
		lookups++
		if lookups < 3 {
			// Initially only 1 peer is discoverable
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		// Subsequently all 3 peers are discoverable
		return []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("127.0.0.2"),
			net.ParseIP("127.0.0.3"),
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:18081",
		RaftNodeID:          "127.0.0.1:18081",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"headless.grantory:18081"},
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir,
		WithDNSResolver(newDNSResolver(10*time.Millisecond, mockLookup)),
		WithDNSWaitTimeout(3*time.Second),
		WithDNSRetryInterval(20*time.Millisecond),
	)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	mu.Lock()
	count := lookups
	mu.Unlock()
	assert.GreaterOrEqual(t, count, 3, "should have retried DNS lookup until 3 peers discovered")

	// Verify cluster configuration was bootstrapped with 3 servers
	confFuture := node.raft.GetConfiguration()
	require.NoError(t, confFuture.Error())
	assert.Len(t, confFuture.Configuration().Servers, 3)
}

func TestBootstrapDNSStabilization_Timeout(t *testing.T) {
	mockLookup := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:18081",
		RaftNodeID:          "127.0.0.1:18081",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"headless.grantory:18081"},
	}

	// Should not error when timeout expires, but skips auto-bootstrap
	node, err := NewRaftNode(ctx, cfg, nsStore, dir,
		WithDNSResolver(newDNSResolver(10*time.Millisecond, mockLookup)),
		WithDNSWaitTimeout(100*time.Millisecond),
		WithDNSRetryInterval(20*time.Millisecond),
	)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	confFuture := node.raft.GetConfiguration()
	require.NoError(t, confFuture.Error())
	assert.Empty(t, confFuture.Configuration().Servers, "cluster should not be bootstrapped when expect count not met")
}

func TestBootstrapDNSStabilization_ContextCanceled(t *testing.T) {
	mockLookup := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(context.Background(), dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:18081",
		RaftNodeID:          "127.0.0.1:18081",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"headless.grantory:18081"},
	}

	_, err = NewRaftNode(ctx, cfg, nsStore, dir,
		WithDNSResolver(newDNSResolver(10*time.Millisecond, mockLookup)),
		WithDNSWaitTimeout(5*time.Second),
		WithDNSRetryInterval(20*time.Millisecond),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wait for DNS bootstrap peers")
}

func TestHeadlessDNSStabilization_LeaderDiscovery(t *testing.T) {
	leaderListener, err := net.Listen("tcp", "127.0.0.2:0")
	require.NoError(t, err)
	_, leaderPort, err := net.SplitHostPort(leaderListener.Addr().String())
	require.NoError(t, err)
	leaderURL := "http://" + leaderListener.Addr().String()

	leaderServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cluster/status":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ClusterStatusResponse{
				NodeID:     "node-leader",
				Role:       "leader",
				IsLeader:   true,
				LeaderAddr: "127.0.0.2:9300",
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

	var mu sync.Mutex
	lookups := 0
	mockLookup := func(host string) ([]net.IP, error) {
		mu.Lock()
		defer mu.Unlock()
		lookups++
		if lookups == 1 {
			return nil, net.UnknownNetworkError("temporary failure")
		}
		return []net.IP{net.ParseIP("127.0.0.2")}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftAdvertise:       "127.0.0.1:19091",
		RaftNodeID:          "node-follower",
		RaftAutoJoin:        true,
		RaftClusterSecret:   "cluster-secret",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"headless.grantory:" + leaderPort},
		RaftPeerHTTPAddrs:   []string{"127.0.0.2:9300=" + leaderURL, "127.0.0.2:" + leaderPort + "=" + leaderURL},
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir,
		WithDNSResolver(newDNSResolver(10*time.Millisecond, mockLookup)),
		WithDNSWaitTimeout(2*time.Second),
		WithDNSRetryInterval(20*time.Millisecond),
	)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	mu.Lock()
	count := lookups
	mu.Unlock()
	assert.GreaterOrEqual(t, count, 2, "should have retried DNS lookup until leader discovered")

	// Verify that because active leader was discovered, bootstrap was skipped
	confFuture := node.raft.GetConfiguration()
	require.NoError(t, confFuture.Error())
	assert.Empty(t, confFuture.Configuration().Servers, "cluster should not be bootstrapped when leader was discovered")
}

func TestLeaderHTTPAddr_DirectAddrResolutionPostRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-lead",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	leaderAddr := node.LeaderAddr()
	require.NotEmpty(t, leaderAddr)

	refreshExecuted := false
	node.getConfigOverride = func() hashiraft.ConfigurationFuture {
		// During refresh, register the HTTP address directly under leaderAddr (not node-lead)
		node.RegisterHTTPAddr(leaderAddr, "http://127.0.0.1:8888")
		refreshExecuted = true
		return node.raft.GetConfiguration()
	}

	// Invalidate refresh timer and ensure neither leaderAddr nor node-lead are in httpAddrs
	node.mu.Lock()
	node.lastConfigRefresh = time.Now().Add(-10 * time.Second)
	delete(node.httpAddrs, leaderAddr)
	delete(node.httpAddrs, "node-lead")
	node.mu.Unlock()

	// LeaderHTTPAddr must execute refresh and resolve the directly registered address post-refresh
	resolved := node.LeaderHTTPAddr()
	require.True(t, refreshExecuted, "config refresh should have been executed")
	assert.Equal(t, "http://127.0.0.1:8888", resolved)
}

func TestNewRaftNode_InitialConfigResolvesIPAliases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	freeAddr := getFreeClusterPorts(t, 1)[0]
	_, port, err := net.SplitHostPort(freeAddr)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:" + port,
		RaftAdvertise:       "localhost:" + port,
		RaftNodeID:          "node-lead",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	// Check that serverIDByAddr is populated with both hostname and resolved IP aliases
	// immediately after NewRaftNode returns (before any periodic refresh).
	node.mu.RLock()
	defer node.mu.RUnlock()

	assert.Equal(t, "node-lead", node.serverIDByAddr["localhost:"+port])
	assert.Equal(t, "node-lead", node.serverIDByAddr["127.0.0.1:"+port])
	assert.Equal(t, "localhost:"+port, node.addrByServerID["node-lead"])
}

func TestServerIDByAddr(t *testing.T) {
	t.Parallel()

	var nilNode *RaftNode
	assert.Empty(t, nilNode.ServerIDByAddr("10.0.0.1:9090"))

	node := &RaftNode{
		serverIDByAddr: map[string]string{
			"10.0.0.1:9090":  "node-1",
			"127.0.0.1:9090": "node-1",
			"localhost:9090": "node-1",
			"10.0.0.2:9090":  "node-2",
		},
	}

	assert.Equal(t, "node-1", node.ServerIDByAddr("10.0.0.1:9090"))
	assert.Equal(t, "node-1", node.ServerIDByAddr("127.0.0.1:9090"))
	assert.Equal(t, "node-1", node.ServerIDByAddr("localhost:9090"))
	assert.Equal(t, "node-2", node.ServerIDByAddr("10.0.0.2:9090"))
	assert.Empty(t, node.ServerIDByAddr("10.0.0.99:9090"))
}

func TestRaftNode_InstanceScopedDNSResolver(t *testing.T) {
	t.Parallel()

	var nilNode *RaftNode
	assert.Nil(t, nilNode.resolveHostPort("host"))

	var lookupCount1, lookupCount2 int
	var mu1, mu2 sync.Mutex

	lookup1 := func(host string) ([]net.IP, error) {
		mu1.Lock()
		lookupCount1++
		mu1.Unlock()
		return []net.IP{net.ParseIP("192.168.1.10")}, nil
	}

	lookup2 := func(host string) ([]net.IP, error) {
		mu2.Lock()
		lookupCount2++
		mu2.Unlock()
		return []net.IP{net.ParseIP("192.168.1.20")}, nil
	}

	node1 := &RaftNode{
		cfg:      config.Config{RaftBind: "127.0.0.1:8081"},
		resolver: newDNSResolver(1*time.Hour, lookup1),
	}
	node2 := &RaftNode{
		cfg:      config.Config{RaftBind: "127.0.0.1:8082"},
		resolver: newDNSResolver(1*time.Hour, lookup2),
	}

	// 1. Initial resolution populates both independent caches
	ips1 := node1.resolveHostPort("peer-host")
	ips2 := node2.resolveHostPort("peer-host")
	assert.Equal(t, []string{"192.168.1.10:8081"}, ips1)
	assert.Equal(t, []string{"192.168.1.20:8082"}, ips2)
	assert.Equal(t, 1, lookupCount1)
	assert.Equal(t, 1, lookupCount2)

	// 2. Second lookup hits cache (no new lookups performed)
	_ = node1.resolveHostPort("peer-host")
	_ = node2.resolveHostPort("peer-host")
	assert.Equal(t, 1, lookupCount1)
	assert.Equal(t, 1, lookupCount2)

	// 3. Flushing node1's resolver only invalidates node1's cache
	node1.resolver.flush()

	// 4. node1 lookup hits custom resolver again, node2 lookup still uses its intact cache
	_ = node1.resolveHostPort("peer-host")
	_ = node2.resolveHostPort("peer-host")
	assert.Equal(t, 2, lookupCount1, "node1 resolver cache should have been flushed")
	assert.Equal(t, 1, lookupCount2, "node2 resolver cache should remain intact and untouched")

	// 5. Flushing node2's resolver invalidates node2's cache while node1 uses its cache
	node2.resolver.flush()
	_ = node1.resolveHostPort("peer-host")
	_ = node2.resolveHostPort("peer-host")
	assert.Equal(t, 2, lookupCount1, "node1 resolver cache should not be affected by flushing node2")
	assert.Equal(t, 2, lookupCount2, "node2 resolver cache should now be flushed")
}

func TestRemoveServer_UnknownNodeReturnsErrNotFound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	err = node.RemoveServer("unknown-node-id", 0, 5*time.Second)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound), "expected errors.Is(err, ErrNotFound) to be true, got: %v", err)
}

func TestPropose_CancelledContextAbortsBeforeApply(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	cmd, err := NewCommand("default", CmdCreateHost, time.Now().UTC(), storage.Host{ID: "aborted-host"})
	require.NoError(t, err)

	canceledCtx, cancelFn := context.WithCancel(context.Background())
	cancelFn() // pre-cancel context

	resp, err := node.Propose(canceledCtx, cmd)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "expected context.Canceled, got: %v", err)
	assert.Equal(t, ApplyResponse{}, resp)

	// Ensure proposal was aborted before apply, so host was never created
	st, err := node.nsStore.StoreFor(ctx, "default")
	if err == nil {
		_, err = st.GetHost(ctx, "aborted-host")
		require.Error(t, err)
	}
}
