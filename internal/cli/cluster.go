package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	hashiraft "github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.etcd.io/bbolt"
	bbolterrors "go.etcd.io/bbolt/errors"

	clusterraft "github.com/tasansga/terraform-provider-grantory/internal/cluster/raft"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
	"github.com/tasansga/terraform-provider-grantory/internal/store"
)

const FlagLockTimeout = "lock-timeout"

func newClusterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Manage Grantory cluster state",
		Long:  "Commands for managing Grantory cluster operations, such as manual disaster recovery.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.PersistentFlags().String("server-url", "", "Grantory server URL (env: "+EnvServerURL+")")
	cmd.PersistentFlags().String("cluster-secret", "", "Shared secret for authenticating cluster management operations (env: "+config.EnvRaftClusterSecret+")")
	cmd.PersistentFlags().String("raft-ca-file", "", "CA certificate for Raft mTLS verification (env: "+config.EnvRaftCAFile+")")
	cmd.PersistentFlags().String("raft-cert-file", "", "path to client certificate file for Raft TLS auth (env: "+config.EnvRaftCertFile+")")
	cmd.PersistentFlags().String("raft-key-file", "", "path to client private key file for Raft TLS auth (env: "+config.EnvRaftKeyFile+")")
	cmd.PersistentFlags().String("tls-cert", "", "path to the TLS certificate file (env: "+config.EnvTLSCert+")")
	cmd.PersistentFlags().String("tls-key", "", "path to the TLS private key file (env: "+config.EnvTLSKey+")")
	cmd.PersistentFlags().String("raft-tls-server-name", "", "expected TLS server name (DNS SAN) for peer verification (env: "+config.EnvRaftTLSServerName+")")

	cmd.AddCommand(newClusterRecoverCmd())
	cmd.AddCommand(newClusterStatusCmd())
	cmd.AddCommand(newClusterJoinCmd())
	cmd.AddCommand(newClusterRemoveCmd())
	cmd.AddCommand(newClusterStepDownCmd())
	return cmd
}

func newClusterRecoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Recover a Raft cluster with lost quorum by forcing a single-node configuration",
		Long: "Recover a Raft cluster when quorum is permanently lost by rewriting the Raft cluster state on disk.\n" +
			"This command forces a 1-node configuration containing only the specified surviving node as leader.\n" +
			"The Grantory server on this node MUST be stopped before running this command.",
		RunE: runClusterRecover,
	}

	cmd.Flags().String("database", config.DefaultDataDir, "database directory path (env: "+config.EnvDatabase+")")
	cmd.Flags().String("node-id", "", "node ID of surviving node (env: "+config.EnvRaftNodeID+")")
	cmd.Flags().String("bind", "", "Raft bind/advertise address of surviving node (env: "+config.EnvRaftAdvertise+" or "+config.EnvRaftBind+")")
	cmd.Flags().String(FlagLockTimeout, config.DefaultRaftLockTimeout.String(), "timeout waiting for exclusive lock on Raft database (env: "+config.EnvRaftLockTimeout+", "+config.EnvGrantoryRaftLockTimeout+", or "+config.EnvGrantoryLockTimeout+")")

	return cmd
}

func runClusterRecover(cmd *cobra.Command, _ []string) error {
	dataDir := resolveClusterFlagOrEnv(cmd, "database", config.EnvDatabase)
	if dataDir == "" {
		dataDir = config.DefaultDataDir
	}

	if storage.IsPostgresDSN(dataDir) {
		return errors.New("raft cluster recovery is not supported for postgresql backend")
	}

	nodeID := resolveClusterFlagOrEnv(cmd, "node-id", config.EnvRaftNodeID)
	if nodeID == "" {
		return errors.New("--node-id is required (or set " + config.EnvRaftNodeID + ")")
	}

	bindAddr := resolveClusterFlagOrEnv(cmd, "bind", config.EnvRaftAdvertise, config.EnvRaftBind)
	if bindAddr == "" {
		return errors.New("--bind is required (or set " + config.EnvRaftAdvertise + " or " + config.EnvRaftBind + ")")
	}
	host, _, err := net.SplitHostPort(bindAddr)
	if err != nil {
		return fmt.Errorf("invalid --bind address %q: must be in host:port format", bindAddr)
	}
	cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
	if ip := net.ParseIP(cleanHost); ip != nil && ip.IsUnspecified() {
		return fmt.Errorf("cluster recover address %q cannot have an unspecified IP host (0.0.0.0 or ::); provide a routable address via --bind or %s", bindAddr, config.EnvRaftAdvertise)
	}

	lockTimeout, err := resolveClusterDurationFlagOrEnv(cmd, FlagLockTimeout, config.EnvRaftLockTimeout, config.EnvGrantoryRaftLockTimeout, config.EnvGrantoryLockTimeout)
	if err != nil {
		return err
	}

	raftDir := filepath.Join(dataDir, clusterraft.RaftDirName)
	dbPath := filepath.Join(raftDir, clusterraft.RaftDBFileName)
	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("refusing recovery: no existing Raft state found in database directory")
		}
		return fmt.Errorf("stat raft database %q: %w", dbPath, err)
	}

	logrus.WithFields(logrus.Fields{
		"node_id":      nodeID,
		"bind":         bindAddr,
		"database":     dataDir,
		"lock_timeout": lockTimeout.String(),
	}).Info("starting Raft cluster recovery")

	logrus.WithFields(logrus.Fields{
		"raft_db":      dbPath,
		"lock_timeout": lockTimeout.String(),
	}).Info("acquiring exclusive lock on Raft database")

	boltStore, err := raftboltdb.New(raftboltdb.Options{
		Path: dbPath,
		BoltOptions: &bbolt.Options{
			Timeout: lockTimeout,
		},
	})
	if err != nil {
		if errors.Is(err, bbolterrors.ErrTimeout) {
			return fmt.Errorf("open bolt store %q: %w (ensure grantory serve is stopped before running cluster recovery)", dbPath, err)
		}
		return fmt.Errorf("open bolt store %q: %w", dbPath, err)
	}
	defer func() { _ = boltStore.Close() }()

	logrus.WithField("raft_db", dbPath).Info("acquired Raft database lock")

	clusterraft.CleanupStagingDirs(filepath.Join(dataDir, clusterraft.RaftDirName, clusterraft.StagingDirName), dataDir)

	snapshotDir := filepath.Join(raftDir, clusterraft.SnapshotsDirName)
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return fmt.Errorf("create snapshot directory %q: %w", snapshotDir, err)
	}

	snapshotStore, err := hashiraft.NewFileSnapshotStore(snapshotDir, 3, clusterraft.NewRaftLogWriter(logrus.WithField("component", "raft"), logrus.InfoLevel))
	if err != nil {
		return fmt.Errorf("create snapshot store %q: %w", snapshotDir, err)
	}

	_, transport := hashiraft.NewInmemTransport(hashiraft.ServerAddress(bindAddr))

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	nsStore, err := store.NewNamespaceStore(ctx, dataDir)
	if err != nil {
		return fmt.Errorf("open namespace store: %w", err)
	}
	defer func() { _ = nsStore.Close() }()

	fsm := clusterraft.NewFSM(ctx, nsStore)

	hasState, err := hashiraft.HasExistingState(boltStore, boltStore, snapshotStore)
	if err != nil {
		return fmt.Errorf("check existing raft state: %w", err)
	}
	if !hasState {
		return errors.New("refusing recovery: no existing Raft state found in database directory")
	}

	raftConfig := hashiraft.DefaultConfig()
	raftConfig.LocalID = hashiraft.ServerID(nodeID)
	raftConfig.LogOutput = clusterraft.NewRaftLogWriter(logrus.WithField("component", "raft"), logrus.InfoLevel)

	configuration := hashiraft.Configuration{
		Servers: []hashiraft.Server{
			{
				ID:       hashiraft.ServerID(nodeID),
				Address:  hashiraft.ServerAddress(bindAddr),
				Suffrage: hashiraft.Voter,
			},
		},
	}

	logrus.WithFields(logrus.Fields{
		"node_id": nodeID,
		"bind":    bindAddr,
	}).Info("rewriting Raft cluster configuration to single-node")

	if err := hashiraft.RecoverCluster(raftConfig, fsm, boltStore, boltStore, snapshotStore, transport, configuration); err != nil {
		return fmt.Errorf("recover cluster: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"node_id":  nodeID,
		"bind":     bindAddr,
		"database": dataDir,
	}).Info("cluster recovered successfully")

	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Cluster recovered successfully. Node %q (%s) is now configured as the sole voter.\n", nodeID, bindAddr)
	return err
}

func resolveClusterServerURL(cmd *cobra.Command) (string, error) {
	serverURL := resolveClusterFlagOrEnv(cmd, "server-url", EnvServerURL, "GRANTORY_SERVER_URL", "SERVER_URL", EnvGrantoryControllerServerURL, "GRANTORY_URL", "GRANTORY_ADDR")
	if serverURL == "" {
		return "", errors.New("--server-url is required (or set " + EnvServerURL + ")")
	}
	lower := strings.ToLower(serverURL)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		serverURL = "http://" + serverURL
	}
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid --server-url %q: must be a valid host:port or URL", serverURL)
	}
	return strings.TrimRight(serverURL, "/"), nil
}

func resolveClusterSecret(cmd *cobra.Command) string {
	for _, flagName := range []string{"cluster-secret", "raft-cluster-secret", FlagToken} {
		if flag := lookupFlag(cmd, flagName); flag != nil && flag.Changed && strings.TrimSpace(flag.Value.String()) != "" {
			return strings.TrimSpace(flag.Value.String())
		}
	}
	for _, envVar := range []string{
		config.EnvRaftClusterSecret,
		"GRANTORY_CLUSTER_SECRET",
		"GRANTORY_TOKEN",
		EnvToken,
		EnvGrantoryControllerToken,
	} {
		if val := strings.TrimSpace(os.Getenv(envVar)); val != "" {
			return val
		}
	}
	return ""
}

func newClusterStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Display Raft cluster status and membership",
		Long:  "Display Raft cluster status and membership details from the cluster leader.",
		RunE:  runClusterStatus,
	}
}

func runClusterStatus(cmd *cobra.Command, _ []string) error {
	return runSimpleClusterRequest(cmd, http.MethodGet, "/api/v1/cluster/status")
}


func newClusterRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a node from the Raft cluster",
		Long:  "Remove a node from the Raft cluster membership.",
		RunE:  runClusterRemove,
	}

	cmd.Flags().String("node-id", "", "node ID of the cluster member to remove (env: "+config.EnvRaftNodeID+")")
	cmd.Flags().String("address", "", "network address of the node to remove (defaults from "+config.EnvRaftAdvertise+" or "+config.EnvRaftBind+" when operating on the local node)")

	return cmd
}

func runClusterRemove(cmd *cobra.Command, _ []string) error {
	serverURL, err := resolveClusterServerURL(cmd)
	if err != nil {
		return err
	}
	clusterSecret := resolveClusterSecret(cmd)

	nodeID := resolveClusterFlagOrEnv(cmd, "node-id", config.EnvRaftNodeID)
	if nodeID == "" {
		return errors.New("--node-id is required (or set " + config.EnvRaftNodeID + ")")
	}

	nodeIDFlag := lookupFlag(cmd, "node-id")
	nodeIDExplicit := nodeIDFlag != nil && nodeIDFlag.Changed && strings.TrimSpace(nodeIDFlag.Value.String()) != ""

	address := resolveClusterNodeAddress(cmd, nodeID, nodeIDExplicit)
	if address != "" {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("invalid --address %q: must be in host:port format", address)
		}
		host = strings.Trim(host, "[]")
		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			return fmt.Errorf("invalid --address %q: address cannot be an unspecified IP (0.0.0.0 or ::)", address)
		}
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	payload := clusterraft.ClusterRemoveRequest{
		NodeID:  nodeID,
		Address: address,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal remove request: %w", err)
	}

	reqURL := strings.TrimRight(serverURL, "/") + "/api/v1/cluster/remove"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("create remove request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	clusterraft.ApplyClusterAuth(httpReq, clusterSecret)

	return executeClusterRequest(cmd, httpReq)
}

func newClusterStepDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "step-down",
		Short: "Step down cluster leadership on the active leader node",
		Long:  "Initiate leadership transfer away from the active cluster leader node.",
		RunE:  runClusterStepDown,
	}
}

func runClusterStepDown(cmd *cobra.Command, _ []string) error {
	return runSimpleClusterRequest(cmd, http.MethodPost, "/api/v1/cluster/step-down")
}

func newClusterJoinCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "join",
		Short: "Join a node into an existing Raft cluster",
		Long:  "Join a node into the Raft cluster membership via the active cluster leader.",
		RunE:  runClusterJoin,
	}

	cmd.Flags().String("node-id", "", "node ID of the cluster member to join (env: "+config.EnvRaftNodeID+")")
	cmd.Flags().String("address", "", "Raft peer network address of the node to join (defaults to "+config.EnvRaftAdvertise+" or "+config.EnvRaftBind+" when joining the local node)")
	cmd.Flags().String("http-address", "", "HTTP address of the node to join")

	return cmd
}

func runClusterJoin(cmd *cobra.Command, _ []string) error {
	serverURL, err := resolveClusterServerURL(cmd)
	if err != nil {
		return err
	}
	clusterSecret := resolveClusterSecret(cmd)

	nodeID := resolveClusterFlagOrEnv(cmd, "node-id", config.EnvRaftNodeID)
	if nodeID == "" {
		return errors.New("--node-id is required (or set " + config.EnvRaftNodeID + ")")
	}

	nodeIDFlag := lookupFlag(cmd, "node-id")
	nodeIDExplicit := nodeIDFlag != nil && nodeIDFlag.Changed && strings.TrimSpace(nodeIDFlag.Value.String()) != ""

	address := resolveClusterNodeAddress(cmd, nodeID, nodeIDExplicit)
	if address == "" {
		localNodeID := strings.TrimSpace(os.Getenv(config.EnvRaftNodeID))
		if nodeIDExplicit && (localNodeID == "" || nodeID != localNodeID) {
			return errors.New("--address is required when specifying --node-id for a remote node")
		}
		return errors.New("--address is required (or set " + config.EnvRaftAdvertise + " or " + config.EnvRaftBind + ")")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid --address %q: must be in host:port format", address)
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return fmt.Errorf("invalid --address %q: address cannot be an unspecified IP (0.0.0.0 or ::)", address)
	}

	httpAddress := resolveClusterFlagOrEnv(cmd, "http-address")
	if httpAddress != "" {
		u, err := url.Parse(httpAddress)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("invalid --http-address %q: must be a valid http:// or https:// URL", httpAddress)
		}
		cleanHTTPHost := strings.Trim(strings.TrimSpace(u.Hostname()), "[]")
		if ip := net.ParseIP(cleanHTTPHost); ip != nil && ip.IsUnspecified() {
			return fmt.Errorf("invalid --http-address %q: http_address cannot have an unspecified IP host (0.0.0.0 or ::)", httpAddress)
		}
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	payload := clusterraft.ClusterJoinRequest{
		NodeID:      nodeID,
		Address:     address,
		HTTPAddress: httpAddress,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal join request: %w", err)
	}

	reqURL := strings.TrimRight(serverURL, "/") + "/api/v1/cluster/join"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("create join request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	clusterraft.ApplyClusterAuth(httpReq, clusterSecret)

	return executeClusterRequest(cmd, httpReq)
}

func runSimpleClusterRequest(cmd *cobra.Command, method, path string) error {
	serverURL, err := resolveClusterServerURL(cmd)
	if err != nil {
		return err
	}
	clusterSecret := resolveClusterSecret(cmd)
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	reqURL := strings.TrimRight(serverURL, "/") + path
	httpReq, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return fmt.Errorf("create request %s %s: %w", method, path, err)
	}
	clusterraft.ApplyClusterAuth(httpReq, clusterSecret)
	return executeClusterRequest(cmd, httpReq)
}

func executeClusterRequest(cmd *cobra.Command, req *http.Request, optionalClient ...*http.Client) error {
	var client *http.Client
	if len(optionalClient) > 0 && optionalClient[0] != nil {
		client = optionalClient[0]
	} else {
		var err error
		client, err = resolveClusterHTTPClient(cmd)
		if err != nil {
			return err
		}
		defer client.CloseIdleConnections()
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cluster request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if msg != "" {
			return fmt.Errorf("cluster request failed (HTTP %d): %s", resp.StatusCode, msg)
		}
		return fmt.Errorf("cluster request failed (HTTP %d)", resp.StatusCode)
	}

	var out io.Writer = os.Stdout
	if cmd != nil {
		out = cmd.OutOrStdout()
	}
	_, err = fmt.Fprintln(out, strings.TrimSpace(string(body)))
	return err
}

func lookupFlag(cmd *cobra.Command, flagName string) *pflag.Flag {
	if cmd == nil {
		return nil
	}
	for curr := cmd; curr != nil; curr = curr.Parent() {
		if flag := curr.Flag(flagName); flag != nil && flag.Changed {
			return flag
		}
	}
	for curr := cmd; curr != nil; curr = curr.Parent() {
		if flag := curr.Flag(flagName); flag != nil {
			return flag
		}
	}
	return nil
}

// resolveClusterFlagOrEnv resolves a flag value with env var and default fallback,
// preserving legacy empty-string fallback behavior for string flags, whereas
// resolveClusterDurationFlagOrEnv enforces strict non-empty syntax on duration flags.
func resolveClusterFlagOrEnv(cmd *cobra.Command, flagName string, envVars ...string) string {
	flag := lookupFlag(cmd, flagName)
	if flag != nil && flag.Changed && strings.TrimSpace(flag.Value.String()) != "" {
		return strings.TrimSpace(flag.Value.String())
	}
	for _, envVar := range envVars {
		if val := strings.TrimSpace(os.Getenv(envVar)); val != "" {
			return val
		}
	}
	if flag != nil && strings.TrimSpace(flag.DefValue) != "" {
		return strings.TrimSpace(flag.DefValue)
	}
	return ""
}

func resolveClusterDurationFlagOrEnv(cmd *cobra.Command, flagName string, envVars ...string) (time.Duration, error) {
	flag := lookupFlag(cmd, flagName)
	var source, val string
	if flag != nil && flag.Changed {
		source = "--" + flagName
		raw := flag.Value.String()
		val = strings.TrimSpace(raw)
		if val == "" {
			return 0, fmt.Errorf("invalid %s %q: duration cannot be empty", source, raw)
		}
	} else {
		for _, envVar := range envVars {
			if envVal := strings.TrimSpace(os.Getenv(envVar)); envVal != "" {
				source = envVar
				val = envVal
				break
			}
		}
	}

	if val == "" {
		if flag != nil && strings.TrimSpace(flag.DefValue) != "" {
			source = "--" + flagName
			val = strings.TrimSpace(flag.DefValue)
		}
	}

	if val == "" {
		return 0, fmt.Errorf("--%s is required", flagName)
	}

	d, err := time.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", source, val, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid %s %q: duration must be greater than zero", source, val)
	}
	return d, nil
}

func resolveClusterNodeAddress(cmd *cobra.Command, nodeID string, nodeIDExplicit bool) string {
	localNodeID := strings.TrimSpace(os.Getenv(config.EnvRaftNodeID))
	if nodeIDExplicit && (localNodeID == "" || nodeID != localNodeID) {
		return resolveClusterFlagOrEnv(cmd, "address")
	}
	return resolveClusterFlagOrEnv(cmd, "address", config.EnvRaftAdvertise, config.EnvRaftBind)
}

func resolveClusterHTTPClient(cmd *cobra.Command) (*http.Client, error) {
	cfg := config.Config{
		RaftCAFile:        resolveClusterFlagOrEnv(cmd, "raft-ca-file", config.EnvRaftCAFile),
		RaftCertFile:      resolveClusterFlagOrEnv(cmd, "raft-cert-file", config.EnvRaftCertFile),
		RaftKeyFile:       resolveClusterFlagOrEnv(cmd, "raft-key-file", config.EnvRaftKeyFile),
		TLSCert:           resolveClusterFlagOrEnv(cmd, "tls-cert", config.EnvTLSCert),
		TLSKey:            resolveClusterFlagOrEnv(cmd, "tls-key", config.EnvTLSKey),
		RaftTLSServerName: resolveClusterFlagOrEnv(cmd, "raft-tls-server-name", config.EnvRaftTLSServerName),
	}
	return clusterraft.BuildClusterHTTPClient(cfg)
}
