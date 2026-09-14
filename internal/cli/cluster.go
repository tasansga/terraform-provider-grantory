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
	"os"
	"path/filepath"
	"strings"
	"time"

	hashiraft "github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	clusterraft "github.com/tasansga/terraform-provider-grantory/internal/cluster/raft"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/server"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
	"github.com/tasansga/terraform-provider-grantory/internal/store"
)

func newClusterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Manage Grantory cluster state",
		Long:  "Commands for managing Grantory cluster operations, such as manual disaster recovery.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newClusterRecoverCmd())
	cmd.AddCommand(newClusterStatusCmd())
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

	return cmd
}

func runClusterRecover(cmd *cobra.Command, _ []string) error {
	dataDir, _ := cmd.Flags().GetString("database")
	if !cmd.Flags().Changed("database") {
		if envDB := os.Getenv(config.EnvDatabase); envDB != "" {
			dataDir = envDB
		}
	}
	if strings.TrimSpace(dataDir) == "" {
		dataDir = config.DefaultDataDir
	}

	if storage.IsPostgresDSN(dataDir) {
		return errors.New("raft cluster recovery is not supported for postgresql backend")
	}

	clusterraft.CleanupStagingDirs(filepath.Join(dataDir, clusterraft.RaftDirName, clusterraft.StagingDirName), dataDir)

	nodeID, _ := cmd.Flags().GetString("node-id")
	if strings.TrimSpace(nodeID) == "" {
		nodeID = os.Getenv(config.EnvRaftNodeID)
	}
	if strings.TrimSpace(nodeID) == "" {
		return errors.New("--node-id is required (or set " + config.EnvRaftNodeID + ")")
	}

	bindAddr, _ := cmd.Flags().GetString("bind")
	if strings.TrimSpace(bindAddr) == "" {
		bindAddr = os.Getenv(config.EnvRaftAdvertise)
		if strings.TrimSpace(bindAddr) == "" {
			bindAddr = os.Getenv(config.EnvRaftBind)
		}
	}
	if strings.TrimSpace(bindAddr) == "" {
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

	raftDir := filepath.Join(dataDir, clusterraft.RaftDirName)
	if err := os.MkdirAll(raftDir, 0o755); err != nil {
		return fmt.Errorf("create raft directory %q: %w", raftDir, err)
	}

	snapshotDir := filepath.Join(raftDir, clusterraft.SnapshotsDirName)
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return fmt.Errorf("create snapshot directory %q: %w", snapshotDir, err)
	}

	dbPath := filepath.Join(raftDir, clusterraft.RaftDBFileName)
	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("refusing recovery: no existing Raft state found in database directory")
		}
		return fmt.Errorf("stat raft database %q: %w", dbPath, err)
	}
	boltStore, err := raftboltdb.NewBoltStore(dbPath)
	if err != nil {
		return fmt.Errorf("open bolt store %q: %w (ensure grantory serve is stopped before running cluster recovery)", dbPath, err)
	}
	defer func() { _ = boltStore.Close() }()

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
	serverURL, _ := cmd.Flags().GetString("server-url")
	if strings.TrimSpace(serverURL) == "" && cmd != nil && cmd.Root() != nil {
		if flag := cmd.Root().PersistentFlags().Lookup(FlagServerURL); flag != nil {
			serverURL = flag.Value.String()
		}
	}
	if strings.TrimSpace(serverURL) == "" {
		for _, envVar := range []string{EnvServerURL, "GRANTORY_SERVER_URL", "SERVER_URL", EnvGrantoryControllerServerURL} {
			if val := strings.TrimSpace(os.Getenv(envVar)); val != "" {
				serverURL = val
				break
			}
		}
	}
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" {
		return "", errors.New("--server-url is required (or set " + EnvServerURL + ")")
	}
	return serverURL, nil
}

func resolveClusterSecret(cmd *cobra.Command) string {
	clusterSecret, _ := cmd.Flags().GetString("cluster-secret")
	if strings.TrimSpace(clusterSecret) == "" && cmd != nil && cmd.Root() != nil {
		if flag := cmd.Root().PersistentFlags().Lookup("raft-cluster-secret"); flag != nil {
			clusterSecret = flag.Value.String()
		}
	}
	if strings.TrimSpace(clusterSecret) == "" {
		for _, envVar := range []string{config.EnvRaftClusterSecret, "GRANTORY_TOKEN"} {
			if val := strings.TrimSpace(os.Getenv(envVar)); val != "" {
				clusterSecret = val
				break
			}
		}
	}
	if strings.TrimSpace(clusterSecret) == "" && cmd != nil && cmd.Root() != nil {
		if flag := cmd.Root().PersistentFlags().Lookup(FlagToken); flag != nil {
			clusterSecret = flag.Value.String()
		}
	}
	if strings.TrimSpace(clusterSecret) == "" {
		clusterSecret = os.Getenv(EnvToken)
	}
	return strings.TrimSpace(clusterSecret)
}

func newClusterStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display Raft cluster status and membership",
		Long:  "Display Raft cluster status and membership details from the cluster leader.",
		RunE:  runClusterStatus,
	}

	cmd.Flags().String("server-url", "", "Grantory server URL (env: "+EnvServerURL+")")
	cmd.Flags().String("cluster-secret", "", "Shared secret for authenticating cluster management operations (env: "+config.EnvRaftClusterSecret+")")

	return cmd
}

func runClusterStatus(cmd *cobra.Command, _ []string) error {
	serverURL, err := resolveClusterServerURL(cmd)
	if err != nil {
		return err
	}
	clusterSecret := resolveClusterSecret(cmd)

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	reqURL := strings.TrimRight(serverURL, "/") + "/api/v1/cluster/status"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("create cluster status request: %w", err)
	}

	if clusterSecret != "" {
		httpReq.Header.Set(server.HeaderClusterSecret, clusterSecret)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("cluster status request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("get cluster status failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	_, err = fmt.Fprintln(cmd.OutOrStdout(), strings.TrimSpace(string(body)))
	return err
}

func newClusterRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a node from the Raft cluster",
		Long:  "Remove a node from the Raft cluster membership.",
		RunE:  runClusterRemove,
	}

	cmd.Flags().String("server-url", "", "Grantory server URL (env: "+EnvServerURL+")")
	cmd.Flags().String("node-id", "", "node ID of the cluster member to remove")
	cmd.Flags().String("address", "", "network address of the node to remove")
	cmd.Flags().String("cluster-secret", "", "Shared secret for authenticating cluster management operations (env: "+config.EnvRaftClusterSecret+")")

	return cmd
}

func runClusterRemove(cmd *cobra.Command, _ []string) error {
	serverURL, err := resolveClusterServerURL(cmd)
	if err != nil {
		return err
	}
	clusterSecret := resolveClusterSecret(cmd)

	nodeID, _ := cmd.Flags().GetString("node-id")
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return errors.New("--node-id is required")
	}

	address, _ := cmd.Flags().GetString("address")
	address = strings.TrimSpace(address)

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	payload := server.ClusterRemoveRequest{
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

	if clusterSecret != "" {
		httpReq.Header.Set(server.HeaderClusterSecret, clusterSecret)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("remove request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("remove node failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	_, err = fmt.Fprintln(cmd.OutOrStdout(), strings.TrimSpace(string(body)))
	return err
}

func newClusterStepDownCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "step-down",
		Short: "Step down cluster leadership on the active leader node",
		Long:  "Initiate leadership transfer away from the active cluster leader node.",
		RunE:  runClusterStepDown,
	}

	cmd.Flags().String("server-url", "", "Grantory server URL (env: "+EnvServerURL+")")
	cmd.Flags().String("cluster-secret", "", "Shared secret for authenticating cluster management operations (env: "+config.EnvRaftClusterSecret+")")

	return cmd
}

func runClusterStepDown(cmd *cobra.Command, _ []string) error {
	serverURL, err := resolveClusterServerURL(cmd)
	if err != nil {
		return err
	}
	clusterSecret := resolveClusterSecret(cmd)

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	reqURL := strings.TrimRight(serverURL, "/") + "/api/v1/cluster/step-down"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, nil)
	if err != nil {
		return fmt.Errorf("create step-down request: %w", err)
	}

	if clusterSecret != "" {
		httpReq.Header.Set(server.HeaderClusterSecret, clusterSecret)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("step-down request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("step-down failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	_, err = fmt.Fprintln(cmd.OutOrStdout(), strings.TrimSpace(string(body)))
	return err
}
