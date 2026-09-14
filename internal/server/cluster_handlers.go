package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/tasansga/terraform-provider-grantory/internal/cluster/raft"
)

// CommandProposer is an optional interface for replicating commands across the cluster.
type CommandProposer interface {
	Propose(ctx context.Context, cmd raft.RaftCommand) (raft.ApplyResponse, error)
}

// LeaderStepDowner is an optional interface for transferring cluster leadership.
type LeaderStepDowner interface {
	StepDown() error
}

// ClusterMembersReporter is an optional interface for querying cluster server members.
type ClusterMembersReporter interface {
	ClusterServers() []raft.ServerInfo
}

const (
	// HeaderClusterSecret is the header used to authenticate cluster management requests.
	HeaderClusterSecret = "X-Grantory-Cluster-Secret"
)

// ClusterStatusResponse describes the current cluster status of this node.
type ClusterStatusResponse struct {
	NodeID     string            `json:"node_id"`
	Role       string            `json:"role"`
	IsLeader   bool              `json:"is_leader"`
	LeaderAddr string            `json:"leader_addr"`
	Servers    []raft.ServerInfo `json:"servers,omitempty"`
}

// ClusterJoinRequest payload to dynamically add a voter to the cluster.
type ClusterJoinRequest struct {
	NodeID      string `json:"node_id"`
	Address     string `json:"address"`
	HTTPAddress string `json:"http_address,omitempty"`
}

// ClusterRemoveRequest payload to dynamically remove a node from the cluster.
type ClusterRemoveRequest struct {
	NodeID  string `json:"node_id"`
	Address string `json:"address,omitempty"`
}

// registerClusterAdminAuth applies admin authentication middleware for cluster modification routes.
func registerClusterAdminAuth(app fiber.Router, secret string) {
	app.Use("/api/v1/cluster/join", clusterAdminAuthMiddleware(secret))
	app.Use("/api/v1/cluster/remove", clusterAdminAuthMiddleware(secret))
	app.Use("/api/v1/cluster/step-down", clusterAdminAuthMiddleware(secret))
}

// registerClusterRoutes registers endpoints for cluster status and administration.
func registerClusterRoutes(app fiber.Router, node ClusterManager) {
	app.Get("/api/v1/cluster/status", handleClusterStatus(node))
	app.Post("/api/v1/cluster/join", handleClusterJoin(node))
	app.Post("/api/v1/cluster/remove", handleClusterRemove(node))
	app.Post("/api/v1/cluster/step-down", handleClusterStepDown(node))
}

// clusterAdminAuthMiddleware verifies authentication for cluster management endpoints.
func clusterAdminAuthMiddleware(secret string) fiber.Handler {
	secret = strings.TrimSpace(secret)
	return func(c *fiber.Ctx) error {
		if secret == "" {
			logrus.Warn("cluster management endpoint invoked but cluster secret is not configured")
			return fiber.NewError(fiber.StatusForbidden, "cluster secret required for dynamic membership changes")
		}

		authHeader := c.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			token := strings.TrimSpace(authHeader[7:])
			if subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1 {
				return c.Next()
			}
		}

		clusterSecret := strings.TrimSpace(c.Get(HeaderClusterSecret))
		if clusterSecret != "" && subtle.ConstantTimeCompare([]byte(clusterSecret), []byte(secret)) == 1 {
			return c.Next()
		}

		return fiber.NewError(fiber.StatusUnauthorized, "unauthorized cluster management request")
	}
}

func handleClusterStatus(node ClusterManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if isNilClusterManager(node) {
			return c.Status(http.StatusOK).JSON(ClusterStatusResponse{
				NodeID:     "standalone",
				Role:       "standalone",
				IsLeader:   true,
				LeaderAddr: "",
			})
		}

		nodeID := ""
		if ni, ok := node.(NodeIdentifier); ok {
			nodeID = ni.NodeID()
		}

		role := "follower"
		if rr, ok := node.(RoleReporter); ok {
			role = rr.Role()
		} else if node.IsLeader() {
			role = "leader"
		}

		var servers []raft.ServerInfo
		if rep, ok := node.(ClusterMembersReporter); ok {
			servers = rep.ClusterServers()
		}

		return c.Status(http.StatusOK).JSON(ClusterStatusResponse{
			NodeID:     nodeID,
			Role:       role,
			IsLeader:   node.IsLeader(),
			LeaderAddr: node.LeaderAddr(),
			Servers:    servers,
		})
	}
}

func handleClusterJoin(node ClusterManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if isNilClusterManager(node) || !node.IsLeader() {
			c.Set("Retry-After", "1")
			return fiber.NewError(fiber.StatusServiceUnavailable, "node is not cluster leader")
		}

		var req ClusterJoinRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid json payload")
		}

		req.NodeID = strings.TrimSpace(req.NodeID)
		req.Address = strings.TrimSpace(req.Address)
		req.HTTPAddress = strings.TrimSpace(req.HTTPAddress)
		if req.NodeID == "" || req.Address == "" {
			return fiber.NewError(fiber.StatusBadRequest, "node_id and address are required")
		}

		host, port, err := net.SplitHostPort(req.Address)
		if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			return fiber.NewError(fiber.StatusBadRequest, "address must be a valid host:port")
		}

		cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
		if ip := net.ParseIP(cleanHost); ip != nil && ip.IsUnspecified() {
			return fiber.NewError(fiber.StatusBadRequest, "address cannot be an unspecified IP (0.0.0.0 or ::)")
		}

		if req.HTTPAddress != "" {
			u, err := url.ParseRequestURI(req.HTTPAddress)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.TrimSpace(u.Host) == "" {
				return fiber.NewError(fiber.StatusBadRequest, "http_address must be a valid http or https URL")
			}
			cleanHTTPHost := strings.Trim(strings.TrimSpace(u.Hostname()), "[]")
			if ip := net.ParseIP(cleanHTTPHost); ip != nil && ip.IsUnspecified() {
				return fiber.NewError(fiber.StatusBadRequest, "http_address cannot have an unspecified IP host")
			}
		}

		mm, ok := node.(MembershipManager)
		if !ok {
			return fiber.NewError(fiber.StatusInternalServerError, "node does not support membership management")
		}

		if err := mm.AddVoter(req.NodeID, req.Address, 0, 10*time.Second); err != nil {
			logrus.WithError(err).WithField("node_id", req.NodeID).WithField("address", req.Address).Error("failed to add voter")
			if raft.IsMembershipConflict(err) {
				return fiber.NewError(fiber.StatusConflict, fmt.Sprintf("configuration conflict: %v", err))
			}
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("failed to add voter: %v", err))
		}

		var warningMsg string
		if req.HTTPAddress != "" {
			if prop, ok := node.(CommandProposer); ok {
				cmd, err := raft.NewCommand("", raft.CmdRegisterNodeHTTPAddr, time.Now().UTC(), raft.RegisterNodeHTTPAddrPayload{
					ServerID: req.NodeID,
					Address:  req.Address,
					HTTPAddr: req.HTTPAddress,
				})
				if err != nil {
					logrus.WithError(err).WithField("node_id", req.NodeID).Warn("failed to construct register node HTTP address command")
					warningMsg = fmt.Sprintf("failed to construct HTTP address registration command: %v", err)
				} else {
					applyResp, propErr := prop.Propose(c.UserContext(), cmd)
					if propErr != nil {
						logrus.WithError(propErr).WithField("node_id", req.NodeID).Warn("failed to replicate node HTTP address registration")
						warningMsg = fmt.Sprintf("failed to replicate node HTTP address registration: %v", propErr)
					} else if applyResp.Error != nil {
						logrus.WithError(applyResp.Error).WithField("node_id", req.NodeID).Warn("node HTTP address registration rejected by state machine")
						warningMsg = fmt.Sprintf("node HTTP address registration rejected by state machine: %v", applyResp.Error)
					}
				}
			} else if reg, ok := node.(HTTPAddrRegistrar); ok {
				reg.RegisterHTTPAddr(req.Address, req.HTTPAddress)
				reg.RegisterHTTPAddr(req.NodeID, req.HTTPAddress)
			}
		}

		resp := map[string]any{
			"status":  "joined",
			"node_id": req.NodeID,
			"address": req.Address,
		}
		if req.HTTPAddress != "" {
			resp["http_address"] = req.HTTPAddress
		}
		if warningMsg != "" {
			resp["warning"] = warningMsg
		}
		return c.Status(http.StatusOK).JSON(resp)
	}
}

func handleClusterRemove(node ClusterManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if isNilClusterManager(node) || !node.IsLeader() {
			c.Set("Retry-After", "1")
			return fiber.NewError(fiber.StatusServiceUnavailable, "node is not cluster leader")
		}

		var req ClusterRemoveRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid json payload")
		}

		req.NodeID = strings.TrimSpace(req.NodeID)
		if req.NodeID == "" {
			return fiber.NewError(fiber.StatusBadRequest, "node_id is required")
		}

		targetID := req.NodeID
		if resolver, ok := node.(interface{ ServerIDByAddr(string) string }); ok {
			if sid := resolver.ServerIDByAddr(req.NodeID); sid != "" {
				targetID = sid
			}
		}
		var raftAddr string
		if resolver, ok := node.(interface{ AddrByServerID(string) string }); ok {
			raftAddr = resolver.AddrByServerID(targetID)
		}
		if raftAddr == "" && req.Address != "" {
			raftAddr = req.Address
		}
		if raftAddr == "" && req.NodeID != targetID {
			raftAddr = req.NodeID
		}

		var activeNodeID string
		if nodeIDProvider, ok := node.(interface{ NodeID() string }); ok {
			activeNodeID = nodeIDProvider.NodeID()
		}
		var activeAdvAddr string
		if advProvider, ok := node.(interface{ RaftAdvertise() string }); ok {
			activeAdvAddr = advProvider.RaftAdvertise()
		}
		var activeRaftAddr string
		if addrProvider, ok := node.(interface{ RaftAddress() string }); ok {
			activeRaftAddr = addrProvider.RaftAddress()
		}
		leaderAddr := node.LeaderAddr()

		isLeaderTarget := func(val string) bool {
			if val == "" {
				return false
			}
			return (activeNodeID != "" && val == activeNodeID) ||
				(activeAdvAddr != "" && val == activeAdvAddr) ||
				(activeRaftAddr != "" && val == activeRaftAddr) ||
				(leaderAddr != "" && val == leaderAddr)
		}

		if isLeaderTarget(targetID) || isLeaderTarget(req.NodeID) || isLeaderTarget(raftAddr) || isLeaderTarget(req.Address) {
			return fiber.NewError(fiber.StatusBadRequest, "cannot remove active cluster leader; step down leadership via /api/v1/cluster/step-down or stop the node to elect a new leader before removal")
		}

		mm, ok := node.(MembershipManager)
		if !ok {
			return fiber.NewError(fiber.StatusInternalServerError, "node does not support membership management")
		}

		if err := mm.RemoveServer(targetID, 0, 10*time.Second); err != nil {
			logrus.WithError(err).WithField("node_id", targetID).Error("failed to remove server")
			if strings.Contains(err.Error(), "cannot remove active cluster leader") {
				return fiber.NewError(fiber.StatusBadRequest, err.Error())
			}
			if errors.Is(err, raft.ErrNotFound) {
				return fiber.NewError(fiber.StatusNotFound, fmt.Sprintf("server %s not found in cluster", targetID))
			}
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("failed to remove server: %v", err))
		}

		var warningMsg string
		if prop, ok := node.(CommandProposer); ok {
			cmd, err := raft.NewCommand("", raft.CmdDeregisterNodeHTTPAddr, time.Now().UTC(), raft.DeregisterNodeHTTPAddrPayload{
				ServerID: targetID,
				Address:  raftAddr,
			})
			if err != nil {
				logrus.WithError(err).WithField("node_id", targetID).Warn("failed to construct deregister node HTTP address command")
				warningMsg = fmt.Sprintf("failed to construct HTTP address deregistration command: %v", err)
			} else {
				applyResp, propErr := prop.Propose(c.UserContext(), cmd)
				if propErr != nil {
					logrus.WithError(propErr).WithField("node_id", targetID).Warn("failed to replicate node HTTP address deregistration")
					warningMsg = fmt.Sprintf("failed to replicate node HTTP address deregistration: %v", propErr)
				} else if applyResp.Error != nil {
					logrus.WithError(applyResp.Error).WithField("node_id", targetID).Warn("node HTTP address deregistration rejected by state machine")
					warningMsg = fmt.Sprintf("node HTTP address deregistration rejected by state machine: %v", applyResp.Error)
				}
			}
		} else if reg, ok := node.(HTTPAddrRegistrar); ok {
			reg.DeregisterHTTPAddr(targetID)
			if req.NodeID != targetID {
				reg.DeregisterHTTPAddr(req.NodeID)
			}
			if raftAddr != "" && raftAddr != req.NodeID {
				reg.DeregisterHTTPAddr(raftAddr)
			}
		}

		resp := map[string]any{
			"status":  "removed",
			"node_id": req.NodeID,
		}
		if warningMsg != "" {
			resp["warning"] = warningMsg
		}
		return c.Status(http.StatusOK).JSON(resp)
	}
}

func handleClusterStepDown(node ClusterManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if isNilClusterManager(node) || !node.IsLeader() {
			c.Set("Retry-After", "1")
			return fiber.NewError(fiber.StatusServiceUnavailable, "node is not cluster leader")
		}

		stepDowner, ok := node.(LeaderStepDowner)
		if !ok {
			return fiber.NewError(fiber.StatusInternalServerError, "node does not support leadership step-down")
		}

		if err := stepDowner.StepDown(); err != nil {
			logrus.WithError(err).Error("failed to step down leadership")
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("failed to step down leadership: %v", err))
		}

		return c.Status(http.StatusOK).JSON(fiber.Map{
			"status":  "ok",
			"message": "leadership transfer initiated",
		})
	}
}
