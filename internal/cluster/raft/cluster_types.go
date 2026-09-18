package raft

import (
	"net/http"
	"strings"
)

// ClusterStatusResponse describes the current cluster status of a node.
type ClusterStatusResponse struct {
	NodeID         string       `json:"node_id"`
	Role           string       `json:"role"`
	IsLeader       bool         `json:"is_leader"`
	LeaderAddr     string       `json:"leader_addr"`
	Servers        []ServerInfo `json:"servers,omitempty"`
	AutoJoinStatus string       `json:"auto_join_status,omitempty"`
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

// ExtractBearerToken strips any leading case-insensitive "Bearer " prefix and surrounding whitespace.
func ExtractBearerToken(header string) string {
	header = strings.TrimSpace(header)
	if len(header) >= 6 && strings.EqualFold(header[:6], "bearer") {
		if len(header) == 6 || header[6] == ' ' || header[6] == '\t' {
			return strings.TrimSpace(header[6:])
		}
	}
	return header
}

// FormatBearerToken strips any leading case-insensitive "Bearer " prefix and returns "Bearer <token>".
func FormatBearerToken(secret string) string {
	secret = ExtractBearerToken(secret)
	if secret == "" {
		return ""
	}
	return "Bearer " + secret
}

// ApplyClusterAuth applies the cluster authentication header to an HTTP request.
func ApplyClusterAuth(req *http.Request, clusterSecret string) {
	if req == nil {
		return
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if token := FormatBearerToken(clusterSecret); token != "" {
		req.Header.Set("Authorization", token)
	}
}
