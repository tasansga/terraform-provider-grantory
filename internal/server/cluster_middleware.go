package server

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/proxy"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

func isNilClusterManager(node ClusterManager) bool {
	if node == nil {
		return true
	}
	v := reflect.ValueOf(node)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

const (
	// HeaderForwardedBy is the HTTP header set by a follower when forwarding a request to the leader.
	HeaderForwardedBy = "X-Grantory-Forwarded-By"
	// HeaderForwardedSig is the HTTP header containing hop HMAC signatures for loop detection.
	HeaderForwardedSig = "X-Grantory-Forwarded-Sig"
	// maxForwardHops is the maximum number of proxy hops allowed before detecting a runaway forwarding loop.
	maxForwardHops = 10
	// ForwardHopTTL is the maximum validity window for cluster proxy hop signatures.
	// 45 seconds safely exceeds the 30-second reverse proxy read timeout.
	ForwardHopTTL = 45 * time.Second
)

// HopSecretProvider is an optional interface for nodes that provide a local hop secret.
type HopSecretProvider interface {
	HopSecret() [32]byte
}

// ComputeHopSignature generates an HMAC-SHA256 signature for hop authentication in cluster loop detection.
func ComputeHopSignature(secret [32]byte, nodeID string, ts int64) string {
	mac := hmac.New(sha256.New, secret[:])
	_, _ = fmt.Fprintf(mac, "%s:%d", nodeID, ts)
	return hex.EncodeToString(mac.Sum(nil))
}

// ClusterManager specifies the minimal interface required for cluster request routing.
type ClusterManager interface {
	IsLeader() bool
	LeaderAddr() string
}

// BarrierChecker is an optional interface implemented by nodes supporting linearizable read barriers.
type BarrierChecker interface {
	Barrier(ctx context.Context) error
}

// NodeIdentifier is an optional interface for reporting the node's cluster identifier.
type NodeIdentifier interface {
	NodeID() string
}

// RoleReporter is an optional interface for reporting the cluster role.
type RoleReporter interface {
	Role() string
}

// LeaderHTTPAddrReporter is an optional interface for returning the leader's HTTP address.
type LeaderHTTPAddrReporter interface {
	LeaderHTTPAddr() string
}

// TLSReporter is an optional interface for reporting whether TLS is enabled.
type TLSReporter interface {
	IsTLS() bool
}

// MembershipManager is an optional interface for managing cluster voting members.
type MembershipManager interface {
	AddVoter(id string, addr string, prevIndex uint64, timeout time.Duration) error
	RemoveServer(id string, prevIndex uint64, timeout time.Duration) error
}

// HTTPAddrRegistrar is an optional interface for registering HTTP addresses for cluster nodes.
type HTTPAddrRegistrar interface {
	RegisterHTTPAddr(raftAddrOrID, httpAddr string)
	DeregisterHTTPAddr(raftAddrOrID string)
}

// clusterRoutingMiddleware (ClusterProxy) intercepts requests based on the node's cluster role:
// - Standalone (node == nil): passes through directly.
// - Leader: executes a linearizable barrier on GET/HEAD requests to confirm leadership quorum;
//   allows write requests to proceed to handlers.
// - Follower: transparently reverse-proxies requests to the cluster leader, setting loop-prevention headers.
//
// Architecture & Forwarding Loop Prevention:
//
// 1. Role-Based Reverse Proxying:
// In an active Raft cluster, only the leader commits writes to the consensus log and database.
// Followers proxy all mutative API calls (and server-rendered UI/metrics) directly to the current
// leader HTTP address. Each forwarding follower appends its cluster node ID to the
// X-Grantory-Forwarded-By header and a corresponding HMAC-SHA256 signature to
// X-Grantory-Forwarded-Sig.
//
// 2. Self-Loop Cycle Detection:
// When any node receives a forwarded request, it checks whether its own node ID is already
// present in the X-Grantory-Forwarded-By chain (hasNode). If present, it validates the HMAC
// signature for that hop using its local hop secret (validLoop). If the signature matches,
// the node halts execution and returns HTTP 508 Loop Detected.
// Because any forwarding loop on a finite set of N cluster nodes must revisit at least one node
// in at most N hops, self-loop detection (hasNode && validLoop) is cryptographically guaranteed
// by the node that originally added the hop to detect and break all cycles across all finite
// clusters, even without a shared cluster secret.
//
// 3. Cluster-Wide Hop Authentication & Threshold Enforcement:
// When --raft-cluster-secret is configured, every node in the cluster shares the same secret key
// for HopSecretProvider. This enables cluster-wide hop authentication: intermediate nodes can
// verify signatures added by any cluster peer. This allows the cluster to enforce the absolute
// maxForwardHops threshold (10 hops) across distinct nodes (hopCount >= maxForwardHops && validSigCount >= maxForwardHops)
// without risk of external attackers forging spoofed forward headers to trigger premature 508 errors.
func clusterRoutingMiddleware(node ClusterManager, customClient ...*fasthttp.Client) fiber.Handler {
	if isNilClusterManager(node) {
		return func(c *fiber.Ctx) error {
			return c.Next()
		}
	}

	var client *fasthttp.Client
	if len(customClient) > 0 && customClient[0] != nil {
		client = customClient[0]
	}

	instanceID := uuid.New().String()

	var localHopSecret [32]byte
	if hsp, ok := node.(HopSecretProvider); ok && hsp.HopSecret() != ([32]byte{}) {
		localHopSecret = hsp.HopSecret()
	} else {
		if _, err := cryptorand.Read(localHopSecret[:]); err != nil {
			logrus.WithError(err).Error("failed to generate random local hop secret")
		}
	}

	return func(c *fiber.Ctx) error {
		// Never proxy health, metadata, static assets (/static/*, /favicon.ico), root redirect, or local cluster status/step-down.
		// Note: Server-rendered dynamic UI pages (*.html), cluster membership modification routes
		// (/api/v1/cluster/join and /api/v1/cluster/remove), and /metrics route through cluster consensus so that
		// followers reverse-proxy to the leader and leader performs read barriers against SQLite.
		cleanPath := path.Clean(c.Path())
		if !strings.HasPrefix(cleanPath, "/") {
			cleanPath = "/" + cleanPath
		}
		if cleanPath == "/" || cleanPath == "/favicon.ico" ||
			cleanPath == "/static" || strings.HasPrefix(cleanPath, "/static/") ||
			cleanPath == "/healthz" || cleanPath == "/readyz" || cleanPath == "/meta" ||
			cleanPath == "/api/v1/cluster/status" ||
			cleanPath == "/api/v1/cluster/step-down" {
			return c.Next()
		}

		// Leader processing:
		if node.IsLeader() {
			if c.Method() == fiber.MethodGet || c.Method() == fiber.MethodHead {
				if bc, ok := node.(BarrierChecker); ok {
					if err := bc.Barrier(c.UserContext()); err != nil {
						if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
							return fiber.NewError(fiber.StatusRequestTimeout, "client request cancelled or timed out")
						}
						logrus.WithError(err).Warn("cluster quorum lost during read barrier")
						c.Set("Retry-After", "1")
						return fiber.NewError(fiber.StatusServiceUnavailable, "cluster quorum lost")
					}
				}
			}
			return c.Next()
		}

		// Follower processing:
		nodeID := ""
		if ni, ok := node.(NodeIdentifier); ok {
			nodeID = ni.NodeID()
		}
		fwdID := nodeID
		if fwdID == "" {
			fwdID = instanceID
		}

		// Loop detection: check if request already traversed this node.
		forwardedBy := c.Get(HeaderForwardedBy)
		forwardedSig := c.Get(HeaderForwardedSig)

		if forwardedBy == "" && forwardedSig != "" {
			c.Request().Header.Del(HeaderForwardedSig)
			forwardedSig = ""
		}

		validSigCount := 0
		ttlSec := int64(ForwardHopTTL / time.Second)
		now := time.Now().Unix()
		if forwardedSig != "" {
			for _, entry := range strings.Split(forwardedSig, ",") {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					continue
				}
				lastColon := strings.LastIndex(entry, ":")
				if lastColon == -1 {
					continue
				}
				sigVal := strings.TrimSpace(entry[lastColon+1:])
				prefix := entry[:lastColon]
				secondLastColon := strings.LastIndex(prefix, ":")
				if secondLastColon != -1 {
					nodePart := strings.TrimSpace(prefix[:secondLastColon])
					tsStr := strings.TrimSpace(prefix[secondLastColon+1:])
					if ts, err := strconv.ParseInt(tsStr, 10, 64); err == nil {
						if (now-ts <= ttlSec) && (ts-now <= 5) && sigVal != "" && nodePart != "" {
							expectedSig := ComputeHopSignature(localHopSecret, nodePart, ts)
							if subtle.ConstantTimeCompare([]byte(sigVal), []byte(expectedSig)) == 1 {
								validSigCount++
							}
						}
					}
				} else {
					// Fallback to legacy nodeID:sig format without timestamp
					nodePart := strings.TrimSpace(prefix)
					if nodePart != "" && sigVal != "" {
						legacyMac := hmac.New(sha256.New, localHopSecret[:])
						legacyMac.Write([]byte(nodePart))
						legacyExpectedSig := hex.EncodeToString(legacyMac.Sum(nil))
						if subtle.ConstantTimeCompare([]byte(sigVal), []byte(legacyExpectedSig)) == 1 {
							validSigCount++
						}
					}
				}
			}
		}

		if forwardedBy != "" {
			rawHops := strings.Split(forwardedBy, ",")
			hopCount := 0
			for _, part := range rawHops {
				if strings.TrimSpace(part) != "" {
					hopCount++
				}
			}
			// Hop limit enforcement (maxForwardHops):
			// We only trigger loop detection based on hopCount if validSigCount also meets or exceeds
			// maxForwardHops. Requiring valid signatures prevents unauthenticated external clients from
			// spoofing X-Grantory-Forwarded-By headers to cause a denial-of-service (premature 508).
			//
			// With --raft-cluster-secret configured, all nodes share the hop secret, enabling cluster-wide
			// hop verification where any intermediate node can authenticate hops from other nodes and enforce
			// this multi-node threshold.
			//
			// Even in clusters without --raft-cluster-secret (where nodes use ephemeral random secrets and
			// cannot verify foreign hops), cycle prevention remains mathematically guaranteed: any real cycle
			// must eventually return to a node that already handled the request, where self-loop detection
			// (hasNode && validLoop below) will cryptographically recognize its own signature and reject the request.
			if hopCount >= maxForwardHops && validSigCount >= maxForwardHops {
				return fiber.NewError(fiber.StatusLoopDetected, "maximum forward hops exceeded")
			}

			var cleanedHops []string
			hasNode := false
			for _, part := range rawHops {
				trimmed := strings.TrimSpace(part)
				if trimmed == "" {
					continue
				}
				if trimmed == fwdID {
					hasNode = true
				} else {
					cleanedHops = append(cleanedHops, trimmed)
				}
			}

			if hasNode {
				validLoop := false
				var cleanedSigs []string
				if forwardedSig != "" {
					for _, entry := range strings.Split(forwardedSig, ",") {
						entry = strings.TrimSpace(entry)
						if entry == "" {
							continue
						}
						prefix := fwdID + ":"
						if strings.HasPrefix(entry, prefix) {
							rest := strings.TrimPrefix(entry, prefix)
							if colonIdx := strings.Index(rest, ":"); colonIdx != -1 {
								tsStr := strings.TrimSpace(rest[:colonIdx])
								sigVal := strings.TrimSpace(rest[colonIdx+1:])
								if ts, err := strconv.ParseInt(tsStr, 10, 64); err == nil {
									expectedSig := ComputeHopSignature(localHopSecret, fwdID, ts)
									// Self-loop verification intentionally does not check TTL expiration:
									// The hop signature is generated using this node's private, in-memory 32-byte localHopSecret
									// and cannot be forged by external clients or peers. If an in-flight request takes > 45s
									// (e.g. under high latency or multi-hop topologies) before cycling back to this node,
									// stripping the signature would reset the cycle counter and cause the request to loop indefinitely.
									// Therefore, authentic self-signatures always trigger loop detection (HTTP 508) regardless of timestamp age.
									if subtle.ConstantTimeCompare([]byte(sigVal), []byte(expectedSig)) == 1 {
										validLoop = true
									}
									continue
								}
							}
							// Fallback to legacy nodeID:sig format without timestamp
							sigVal := strings.TrimSpace(rest)
							legacyMac := hmac.New(sha256.New, localHopSecret[:])
							legacyMac.Write([]byte(fwdID))
							legacyExpectedSig := hex.EncodeToString(legacyMac.Sum(nil))
							if subtle.ConstantTimeCompare([]byte(sigVal), []byte(legacyExpectedSig)) == 1 {
								validLoop = true
							}
						} else {
							cleanedSigs = append(cleanedSigs, entry)
						}
					}
				}

				if validLoop {
					return fiber.NewError(fiber.StatusLoopDetected, "forwarding loop detected")
				}

				// Spoofed header detected: strip fwdID from HeaderForwardedBy and HeaderForwardedSig.
				if len(cleanedHops) == 0 {
					c.Request().Header.Del(HeaderForwardedBy)
					c.Request().Header.Del(HeaderForwardedSig)
				} else {
					c.Request().Header.Set(HeaderForwardedBy, strings.Join(cleanedHops, ", "))
					c.Request().Header.Set(HeaderForwardedSig, strings.Join(cleanedSigs, ", "))
				}
			}
		}

		// Resolve leader HTTP address.
		leaderAddr := ""
		if lhr, ok := node.(LeaderHTTPAddrReporter); ok {
			leaderAddr = lhr.LeaderHTTPAddr()
		} else {
			leaderAddr = node.LeaderAddr()
		}
		leaderAddr = strings.TrimSpace(leaderAddr)
		if leaderAddr == "" {
			c.Set("Retry-After", "1")
			if strings.TrimSpace(node.LeaderAddr()) == "" {
				return fiber.NewError(fiber.StatusServiceUnavailable, "no leader currently elected")
			}
			logrus.Warn("cluster proxy: raft leader elected but leader HTTP address is not yet available")
			return fiber.NewError(fiber.StatusServiceUnavailable, "leader HTTP address unavailable")
		}

		// Set forwarding and signature headers to prevent loops.
		now = time.Now().Unix()
		sig := ComputeHopSignature(localHopSecret, fwdID, now)
		if prev := strings.TrimSpace(c.Get(HeaderForwardedBy)); prev != "" {
			c.Request().Header.Set(HeaderForwardedBy, prev+", "+fwdID)
		} else {
			c.Request().Header.Set(HeaderForwardedBy, fwdID)
		}

		sigEntry := fmt.Sprintf("%s:%d:%s", fwdID, now, sig)
		if prevSig := strings.TrimSpace(c.Get(HeaderForwardedSig)); prevSig != "" {
			c.Request().Header.Set(HeaderForwardedSig, prevSig+", "+sigEntry)
		} else {
			c.Request().Header.Set(HeaderForwardedSig, sigEntry)
		}

		// Target URL construction.
		scheme := "http"
		if tr, ok := node.(TLSReporter); ok && tr.IsTLS() {
			scheme = "https"
		}

		target := leaderAddr
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = scheme + "://" + target
		}
		origURL := c.OriginalURL()
		if strings.HasPrefix(origURL, "http://") || strings.HasPrefix(origURL, "https://") {
			if idx := strings.Index(origURL, "://"); idx != -1 {
				rest := origURL[idx+3:]
				if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
					origURL = rest[slashIdx:]
				} else if qIdx := strings.Index(rest, "?"); qIdx != -1 {
					origURL = "/" + rest[qIdx:]
				} else {
					origURL = "/"
				}
			}
		}
		if !strings.HasPrefix(origURL, "/") {
			origURL = "/" + origURL
		}
		target = strings.TrimRight(target, "/") + origURL

		// Execute proxy to leader.
		var proxyErr error
		if client != nil {
			proxyErr = proxy.Do(c, target, client)
		} else {
			proxyErr = proxy.Do(c, target)
		}
		if proxyErr != nil {
			c.Set("Retry-After", "1")
			logrus.WithError(proxyErr).WithField("leader", leaderAddr).WithField("target", target).Warn("proxy to leader failed")
			return fiber.NewError(fiber.StatusBadGateway, "failed to proxy request to cluster leader")
		}
		return nil
	}
}
