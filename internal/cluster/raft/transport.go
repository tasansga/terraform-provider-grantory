package raft

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	hashiraft "github.com/hashicorp/raft"
	"github.com/sirupsen/logrus"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
)

var _ hashiraft.StreamLayer = (*raftStreamLayer)(nil)

type customAddr struct {
	network string
	str     string
}

func (a *customAddr) Network() string { return a.network }
func (a *customAddr) String() string  { return a.str }

type raftStreamLayer struct {
	listener      net.Listener
	advertiseAddr net.Addr
	clientTLS     *tls.Config
}

func (s *raftStreamLayer) Accept() (net.Conn, error) {
	return s.listener.Accept()
}

func (s *raftStreamLayer) Close() error {
	return s.listener.Close()
}

func (s *raftStreamLayer) Addr() net.Addr {
	return s.advertiseAddr
}

func (s *raftStreamLayer) Dial(address hashiraft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	if s.clientTLS != nil {
		return tls.DialWithDialer(dialer, "tcp", string(address), s.clientTLS)
	}
	return dialer.Dial("tcp", string(address))
}

// NewTransport configures a raft.NetworkTransport listening on cfg.RaftBind
// (advertising cfg.RaftAdvertise), with optional mTLS if cfg.RaftCAFile,
// cfg.RaftCertFile, and cfg.RaftKeyFile are set.
func NewTransport(cfg config.Config) (*hashiraft.NetworkTransport, error) {
	stream, err := newStreamLayer(cfg)
	if err != nil {
		return nil, err
	}
	return hashiraft.NewNetworkTransport(stream, 3, 10*time.Second, newRaftLogWriter(logrus.WithField("component", "raft"), logrus.InfoLevel)), nil
}

func newStreamLayer(cfg config.Config) (*raftStreamLayer, error) {
	if cfg.RaftBind == "" {
		return nil, errors.New("raft bind address must not be empty")
	}

	hasCA := cfg.RaftCAFile != ""
	hasCert := cfg.RaftCertFile != ""
	hasKey := cfg.RaftKeyFile != ""

	var serverTLS *tls.Config
	var clientTLS *tls.Config

	if (hasCA || hasCert || hasKey) && (!hasCA || !hasCert || !hasKey) {
		return nil, errors.New("raft TLS requires all of --raft-ca-file, --raft-cert-file, and --raft-key-file to be set")
	}

	if hasCA && hasCert && hasKey {

		cert, err := tls.LoadX509KeyPair(cfg.RaftCertFile, cfg.RaftKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load raft cert and key: %w", err)
		}

		caPEM, err := os.ReadFile(cfg.RaftCAFile)
		if err != nil {
			return nil, fmt.Errorf("read raft ca file: %w", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificates from %s", cfg.RaftCAFile)
		}

		serverTLS = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    caPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS12,
		}

		clientTLS = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caPool,
			MinVersion:   tls.VersionTLS12,
		}
		// When Raft peers connect over IP addresses (common in overlay networks or default configurations),
		// Go's crypto/tls verification checks peer certificate Subject Alternative Names (SANs) against the dialed host.
		// If peer certificates contain DNS SANs rather than IP SANs, setting ServerName via cfg.RaftTLSServerName
		// ensures TLS certificate verification succeeds against the expected DNS SAN instead of failing on the dialed IP.
		if cfg.RaftTLSServerName != "" {
			clientTLS.ServerName = cfg.RaftTLSServerName
		}
	}

	var listener net.Listener
	if serverTLS != nil {
		tcpListener, err := net.Listen("tcp", cfg.RaftBind)
		if err != nil {
			return nil, fmt.Errorf("listen on %s: %w", cfg.RaftBind, err)
		}
		listener = tls.NewListener(tcpListener, serverTLS)
	} else {
		var err error
		listener, err = net.Listen("tcp", cfg.RaftBind)
		if err != nil {
			return nil, fmt.Errorf("listen on %s: %w", cfg.RaftBind, err)
		}
	}

	var advertiseAddr net.Addr
	if cfg.RaftAdvertise != "" {
		adv := cfg.RaftAdvertise
		if _, _, err := net.SplitHostPort(adv); err != nil {
			defPort := defaultRaftPort(cfg)
			if (defPort == "" || defPort == "0") && listener != nil {
				if _, lport, lerr := net.SplitHostPort(listener.Addr().String()); lerr == nil {
					defPort = lport
				}
			}
			if defPort != "" {
				adv = net.JoinHostPort(strings.Trim(adv, "[]"), defPort)
			}
		}
		if isDNSHostname(adv) {
			advertiseAddr = &customAddr{network: "tcp", str: adv}
		} else if resolved, err := net.ResolveTCPAddr("tcp", adv); err == nil {
			advertiseAddr = resolved
		} else {
			advertiseAddr = &customAddr{network: "tcp", str: adv}
		}
	} else {
		advertiseAddr = listener.Addr()
	}

	return &raftStreamLayer{
		listener:      listener,
		advertiseAddr: advertiseAddr,
		clientTLS:     clientTLS,
	}, nil
}
