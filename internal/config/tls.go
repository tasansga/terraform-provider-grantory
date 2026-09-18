package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// BuildClusterTLSConfig builds a shared tls.Config for cluster client operations.
func BuildClusterTLSConfig(cfg Config) (*tls.Config, error) {
	if (cfg.RaftCertFile != "") != (cfg.RaftKeyFile != "") {
		return nil, fmt.Errorf("both raft-cert-file and raft-key-file must be specified (cert: %q, key: %q)", cfg.RaftCertFile, cfg.RaftKeyFile)
	}
	if cfg.TLSKey != "" && cfg.TLSCert == "" {
		return nil, fmt.Errorf("tls-key specified without tls-cert (key: %q)", cfg.TLSKey)
	}

	rootPool, err := x509.SystemCertPool()
	if err != nil || rootPool == nil {
		rootPool = x509.NewCertPool()
	}

	if cfg.RaftCAFile != "" {
		caData, err := os.ReadFile(cfg.RaftCAFile)
		if err != nil {
			return nil, fmt.Errorf("read raft CA file: %w", err)
		}
		if !rootPool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to append certs from raft CA file %q", cfg.RaftCAFile)
		}
	}

	// In development and test environments with self-signed leaf certificates, adding TLSCert
	// directly to the root pool allows followers to trust peer HTTPS endpoints without a dedicated CA.
	// In production deployments using custom intermediate or enterprise root CAs, operators must
	// specify the CA certificate bundle via --raft-ca-file to ensure proper intra-cluster TLS verification.
	if cfg.TLSCert != "" {
		certData, err := os.ReadFile(cfg.TLSCert)
		if err != nil {
			return nil, fmt.Errorf("read TLS cert file: %w", err)
		}
		if !rootPool.AppendCertsFromPEM(certData) {
			return nil, fmt.Errorf("failed to append certs from TLS cert file %q", cfg.TLSCert)
		}
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootPool,
	}
	if cfg.RaftTLSServerName != "" {
		tlsConfig.ServerName = cfg.RaftTLSServerName
	}

	if cfg.RaftCertFile != "" && cfg.RaftKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.RaftCertFile, cfg.RaftKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load raft client keypair: %w", err)
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	} else if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load TLS client keypair: %w", err)
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}

	return tlsConfig, nil
}
