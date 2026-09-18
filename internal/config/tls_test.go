package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

func generateTestCertAndKey(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Grantory Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "cert.pem")
	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	require.NoError(t, certOut.Close())

	keyPath = filepath.Join(dir, "key.pem")
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	require.NoError(t, err)
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}))
	require.NoError(t, keyOut.Close())

	return certPath, keyPath
}

func TestBuildClusterTLSConfig_Defaults(t *testing.T) {
	t.Parallel()

	tlsConfig, err := BuildClusterTLSConfig(Config{})
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	assert.NotNil(t, tlsConfig.RootCAs)
	assert.Empty(t, tlsConfig.ServerName)
	assert.Empty(t, tlsConfig.Certificates)
}

func TestBuildClusterTLSConfig_ServerName(t *testing.T) {
	t.Parallel()

	cfg := Config{
		RaftTLSServerName: "peer.grantory.internal",
	}
	tlsConfig, err := BuildClusterTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, "peer.grantory.internal", tlsConfig.ServerName)
}

func TestBuildClusterTLSConfig_RaftCAFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, _ := generateTestCertAndKey(t, dir)

	t.Run("valid CA file", func(t *testing.T) {
		cfg := Config{
			RaftCAFile: certPath,
		}
		tlsConfig, err := BuildClusterTLSConfig(cfg)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.NotNil(t, tlsConfig.RootCAs)
	})

	t.Run("non-existent RaftCAFile", func(t *testing.T) {
		cfg := Config{
			RaftCAFile: "/non/existent/ca.pem",
		}
		tlsConfig, err := BuildClusterTLSConfig(cfg)
		require.Error(t, err)
		assert.Nil(t, tlsConfig)
		assert.Contains(t, err.Error(), "read raft CA file")
	})

	t.Run("invalid PEM in RaftCAFile", func(t *testing.T) {
		invalidCA := filepath.Join(dir, "invalid-ca.pem")
		require.NoError(t, os.WriteFile(invalidCA, []byte("NOT-A-PEM-FILE"), 0o644))

		cfg := Config{
			RaftCAFile: invalidCA,
		}
		tlsConfig, err := BuildClusterTLSConfig(cfg)
		require.Error(t, err)
		assert.Nil(t, tlsConfig)
		assert.Contains(t, err.Error(), "failed to append certs from raft CA file")
	})
}

func TestBuildClusterTLSConfig_TLSCert(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, _ := generateTestCertAndKey(t, dir)

	t.Run("valid TLS cert", func(t *testing.T) {
		cfg := Config{
			TLSCert: certPath,
		}
		tlsConfig, err := BuildClusterTLSConfig(cfg)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.NotNil(t, tlsConfig.RootCAs)
	})

	t.Run("non-existent TLSCert", func(t *testing.T) {
		cfg := Config{
			TLSCert: "/non/existent/tls.crt",
		}
		tlsConfig, err := BuildClusterTLSConfig(cfg)
		require.Error(t, err)
		assert.Nil(t, tlsConfig)
		assert.Contains(t, err.Error(), "read TLS cert file")
	})

	t.Run("invalid PEM in TLSCert", func(t *testing.T) {
		invalidCert := filepath.Join(dir, "invalid-cert.pem")
		require.NoError(t, os.WriteFile(invalidCert, []byte("NOT-A-PEM-FILE"), 0o644))

		cfg := Config{
			TLSCert: invalidCert,
		}
		tlsConfig, err := BuildClusterTLSConfig(cfg)
		require.Error(t, err)
		assert.Nil(t, tlsConfig)
		assert.Contains(t, err.Error(), "failed to append certs from TLS cert file")
	})
}

func TestBuildClusterTLSConfig_ClientCertificates(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, keyPath := generateTestCertAndKey(t, dir)

	t.Run("loads client cert via RaftCertFile and RaftKeyFile", func(t *testing.T) {
		cfg := Config{
			RaftCertFile: certPath,
			RaftKeyFile:  keyPath,
		}
		tlsConfig, err := BuildClusterTLSConfig(cfg)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		assert.Len(t, tlsConfig.Certificates, 1)
	})

	t.Run("invalid raft client keypair", func(t *testing.T) {
		cfg := Config{
			RaftCertFile: "/non/existent/raft.crt",
			RaftKeyFile:  keyPath,
		}
		tlsConfig, err := BuildClusterTLSConfig(cfg)
		require.Error(t, err)
		assert.Nil(t, tlsConfig)
		assert.Contains(t, err.Error(), "load raft client keypair")
	})

	t.Run("loads client cert via TLSCert and TLSKey fallback", func(t *testing.T) {
		cfg := Config{
			TLSCert: certPath,
			TLSKey:  keyPath,
		}
		tlsConfig, err := BuildClusterTLSConfig(cfg)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		assert.Len(t, tlsConfig.Certificates, 1)
	})

	t.Run("invalid TLS client keypair fallback", func(t *testing.T) {
		cfg := Config{
			TLSCert: certPath,
			TLSKey:  "/non/existent/tls.key",
		}
		tlsConfig, err := BuildClusterTLSConfig(cfg)
		require.Error(t, err)
		assert.Nil(t, tlsConfig)
		assert.Contains(t, err.Error(), "load TLS client keypair")
	})
}

func TestBuildClusterTLSConfig_PartialKeypairs(t *testing.T) {
	t.Parallel()

	t.Run("raft-cert-file without raft-key-file", func(t *testing.T) {
		cfg := Config{
			RaftCertFile: "/some/cert.pem",
		}
		tlsConfig, err := BuildClusterTLSConfig(cfg)
		require.Error(t, err)
		assert.Nil(t, tlsConfig)
		assert.Equal(t, `both raft-cert-file and raft-key-file must be specified (cert: "/some/cert.pem", key: "")`, err.Error())
	})

	t.Run("raft-key-file without raft-cert-file", func(t *testing.T) {
		cfg := Config{
			RaftKeyFile: "/some/key.pem",
		}
		tlsConfig, err := BuildClusterTLSConfig(cfg)
		require.Error(t, err)
		assert.Nil(t, tlsConfig)
		assert.Equal(t, `both raft-cert-file and raft-key-file must be specified (cert: "", key: "/some/key.pem")`, err.Error())
	})

	t.Run("tls-key without tls-cert", func(t *testing.T) {
		cfg := Config{
			TLSKey: "/some/tls.key",
		}
		tlsConfig, err := BuildClusterTLSConfig(cfg)
		require.Error(t, err)
		assert.Nil(t, tlsConfig)
		assert.Equal(t, `tls-key specified without tls-cert (key: "/some/tls.key")`, err.Error())
	})
}

func TestBuildClusterTLSConfig_NoErrorLogging(t *testing.T) {
	hook := logtest.NewGlobal()
	defer hook.Reset()

	cfg := Config{
		RaftCAFile: "/non/existent/ca.pem",
	}
	_, err := BuildClusterTLSConfig(cfg)
	require.Error(t, err)
	assert.Empty(t, hook.Entries, "BuildClusterTLSConfig should not log errors; callers are responsible for logging")
}
