package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
)

func TestConfigureProviderValidServer(t *testing.T) {
	t.Parallel()

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		serverAttr: "https://example.com",
	})

	client, diags := configureProvider(context.Background(), data)
	assert.False(t, diags.HasError(), "expected no diagnostics")

	c, ok := client.(*grantoryClient)
	assert.True(t, ok, "expected grantoryClient")
	assert.Equal(t, "https://example.com", c.BaseAddress(), "base address should match server URI")
}

func TestConfigureProviderInvalidServer(t *testing.T) {
	t.Parallel()

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		serverAttr: "ftp://example.com",
	})

	client, diags := configureProvider(context.Background(), data)
	assert.Nil(t, client, "expected nil client for invalid server")
	assert.True(t, diags.HasError(), "expected diagnostics for invalid server")

	found := false
	for _, diag := range diags {
		if diag.Summary == "unsupported grantory server scheme" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected unsupported scheme diagnostic")
}

func TestParseServerURLMissingHost(t *testing.T) {
	t.Parallel()

	_, diags := parseServerURL("http:///")
	assert.True(t, diags.HasError(), "missing host should produce diagnostic")
}

func TestConfigureProviderConflictingAuth(t *testing.T) {
	t.Parallel()

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		serverAttr:   "https://example.com",
		tokenAttr:    "token",
		userAttr:     "user",
		passwordAttr: "pass",
	})

	client, diags := configureProvider(context.Background(), data)
	assert.Nil(t, client, "expected nil client when auth conflicts")
	assert.True(t, diags.HasError(), "expected diag for conflicting auth")
}

func TestConfigureProviderIncompleteBasicAuth(t *testing.T) {
	t.Parallel()

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		serverAttr: "https://example.com",
		userAttr:   "user",
	})

	client, diags := configureProvider(context.Background(), data)
	assert.Nil(t, client, "expected nil client when password missing")
	assert.True(t, diags.HasError(), "expected diag for incomplete auth")
}

func TestGrantoryClientBaseAddressEmpty(t *testing.T) {
	t.Parallel()

	var c *grantoryClient
	assert.Equal(t, "", c.BaseAddress(), "nil client should return empty base address")
}

func TestConfigureProviderDefaultServer(t *testing.T) {
	t.Parallel()

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{})

	client, diags := configureProvider(context.Background(), data)
	assert.False(t, diags.HasError(), "expected no diagnostics")

	c, ok := client.(*grantoryClient)
	assert.True(t, ok, "expected grantoryClient")
	assert.Equal(t, defaultServerURL, c.BaseAddress(), "base address should use default server URL")
}

func TestConfigureProviderValidSSH(t *testing.T) {
	t.Parallel()

	privateKeyPath := writeTestPrivateKey(t)

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		sshAddressAttr:         "127.0.0.1:1",
		sshUserAttr:            "grantory",
		sshPrivateKeyPathAttr:  privateKeyPath,
		sshSocketPathAttr:      "/tmp/grantory.sock",
		sshInsecureHostKeyAttr: true,
		sshTimeoutSecondsAttr:  1,
	})

	client, diags := configureProvider(context.Background(), data)
	assert.False(t, diags.HasError(), "expected no diagnostics")

	c, ok := client.(*grantoryClient)
	assert.True(t, ok, "expected grantoryClient")
	assert.Equal(t, sshModeBaseURL, c.BaseAddress(), "SSH mode should use synthetic HTTP base URL")
	assert.NotNil(t, c.HTTPClient(), "ssh mode should configure a custom HTTP client")
}

func TestConfigureProviderConflictingTransportModes(t *testing.T) {
	t.Parallel()

	privateKeyPath := writeTestPrivateKey(t)
	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		serverAttr:             "https://example.com",
		sshAddressAttr:         "127.0.0.1:22",
		sshUserAttr:            "grantory",
		sshPrivateKeyPathAttr:  privateKeyPath,
		sshSocketPathAttr:      "/tmp/grantory.sock",
		sshInsecureHostKeyAttr: true,
	})

	client, diags := configureProvider(context.Background(), data)
	assert.Nil(t, client, "expected nil client for conflicting transport modes")
	assert.True(t, diags.HasError(), "expected diagnostics for conflicting transport modes")

	found := false
	for _, d := range diags {
		if d.Summary == "conflicting transport settings" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected conflicting transport settings diagnostic")
}

func TestConfigureProviderSSHMissingRequiredFields(t *testing.T) {
	t.Parallel()

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		sshAddressAttr: "127.0.0.1:22",
	})

	client, diags := configureProvider(context.Background(), data)
	assert.Nil(t, client, "expected nil client for incomplete SSH config")
	assert.True(t, diags.HasError(), "expected diagnostics for incomplete SSH config")

	found := false
	for _, d := range diags {
		if d.Summary == "incomplete SSH transport configuration" {
			found = true
			assert.Contains(t, d.Detail, sshUserAttr)
			assert.Contains(t, d.Detail, sshUseAgentAttr)
			assert.Contains(t, d.Detail, sshSocketPathAttr)
			assert.Contains(t, d.Detail, sshKnownHostsPathAttr)
			break
		}
	}
	assert.True(t, found, "expected incomplete SSH transport configuration diagnostic")
}

func TestConfigureProviderValidSSHWithAgent(t *testing.T) {
	t.Parallel()

	agentSocketPath := startTestAgentSocket(t, true)

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		sshAddressAttr:         "127.0.0.1:1",
		sshUserAttr:            "grantory",
		sshUseAgentAttr:        true,
		sshAgentSocketPathAttr: agentSocketPath,
		sshSocketPathAttr:      "/tmp/grantory.sock",
		sshInsecureHostKeyAttr: true,
		sshTimeoutSecondsAttr:  1,
	})

	client, diags := configureProvider(context.Background(), data)
	assert.False(t, diags.HasError(), "expected no diagnostics")

	c, ok := client.(*grantoryClient)
	assert.True(t, ok, "expected grantoryClient")
	assert.Equal(t, sshModeBaseURL, c.BaseAddress(), "SSH mode should use synthetic HTTP base URL")
}

func TestConfigureProviderSSHAgentSocketImpliesAgent(t *testing.T) {
	t.Parallel()

	agentSocketPath := startTestAgentSocket(t, true)

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		sshAddressAttr:         "127.0.0.1:1",
		sshUserAttr:            "grantory",
		sshAgentSocketPathAttr: agentSocketPath,
		sshSocketPathAttr:      "/tmp/grantory.sock",
		sshInsecureHostKeyAttr: true,
		sshTimeoutSecondsAttr:  1,
	})

	client, diags := configureProvider(context.Background(), data)
	assert.False(t, diags.HasError(), "expected no diagnostics")
	assert.NotNil(t, client, "expected configured client")
}

func TestConfigureProviderSSHMissingAuthSources(t *testing.T) {
	t.Parallel()

	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		sshAddressAttr:         "127.0.0.1:22",
		sshUserAttr:            "grantory",
		sshSocketPathAttr:      "/tmp/grantory.sock",
		sshInsecureHostKeyAttr: true,
	})

	client, diags := configureProvider(context.Background(), data)
	assert.Nil(t, client, "expected nil client when key and agent are missing")
	assert.True(t, diags.HasError(), "expected diagnostics when key and agent are missing")

	found := false
	for _, d := range diags {
		if d.Summary == "incomplete SSH transport configuration" {
			found = true
			assert.Contains(t, d.Detail, sshUseAgentAttr)
			break
		}
	}
	assert.True(t, found, "expected key-or-agent requirement diagnostic")
}

func TestConfigureProviderSSHKnownHostsRequired(t *testing.T) {
	t.Parallel()

	privateKeyPath := writeTestPrivateKey(t)
	p := New()
	data := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		sshAddressAttr:        "127.0.0.1:22",
		sshUserAttr:           "grantory",
		sshPrivateKeyPathAttr: privateKeyPath,
		sshSocketPathAttr:     "/tmp/grantory.sock",
	})

	client, diags := configureProvider(context.Background(), data)
	assert.Nil(t, client, "expected nil client when known_hosts path is missing")
	assert.True(t, diags.HasError(), "expected diagnostics when known_hosts path is missing")

	found := false
	for _, d := range diags {
		if d.Summary == "incomplete SSH transport configuration" {
			found = true
			assert.Contains(t, d.Detail, sshKnownHostsPathAttr)
			break
		}
	}
	assert.True(t, found, "expected known_hosts requirement diagnostic")
}

func writeTestPrivateKey(t *testing.T) string {
	t.Helper()

	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rawKey),
	})
	path := filepath.Join(t.TempDir(), "id_rsa")
	require.NoError(t, os.WriteFile(path, pemKey, 0o600))
	return path
}

func startTestAgentSocket(t *testing.T, withKey bool) string {
	t.Helper()
	keyring := agent.NewKeyring()
	if withKey {
		rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: rawKey}))
	}

	path := filepath.Join(os.TempDir(), fmt.Sprintf("grantory-provider-agent-%d.sock", time.Now().UnixNano()))
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_ = agent.ServeAgent(keyring, c)
				_ = c.Close()
			}(conn)
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		_ = os.Remove(path)
	})
	return path
}
