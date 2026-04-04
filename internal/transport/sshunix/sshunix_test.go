package sshunix

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestNewHTTPClientDirect(t *testing.T) {
	t.Parallel()

	unixSocket := startUnixHTTPServer(t, `{"status":"ok","backend":"unix-direct"}`)
	clientSigner, privateKeyPath := writeClientKeyFile(t)
	target := startSSHServer(t, sshServerOptions{
		authorizedClientKey: clientSigner.PublicKey(),
	})

	knownHosts := writeKnownHostsFile(t, knownhosts.Line([]string{target.address()}, target.hostKey()))

	httpClient, err := NewHTTPClient(Options{
		Address:        target.address(),
		User:           "grantory",
		PrivateKeyPath: privateKeyPath,
		KnownHostsPath: knownHosts,
		SocketPath:     unixSocket,
		Timeout:        2 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if tr, ok := httpClient.Transport.(*Transport); ok {
			tr.CloseIdleConnections()
		}
	})

	resp := doReadyz(t, httpClient)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(body), `"backend":"unix-direct"`)
}

func TestNewHTTPClientBastion(t *testing.T) {
	t.Parallel()

	unixSocket := startUnixHTTPServer(t, `{"status":"ok","backend":"unix-bastion"}`)
	clientSigner, privateKeyPath := writeClientKeyFile(t)
	target := startSSHServer(t, sshServerOptions{
		authorizedClientKey: clientSigner.PublicKey(),
	})
	bastion := startSSHServer(t, sshServerOptions{
		authorizedClientKey: clientSigner.PublicKey(),
	})

	knownHosts := writeKnownHostsFile(
		t,
		knownhosts.Line([]string{target.address()}, target.hostKey()),
		knownhosts.Line([]string{bastion.address()}, bastion.hostKey()),
	)

	httpClient, err := NewHTTPClient(Options{
		Address:               target.address(),
		User:                  "grantory",
		PrivateKeyPath:        privateKeyPath,
		KnownHostsPath:        knownHosts,
		SocketPath:            unixSocket,
		Timeout:               2 * time.Second,
		BastionAddress:        bastion.address(),
		BastionUser:           "grantory",
		BastionPrivateKeyPath: privateKeyPath,
		InsecureHostKey:       false,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if tr, ok := httpClient.Transport.(*Transport); ok {
			tr.CloseIdleConnections()
		}
	})

	resp := doReadyz(t, httpClient)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(body), `"backend":"unix-bastion"`)
}

func TestNewHTTPClientDirectWithAgentOnly(t *testing.T) {
	t.Parallel()

	unixSocket := startUnixHTTPServer(t, `{"status":"ok","backend":"unix-agent"}`)
	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	clientSigner, err := ssh.NewSignerFromKey(rawKey)
	require.NoError(t, err)
	target := startSSHServer(t, sshServerOptions{
		authorizedClientKey: clientSigner.PublicKey(),
	})
	knownHosts := writeKnownHostsFile(t, knownhosts.Line([]string{target.address()}, target.hostKey()))
	agentSocket := startTestAgentSocketWithKeys(t, rawKey)

	httpClient, err := NewHTTPClient(Options{
		Address:         target.address(),
		User:            "grantory",
		UseAgent:        true,
		AgentSocketPath: agentSocket,
		KnownHostsPath:  knownHosts,
		SocketPath:      unixSocket,
		Timeout:         2 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if tr, ok := httpClient.Transport.(*Transport); ok {
			tr.CloseIdleConnections()
		}
	})

	resp := doReadyz(t, httpClient)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(body), `"backend":"unix-agent"`)

	// Ensure reconnect remains possible after CloseIdleConnections and invalidation
	// when using agent auth.
	if tr, ok := httpClient.Transport.(*Transport); ok {
		tr.CloseIdleConnections()
	}
	target.closeActiveConnections()
	resp2 := doReadyz(t, httpClient)
	require.NoError(t, resp2.Body.Close())
}

func TestKnownHostsValidation(t *testing.T) {
	t.Parallel()

	unixSocket := startUnixHTTPServer(t, `{"status":"ok","backend":"unused"}`)
	clientSigner, privateKeyPath := writeClientKeyFile(t)
	target := startSSHServer(t, sshServerOptions{
		authorizedClientKey: clientSigner.PublicKey(),
	})

	otherHostSigner := mustHostSigner(t)
	wrongKnownHosts := writeKnownHostsFile(t, knownhosts.Line([]string{target.address()}, otherHostSigner.PublicKey()))

	httpClient, err := NewHTTPClient(Options{
		Address:        target.address(),
		User:           "grantory",
		PrivateKeyPath: privateKeyPath,
		KnownHostsPath: wrongKnownHosts,
		SocketPath:     unixSocket,
		Timeout:        time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if tr, ok := httpClient.Transport.(*Transport); ok {
			tr.CloseIdleConnections()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://grantory/readyz", nil)
	require.NoError(t, err)
	_, err = httpClient.Do(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "knownhosts")
}

func TestReconnectAfterStaleSSHConnection(t *testing.T) {
	t.Parallel()

	unixSocket := startUnixHTTPServer(t, `{"status":"ok","backend":"reconnect"}`)
	clientSigner, privateKeyPath := writeClientKeyFile(t)
	target := startSSHServer(t, sshServerOptions{
		authorizedClientKey: clientSigner.PublicKey(),
	})
	knownHosts := writeKnownHostsFile(t, knownhosts.Line([]string{target.address()}, target.hostKey()))

	httpClient, err := NewHTTPClient(Options{
		Address:        target.address(),
		User:           "grantory",
		PrivateKeyPath: privateKeyPath,
		KnownHostsPath: knownHosts,
		SocketPath:     unixSocket,
		Timeout:        2 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if tr, ok := httpClient.Transport.(*Transport); ok {
			tr.CloseIdleConnections()
		}
	})

	resp1 := doReadyz(t, httpClient)
	require.NoError(t, resp1.Body.Close())
	target.closeActiveConnections()
	resp2 := doReadyz(t, httpClient)
	require.NoError(t, resp2.Body.Close())
}

func TestDialTimeout(t *testing.T) {
	t.Parallel()

	hangAddr := startHangingTCPListener(t)
	clientSigner, privateKeyPath := writeClientKeyFile(t)
	_ = clientSigner

	httpClient, err := NewHTTPClient(Options{
		Address:         hangAddr,
		User:            "grantory",
		PrivateKeyPath:  privateKeyPath,
		InsecureHostKey: true,
		SocketPath:      "/tmp/not-used.sock",
		Timeout:         120 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if tr, ok := httpClient.Transport.(*Transport); ok {
			tr.CloseIdleConnections()
		}
	})

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://grantory/readyz", nil)
	require.NoError(t, err)
	_, err = httpClient.Do(req)
	require.Error(t, err)
	require.Less(t, time.Since(start), 2*time.Second)
}

func TestNewTransportValidation(t *testing.T) {
	_, err := NewTransport(Options{})
	require.Error(t, err)

	_, err = NewTransport(Options{
		Address:        "127.0.0.1:22",
		User:           "u",
		PrivateKeyPath: "/nope",
		SocketPath:     "/tmp/grantory.sock",
	})
	require.Error(t, err)

	t.Setenv("SSH_AUTH_SOCK", "")
	_, err = NewTransport(Options{
		Address:         "127.0.0.1:22",
		User:            "u",
		UseAgent:        true,
		InsecureHostKey: true,
		SocketPath:      "/tmp/grantory.sock",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "SSH_AUTH_SOCK")

	emptyAgentSocket := startTestAgentSocket(t, false)
	_, err = NewTransport(Options{
		Address:         "127.0.0.1:22",
		User:            "u",
		UseAgent:        true,
		AgentSocketPath: emptyAgentSocket,
		InsecureHostKey: true,
		SocketPath:      "/tmp/grantory.sock",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no SSH keys are loaded")
}

func doReadyz(t *testing.T, httpClient *http.Client) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://grantory/readyz", nil)
	require.NoError(t, err)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	return resp
}

func startUnixHTTPServer(t *testing.T, body string) string {
	t.Helper()
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("grantory-%d.sock", time.Now().UnixNano()))
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Shutdown(context.Background())
		_ = listener.Close()
		_ = os.Remove(socketPath)
	})
	return socketPath
}

type sshServerOptions struct {
	authorizedClientKey ssh.PublicKey
}

type sshTestServer struct {
	listener net.Listener
	signer   ssh.Signer
	opts     sshServerOptions

	connsMu sync.Mutex
	conns   map[*ssh.ServerConn]struct{}
}

func startSSHServer(t *testing.T, opts sshServerOptions) *sshTestServer {
	t.Helper()

	s := &sshTestServer{
		opts:   opts,
		signer: mustHostSigner(t),
		conns:  make(map[*ssh.ServerConn]struct{}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s.listener = ln

	go s.serve(t)
	t.Cleanup(func() {
		_ = s.listener.Close()
	})
	return s
}

func (s *sshTestServer) address() string {
	return s.listener.Addr().String()
}

func (s *sshTestServer) hostKey() ssh.PublicKey {
	return s.signer.PublicKey()
}

func (s *sshTestServer) closeActiveConnections() {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	for conn := range s.conns {
		_ = conn.Close()
	}
}

func (s *sshTestServer) serve(t *testing.T) {
	t.Helper()

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if s.opts.authorizedClientKey == nil {
				return nil, fmt.Errorf("no authorized key configured")
			}
			if string(key.Marshal()) != string(s.opts.authorizedClientKey.Marshal()) {
				return nil, fmt.Errorf("unauthorized key")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(s.signer)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn, cfg)
	}
}

func (s *sshTestServer) handleConn(raw net.Conn, cfg *ssh.ServerConfig) {
	serverConn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		_ = raw.Close()
		return
	}
	s.connsMu.Lock()
	s.conns[serverConn] = struct{}{}
	s.connsMu.Unlock()
	defer func() {
		s.connsMu.Lock()
		delete(s.conns, serverConn)
		s.connsMu.Unlock()
	}()

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		switch newCh.ChannelType() {
		case "direct-streamlocal@openssh.com":
			go s.handleDirectStreamlocal(newCh, serverConn)
		case "direct-tcpip":
			go handleDirectTCPIP(newCh)
		default:
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

type streamLocalOpenMessage struct {
	SocketPath string
	Reserved0  string
	Reserved1  uint32
}

func (s *sshTestServer) handleDirectStreamlocal(newCh ssh.NewChannel, serverConn *ssh.ServerConn) {
	var msg streamLocalOpenMessage
	if err := ssh.Unmarshal(newCh.ExtraData(), &msg); err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, "invalid direct-streamlocal payload")
		return
	}

	targetConn, err := net.Dial("unix", msg.SocketPath)
	if err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newCh.Accept()
	if err != nil {
		_ = targetConn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	proxyConns(ch, targetConn)
}

type directTCPIPOpenMessage struct {
	RAddr string
	RPort uint32
	LAddr string
	LPort uint32
}

func handleDirectTCPIP(newCh ssh.NewChannel) {
	var msg directTCPIPOpenMessage
	if err := ssh.Unmarshal(newCh.ExtraData(), &msg); err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, "invalid direct-tcpip payload")
		return
	}

	target := net.JoinHostPort(msg.RAddr, strconv.Itoa(int(msg.RPort)))
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		_ = targetConn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	proxyConns(ch, targetConn)
}

func proxyConns(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
	_ = a.Close()
	_ = b.Close()
}

func writeClientKeyFile(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rawKey),
	})

	privateKeyPath := filepath.Join(t.TempDir(), "id_rsa")
	require.NoError(t, os.WriteFile(privateKeyPath, pemKey, 0o600))

	signer, err := ssh.NewSignerFromKey(rawKey)
	require.NoError(t, err)
	return signer, privateKeyPath
}

func mustHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

func writeKnownHostsFile(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	content := strings.Join(lines, "\n") + "\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func startHangingTCPListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() {
					_ = c.Close()
				}()
				time.Sleep(5 * time.Second)
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
	})
	return ln.Addr().String()
}

func startTestAgentSocket(t *testing.T, withKey bool) string {
	t.Helper()
	keyring := agent.NewKeyring()
	if withKey {
		rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: rawKey}))
	}

	path := filepath.Join(os.TempDir(), fmt.Sprintf("grantory-agent-%d.sock", time.Now().UnixNano()))
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

func startTestAgentSocketWithKeys(t *testing.T, keys ...interface{}) string {
	t.Helper()
	keyring := agent.NewKeyring()
	for _, key := range keys {
		require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: key}))
	}

	path := filepath.Join(os.TempDir(), fmt.Sprintf("grantory-agent-%d.sock", time.Now().UnixNano()))
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
