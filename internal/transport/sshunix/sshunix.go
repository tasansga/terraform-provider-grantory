package sshunix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	// DefaultTimeout is used when Options.Timeout is unset or invalid.
	DefaultTimeout = 10 * time.Second
)

// Options configures SSH-to-unix-socket transport.
type Options struct {
	Address         string
	User            string
	PrivateKeyPath  string
	UseAgent        bool
	AgentSocketPath string
	KnownHostsPath  string
	InsecureHostKey bool
	SocketPath      string
	Timeout         time.Duration

	BastionAddress        string
	BastionUser           string
	BastionPrivateKeyPath string
}

// Transport is an HTTP RoundTripper that reaches a remote unix socket via SSH.
type Transport struct {
	base   *http.Transport
	dialer *dialer
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.base.RoundTrip(req)
}

// CloseIdleConnections closes idle HTTP and SSH connections.
func (t *Transport) CloseIdleConnections() {
	t.base.CloseIdleConnections()
	t.dialer.close()
}

// NewTransport creates an HTTP transport that tunnels requests through SSH
// and dials a remote unix socket.
func NewTransport(opts Options) (*Transport, error) {
	cfg, err := newDialerConfig(opts)
	if err != nil {
		return nil, err
	}
	d := &dialer{config: cfg}
	base := &http.Transport{
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &Transport{base: base, dialer: d}, nil
}

// NewHTTPClient creates an HTTP client backed by NewTransport.
func NewHTTPClient(opts Options) (*http.Client, error) {
	tr, err := NewTransport(opts)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: tr}, nil
}

type dialerConfig struct {
	timeout    time.Duration
	socketPath string

	targetAddress string
	targetUser    string
	targetKeyPath string

	bastionAddress string
	bastionUser    string
	bastionKeyPath string

	useAgent        bool
	agentSocketPath string

	targetHostKeyCallback  ssh.HostKeyCallback
	bastionHostKeyCallback ssh.HostKeyCallback
}

func newDialerConfig(opts Options) (*dialerConfig, error) {
	address := strings.TrimSpace(opts.Address)
	if address == "" {
		return nil, fmt.Errorf("ssh address is required")
	}
	user := strings.TrimSpace(opts.User)
	if user == "" {
		return nil, fmt.Errorf("ssh user is required")
	}
	privateKeyPath := strings.TrimSpace(opts.PrivateKeyPath)
	socketPath := strings.TrimSpace(opts.SocketPath)
	if socketPath == "" {
		return nil, fmt.Errorf("ssh socket path is required")
	}
	if privateKeyPath == "" && !opts.UseAgent {
		return nil, fmt.Errorf("at least one SSH auth method is required: private key path or SSH agent")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	targetHostKeyCallback, err := hostKeyCallback(
		strings.TrimSpace(opts.KnownHostsPath),
		opts.InsecureHostKey,
	)
	if err != nil {
		return nil, fmt.Errorf("target host key policy: %w", err)
	}
	_, targetClosers, err := authMethods(
		privateKeyPath,
		opts.UseAgent,
		strings.TrimSpace(opts.AgentSocketPath),
	)
	if err != nil {
		return nil, fmt.Errorf("target auth: %w", err)
	}
	closeAll(targetClosers)

	bastionAddress := strings.TrimSpace(opts.BastionAddress)
	agentSocketPath := strings.TrimSpace(opts.AgentSocketPath)
	bastionUser := ""
	bastionKeyPath := ""
	var bastionHostKeyCallback ssh.HostKeyCallback
	if bastionAddress != "" {
		bastionUser = strings.TrimSpace(opts.BastionUser)
		if bastionUser == "" {
			bastionUser = user
		}
		bastionKeyPath = strings.TrimSpace(opts.BastionPrivateKeyPath)
		if bastionKeyPath == "" {
			bastionKeyPath = privateKeyPath
		}

		cb, cbErr := hostKeyCallback(
			strings.TrimSpace(opts.KnownHostsPath),
			opts.InsecureHostKey,
		)
		if cbErr != nil {
			return nil, fmt.Errorf("bastion host key policy: %w", cbErr)
		}
		bastionHostKeyCallback = cb
		_, bastionClosers, authErr := authMethods(
			bastionKeyPath,
			opts.UseAgent,
			agentSocketPath,
		)
		if authErr != nil {
			return nil, fmt.Errorf("bastion auth: %w", authErr)
		}
		closeAll(bastionClosers)
	}

	return &dialerConfig{
		timeout:                timeout,
		socketPath:             socketPath,
		targetAddress:          address,
		targetUser:             user,
		targetKeyPath:          privateKeyPath,
		bastionAddress:         bastionAddress,
		bastionUser:            bastionUser,
		bastionKeyPath:         bastionKeyPath,
		useAgent:               opts.UseAgent,
		agentSocketPath:        agentSocketPath,
		targetHostKeyCallback:  targetHostKeyCallback,
		bastionHostKeyCallback: bastionHostKeyCallback,
	}, nil
}

func (c *dialerConfig) buildClientConfigs() (target *ssh.ClientConfig, bastion *ssh.ClientConfig, closers []io.Closer, err error) {
	targetAuth, targetClosers, err := authMethods(c.targetKeyPath, c.useAgent, c.agentSocketPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("target auth: %w", err)
	}
	closers = append(closers, targetClosers...)
	target = &ssh.ClientConfig{
		User:            c.targetUser,
		Auth:            targetAuth,
		HostKeyCallback: c.targetHostKeyCallback,
		Timeout:         c.timeout,
	}

	if c.bastionAddress == "" {
		return target, nil, closers, nil
	}

	bastionAuth, bastionClosers, bastionErr := authMethods(c.bastionKeyPath, c.useAgent, c.agentSocketPath)
	if bastionErr != nil {
		closeAll(closers)
		return nil, nil, nil, fmt.Errorf("bastion auth: %w", bastionErr)
	}
	closers = append(closers, bastionClosers...)
	bastion = &ssh.ClientConfig{
		User:            c.bastionUser,
		Auth:            bastionAuth,
		HostKeyCallback: c.bastionHostKeyCallback,
		Timeout:         c.timeout,
	}
	return target, bastion, closers, nil
}

func hostKeyCallback(knownHostsPath string, insecure bool) (ssh.HostKeyCallback, error) {
	if insecure {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	if strings.TrimSpace(knownHostsPath) == "" {
		return nil, fmt.Errorf("known_hosts path is required unless insecure host key mode is enabled")
	}
	cb, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts from %q: %w", knownHostsPath, err)
	}
	return cb, nil
}

func authMethods(privateKeyPath string, useAgent bool, agentSocketPath string) ([]ssh.AuthMethod, []io.Closer, error) {
	methods := make([]ssh.AuthMethod, 0, 2)
	closers := make([]io.Closer, 0, 1)
	if privateKeyPath != "" {
		keyMethod, err := publicKeyAuth(privateKeyPath)
		if err != nil {
			return nil, nil, err
		}
		methods = append(methods, keyMethod)
	}
	if useAgent {
		socketPath := agentSocketPath
		if socketPath == "" {
			socketPath = strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
		}
		if socketPath == "" {
			return nil, nil, fmt.Errorf("SSH agent is enabled but no socket path is configured and SSH_AUTH_SOCK is empty")
		}

		agentConn, err := net.Dial("unix", socketPath)
		if err != nil {
			return nil, nil, fmt.Errorf("connect to SSH agent socket %q: %w", socketPath, err)
		}
		agentClient := agent.NewClient(agentConn)
		signers, err := agentClient.Signers()
		if err != nil {
			_ = agentConn.Close()
			return nil, nil, fmt.Errorf("read SSH agent signers from %q: %w", socketPath, err)
		}
		if len(signers) == 0 {
			_ = agentConn.Close()
			return nil, nil, fmt.Errorf("no SSH keys are loaded in agent at %q", socketPath)
		}
		methods = append(methods, ssh.PublicKeysCallback(agentClient.Signers))
		closers = append(closers, agentConn)
	}
	if len(methods) == 0 {
		return nil, nil, fmt.Errorf("no SSH auth methods configured")
	}
	return methods, closers, nil
}

func publicKeyAuth(privateKeyPath string) (ssh.AuthMethod, error) {
	raw, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", privateKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse private key %q: %w", privateKeyPath, err)
	}
	return ssh.PublicKeys(signer), nil
}

func closeAll(closers []io.Closer) {
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
}

type dialer struct {
	config *dialerConfig

	mu             sync.Mutex
	target         *ssh.Client
	bastion        *ssh.Client
	sessionClosers []io.Closer
}

func (d *dialer) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closeSessionsLocked()
}

func (d *dialer) closeSessionsLocked() {
	if d.target != nil {
		_ = d.target.Close()
		d.target = nil
	}
	if d.bastion != nil {
		_ = d.bastion.Close()
		d.bastion = nil
	}
	closeAll(d.sessionClosers)
	d.sessionClosers = nil
}

func (d *dialer) invalidate() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closeSessionsLocked()
}

func (d *dialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	network = strings.TrimSpace(network)
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("unsupported network %q", network)
	}
	ctx, cancel := context.WithTimeout(ctx, d.config.timeout)
	defer cancel()

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		client, err := d.getTargetClient(ctx)
		if err != nil {
			return nil, err
		}

		conn, err := dialViaSSHContext(ctx, client, "unix", d.config.socketPath)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		d.invalidate()
	}

	if lastErr == nil {
		lastErr = errors.New("unknown ssh dial error")
	}
	return nil, fmt.Errorf("dial remote unix socket %q via ssh: %w", d.config.socketPath, lastErr)
}

func (d *dialer) getTargetClient(ctx context.Context) (*ssh.Client, error) {
	d.mu.Lock()
	if d.target != nil {
		client := d.target
		d.mu.Unlock()
		return client, nil
	}
	d.mu.Unlock()

	var (
		targetClient *ssh.Client
		bastion      *ssh.Client
		closers      []io.Closer
		err          error
	)
	targetCfg, bastionCfg, closers, err := d.config.buildClientConfigs()
	if err != nil {
		return nil, err
	}

	if d.config.bastionAddress == "" {
		targetClient, err = connectSSH(ctx, d.config.targetAddress, targetCfg, nil)
		if err != nil {
			closeAll(closers)
			return nil, err
		}
	} else {
		bastion, err = connectSSH(ctx, d.config.bastionAddress, bastionCfg, nil)
		if err != nil {
			closeAll(closers)
			return nil, fmt.Errorf("connect bastion %q: %w", d.config.bastionAddress, err)
		}
		targetClient, err = connectSSH(ctx, d.config.targetAddress, targetCfg, bastion)
		if err != nil {
			_ = bastion.Close()
			closeAll(closers)
			return nil, fmt.Errorf("connect target %q via bastion: %w", d.config.targetAddress, err)
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	// Another goroutine may have connected while we were dialing.
	if d.target != nil {
		_ = targetClient.Close()
		if bastion != nil {
			_ = bastion.Close()
		}
		closeAll(closers)
		return d.target, nil
	}
	d.target = targetClient
	if bastion != nil {
		d.bastion = bastion
	}
	d.sessionClosers = closers
	return d.target, nil
}

func connectSSH(ctx context.Context, address string, cfg *ssh.ClientConfig, via *ssh.Client) (*ssh.Client, error) {
	var (
		rawConn net.Conn
		err     error
	)

	if via == nil {
		dialer := net.Dialer{}
		rawConn, err = dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, fmt.Errorf("dial %q: %w", address, err)
		}
	} else {
		rawConn, err = dialViaSSHContext(ctx, via, "tcp", address)
		if err != nil {
			return nil, fmt.Errorf("dial %q via existing ssh connection: %w", address, err)
		}
	}

	conn, chans, reqs, err := newClientConnContext(ctx, rawConn, address, cfg)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("ssh handshake with %q: %w", address, err)
	}
	return ssh.NewClient(conn, chans, reqs), nil
}

func dialViaSSHContext(ctx context.Context, c *ssh.Client, network, address string) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		conn, err := c.Dial(network, address)
		resCh <- result{conn: conn, err: err}
	}()

	select {
	case res := <-resCh:
		return res.conn, res.err
	case <-ctx.Done():
		_ = c.Close()
		return nil, ctx.Err()
	}
}

func newClientConnContext(
	ctx context.Context,
	conn net.Conn,
	address string,
	cfg *ssh.ClientConfig,
) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	type result struct {
		conn  ssh.Conn
		chans <-chan ssh.NewChannel
		reqs  <-chan *ssh.Request
		err   error
	}
	resCh := make(chan result, 1)
	go func() {
		sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, cfg)
		resCh <- result{conn: sshConn, chans: chans, reqs: reqs, err: err}
	}()

	select {
	case res := <-resCh:
		return res.conn, res.chans, res.reqs, res.err
	case <-ctx.Done():
		_ = conn.Close()
		return nil, nil, nil, ctx.Err()
	}
}
