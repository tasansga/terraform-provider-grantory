package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

type cliBackend interface {
	ListHosts(context.Context) ([]storage.Host, error)
	ListRequests(context.Context) ([]storage.Request, error)
	ListRegisters(context.Context) ([]storage.Register, error)
	ListGrants(context.Context) ([]storage.Grant, error)
	GetHost(context.Context, string) (storage.Host, error)
	GetRequest(context.Context, string) (storage.Request, error)
	GetRegister(context.Context, string) (storage.Register, error)
	GetGrant(context.Context, string) (storage.Grant, error)
	DeleteHost(context.Context, string) error
	DeleteRequest(context.Context, string) error
	DeleteRegister(context.Context, string) error
	DeleteGrant(context.Context, string) error
	UpdateHostLabels(context.Context, string, map[string]string) error
}

type backendConfig struct {
	mode      backendMode
	serverURL string
	token     string
	user      string
	password  string
}

func resolveBackendConfig(cmd *cobra.Command) (backendConfig, error) {
	flags := cmd.Root().PersistentFlags()

	var rawMode string
	if flag := flags.Lookup(FlagBackend); flag != nil && flag.Changed {
		rawMode = flag.Value.String()
	} else {
		rawMode = os.Getenv(EnvBackend)
	}
	mode := strings.ToLower(strings.TrimSpace(rawMode))
	if mode == "" {
		mode = string(backendModeDirect)
	}

	var backendModeVal backendMode
	switch backendMode(strings.ToLower(strings.TrimSpace(mode))) {
	case backendModeDirect, backendModeAPI:
		backendModeVal = backendMode(mode)
	default:
		return backendConfig{}, fmt.Errorf("unknown backend %q", mode)
	}

	serverURL, err := flags.GetString(FlagServerURL)
	if err != nil {
		return backendConfig{}, err
	}
	if strings.TrimSpace(serverURL) == "" {
		serverURL = os.Getenv(EnvServerURL)
	}

	var rawToken string
	if flag := flags.Lookup(FlagToken); flag != nil && flag.Changed {
		rawToken = flag.Value.String()
	} else {
		rawToken = os.Getenv(EnvToken)
	}

	envUser := os.Getenv(EnvUser)
	envPassword := os.Getenv(EnvPassword)

	var rawUser string
	if flag := flags.Lookup(FlagUser); flag != nil && flag.Changed {
		rawUser = flag.Value.String()
	} else if envUser != "" && envPassword != "" {
		rawUser = envUser
	}

	var rawPassword string
	if flag := flags.Lookup(FlagPassword); flag != nil && flag.Changed {
		rawPassword = flag.Value.String()
	} else if envUser != "" && envPassword != "" {
		rawPassword = envPassword
	}

	token := strings.TrimSpace(rawToken)
	user := strings.TrimSpace(rawUser)
	password := strings.TrimSpace(rawPassword)

	if token != "" && (user != "" || password != "") {
		return backendConfig{}, fmt.Errorf("token/Bearer auth cannot be combined with user/password")
	}
	if (user != "") != (password != "") {
		return backendConfig{}, fmt.Errorf("both %s and %s must be provided together for basic auth", FlagUser, FlagPassword)
	}

	if backendModeVal == backendModeAPI && strings.TrimSpace(serverURL) == "" {
		return backendConfig{}, fmt.Errorf("server URL is required when backend=%s", backendModeAPI)
	}

	return backendConfig{
		mode:      backendModeVal,
		serverURL: strings.TrimSpace(serverURL),
		token:     token,
		user:      user,
		password:  password,
	}, nil
}

func newDirectBackend(store *storage.Store) cliBackend {
	return &directBackend{store: store}
}

type directBackend struct {
	store *storage.Store
}

func (d *directBackend) ListHosts(ctx context.Context) ([]storage.Host, error) {
	return d.store.ListHosts(ctx)
}

//go:noinline
func (d *directBackend) ListRequests(ctx context.Context) ([]storage.Request, error) {
	return d.store.ListRequests(ctx)
}

//go:noinline
func (d *directBackend) ListRegisters(ctx context.Context) ([]storage.Register, error) {
	return d.store.ListRegisters(ctx)
}

//go:noinline
func (d *directBackend) ListGrants(ctx context.Context) ([]storage.Grant, error) {
	return d.store.ListGrants(ctx)
}

func (d *directBackend) GetHost(ctx context.Context, id string) (storage.Host, error) {
	return d.store.GetHost(ctx, id)
}

//go:noinline
func (d *directBackend) GetRequest(ctx context.Context, id string) (storage.Request, error) {
	return d.store.GetRequest(ctx, id)
}

//go:noinline
func (d *directBackend) GetRegister(ctx context.Context, id string) (storage.Register, error) {
	return d.store.GetRegister(ctx, id)
}

//go:noinline
func (d *directBackend) GetGrant(ctx context.Context, id string) (storage.Grant, error) {
	return d.store.GetGrant(ctx, id)
}

func (d *directBackend) DeleteHost(ctx context.Context, id string) error {
	return d.store.DeleteHost(ctx, id)
}

//go:noinline
func (d *directBackend) DeleteRequest(ctx context.Context, id string) error {
	return d.store.DeleteRequest(ctx, id)
}

//go:noinline
func (d *directBackend) DeleteRegister(ctx context.Context, id string) error {
	return d.store.DeleteRegister(ctx, id)
}

//go:noinline
func (d *directBackend) DeleteGrant(ctx context.Context, id string) error {
	return d.store.DeleteGrant(ctx, id)
}

func (d *directBackend) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) error {
	return d.store.UpdateHostLabels(ctx, id, labels)
}

func newAPIBackend(namespace, rawURL, token, user, password string) (cliBackend, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, fmt.Errorf("server URL is required for API backend")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("server host is required")
	}

	return &apiBackend{
		baseURL:    u,
		httpClient: http.DefaultClient,
		namespace:  namespace,
		token:      strings.TrimSpace(token),
		user:       user,
		password:   password,
	}, nil
}

type apiBackend struct {
	baseURL    *url.URL
	httpClient *http.Client
	namespace  string
	token      string
	user       string
	password   string
}

type labelsPayload struct {
	Labels map[string]string `json:"labels"`
}

func (a *apiBackend) ListHosts(ctx context.Context) ([]storage.Host, error) {
	var hosts []storage.Host
	if err := a.doJSON(ctx, http.MethodGet, "/hosts", nil, &hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}

//go:noinline
func (a *apiBackend) ListRequests(ctx context.Context) ([]storage.Request, error) {
	var requests []storage.Request
	if err := a.doJSON(ctx, http.MethodGet, "/requests", nil, &requests); err != nil {
		return nil, err
	}
	return requests, nil
}

//go:noinline
func (a *apiBackend) ListRegisters(ctx context.Context) ([]storage.Register, error) {
	var registers []storage.Register
	if err := a.doJSON(ctx, http.MethodGet, "/registers", nil, &registers); err != nil {
		return nil, err
	}
	return registers, nil
}

//go:noinline
func (a *apiBackend) ListGrants(ctx context.Context) ([]storage.Grant, error) {
	var grants []storage.Grant
	if err := a.doJSON(ctx, http.MethodGet, "/grants", nil, &grants); err != nil {
		return nil, err
	}
	return grants, nil
}

//go:noinline
func (a *apiBackend) GetHost(ctx context.Context, id string) (storage.Host, error) {
	var host storage.Host
	if err := a.doJSON(ctx, http.MethodGet, fmt.Sprintf("/hosts/%s", id), nil, &host); err != nil {
		return storage.Host{}, err
	}
	return host, nil
}

//go:noinline
func (a *apiBackend) GetRequest(ctx context.Context, id string) (storage.Request, error) {
	var req storage.Request
	if err := a.doJSON(ctx, http.MethodGet, fmt.Sprintf("/requests/%s", id), nil, &req); err != nil {
		return storage.Request{}, err
	}
	return req, nil
}

//go:noinline
func (a *apiBackend) GetRegister(ctx context.Context, id string) (storage.Register, error) {
	var reg storage.Register
	if err := a.doJSON(ctx, http.MethodGet, fmt.Sprintf("/registers/%s", id), nil, &reg); err != nil {
		return storage.Register{}, err
	}
	return reg, nil
}

//go:noinline
func (a *apiBackend) GetGrant(ctx context.Context, id string) (storage.Grant, error) {
	var grant storage.Grant
	if err := a.doJSON(ctx, http.MethodGet, fmt.Sprintf("/grants/%s", id), nil, &grant); err != nil {
		return storage.Grant{}, err
	}
	return grant, nil
}

//go:noinline
func (a *apiBackend) DeleteHost(ctx context.Context, id string) error {
	return a.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/hosts/%s", id), nil, nil)
}

//go:noinline
func (a *apiBackend) DeleteRequest(ctx context.Context, id string) error {
	return a.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/requests/%s", id), nil, nil)
}

//go:noinline
func (a *apiBackend) DeleteRegister(ctx context.Context, id string) error {
	return a.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/registers/%s", id), nil, nil)
}

//go:noinline
func (a *apiBackend) DeleteGrant(ctx context.Context, id string) error {
	return a.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/grants/%s", id), nil, nil)
}

//go:noinline
func (a *apiBackend) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) error {
	return a.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/hosts/%s/labels", id), labelsPayload{Labels: labels}, nil)
}

func (a *apiBackend) doJSON(ctx context.Context, method, endpoint string, body any, resp any) error {
	if a == nil {
		return fmt.Errorf("api backend not configured")
	}

	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal %s request: %w", endpoint, err)
		}
		payload = bytes.NewReader(data)
	}

	rel, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("parse endpoint %q: %w", endpoint, err)
	}
	target := a.baseURL.ResolveReference(rel)

	req, err := http.NewRequestWithContext(ctx, method, target.String(), payload)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.namespace != "" {
		req.Header.Set("REMOTE_USER", a.namespace)
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	} else if a.user != "" && a.password != "" {
		req.SetBasicAuth(a.user, a.password)
	}

	res, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("perform request: %w", err)
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		if cerr := res.Body.Close(); cerr != nil {
			return fmt.Errorf("read response: %w (close error: %v)", err, cerr)
		}
		return fmt.Errorf("read response: %w", err)
	}
	if err := res.Body.Close(); err != nil {
		return fmt.Errorf("close response body: %w", err)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		return fmt.Errorf("unexpected status %d: %s", res.StatusCode, msg)
	}

	if resp == nil || len(data) == 0 {
		return nil
	}

	if err := json.Unmarshal(data, resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
