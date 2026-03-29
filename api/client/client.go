package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Options configures a Client.
type Options struct {
	// BaseURL is the Grantory server base URL, for example
	// "https://grantory.example.internal".
	BaseURL string
	// Token configures Bearer authentication.
	// Leave empty when auth is not enforced by an upstream proxy.
	Token string
	// User configures Basic authentication username.
	User string
	// Password configures Basic authentication password.
	Password string
	// Namespace is sent as the REMOTE_USER request header.
	Namespace string
	// HTTPClient overrides the client used for HTTP calls.
	// When nil, http.DefaultClient is used.
	HTTPClient *http.Client
}

// Client provides typed methods for Grantory HTTP API resources.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	token      string
	user       string
	password   string
	namespace  string
}

// APIError is returned for non-2xx HTTP responses.
type APIError struct {
	// StatusCode is the HTTP response status.
	StatusCode int
	// Message is the response error message.
	Message string
}

func (e *APIError) Error() string {
	if e == nil {
		return "grantory api error"
	}
	return fmt.Sprintf("grantory api error (status %d): %s", e.StatusCode, e.Message)
}

// IsNotFound reports whether err is an APIError with HTTP 404 status.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// New constructs a Client from Options.
//
// Exactly one auth mode may be set: either Token (Bearer) or User+Password
// (Basic). Authentication is optional when the Grantory endpoint does not
// enforce auth.
func New(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.BaseURL) == "" {
		return nil, fmt.Errorf("server URL is required")
	}

	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("server host is required")
	}

	token := strings.TrimSpace(opts.Token)
	user := strings.TrimSpace(opts.User)
	password := opts.Password
	namespace := strings.TrimSpace(opts.Namespace)
	if token != "" && (user != "" || password != "") {
		return nil, fmt.Errorf("token/Bearer auth cannot be combined with user/password")
	}
	if (user != "") != (password != "") {
		return nil, fmt.Errorf("both user and password must be provided together for basic auth")
	}

	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	return &Client{
		baseURL:    u,
		httpClient: client,
		token:      token,
		user:       user,
		password:   password,
		namespace:  namespace,
	}, nil
}

// BaseURL returns a copy of the configured base URL.
func (c *Client) BaseURL() *url.URL {
	if c == nil || c.baseURL == nil {
		return nil
	}
	copy := *c.baseURL
	return &copy
}

// BaseAddress returns the base URL as string.
func (c *Client) BaseAddress() string {
	if c == nil || c.baseURL == nil {
		return ""
	}
	return c.baseURL.String()
}

// HTTPClient returns the HTTP client used for requests.
func (c *Client) HTTPClient() *http.Client {
	if c == nil {
		return nil
	}
	return c.httpClient
}

// CreateHost creates a host resource.
func (c *Client) CreateHost(ctx context.Context, payload HostCreatePayload) (Host, error) {
	var host Host
	if err := c.doJSON(ctx, http.MethodPost, "/hosts", payload, &host); err != nil {
		return Host{}, err
	}
	return host, nil
}

// GetHost fetches a host by ID.
func (c *Client) GetHost(ctx context.Context, id string) (Host, error) {
	var host Host
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/hosts/%s", id), nil, &host); err != nil {
		return Host{}, err
	}
	return host, nil
}

// ListHosts lists all hosts visible in the selected namespace.
func (c *Client) ListHosts(ctx context.Context) ([]Host, error) {
	var hosts []Host
	if err := c.doJSON(ctx, http.MethodGet, "/hosts", nil, &hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}

// UpdateHostLabels updates labels for an existing host.
func (c *Client) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) (Host, error) {
	var host Host
	if err := c.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/hosts/%s/labels", id), LabelsPayload{Labels: normalizeLabels(labels)}, &host); err != nil {
		return Host{}, err
	}
	return host, nil
}

// DeleteHost deletes a host by ID.
func (c *Client) DeleteHost(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/hosts/%s", id), nil, nil)
}

// CreateRequest creates a request resource.
func (c *Client) CreateRequest(ctx context.Context, payload RequestCreatePayload) (Request, error) {
	var resp Request
	if err := c.doJSON(ctx, http.MethodPost, "/requests", payload, &resp); err != nil {
		return Request{}, err
	}
	return resp, nil
}

// GetRequest fetches a request by ID.
func (c *Client) GetRequest(ctx context.Context, id string) (Request, error) {
	var resp Request
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/requests/%s", id), nil, &resp); err != nil {
		return Request{}, err
	}
	return resp, nil
}

// ListRequests lists requests filtered by the provided options.
func (c *Client) ListRequests(ctx context.Context, opts RequestListOptions) ([]Request, error) {
	params := url.Values{}
	for key, value := range opts.Labels {
		params.Add("label", fmt.Sprintf("%s=%s", key, value))
	}
	for key, value := range opts.HostLabels {
		params.Add("host_label", fmt.Sprintf("%s=%s", key, value))
	}
	if opts.HasGrant != nil {
		params.Set("has_grant", strconv.FormatBool(*opts.HasGrant))
	}

	endpoint := "/requests"
	if encoded := params.Encode(); encoded != "" {
		endpoint = endpoint + "?" + encoded
	}

	var resp []Request
	if err := c.doJSON(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateRequest updates mutable request fields.
func (c *Client) UpdateRequest(ctx context.Context, id string, payload RequestUpdatePayload) (Request, error) {
	var resp Request
	if err := c.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/requests/%s", id), payload, &resp); err != nil {
		return Request{}, err
	}
	return resp, nil
}

// UpdateRequestLabels updates request labels.
func (c *Client) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) (Request, error) {
	return c.UpdateRequest(ctx, id, RequestUpdatePayload{Labels: normalizeLabels(labels)})
}

// DeleteRequest deletes a request by ID.
func (c *Client) DeleteRequest(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/requests/%s", id), nil, nil)
}

// CreateRegister creates a register resource.
func (c *Client) CreateRegister(ctx context.Context, payload RegisterCreatePayload) (Register, error) {
	var reg Register
	if err := c.doJSON(ctx, http.MethodPost, "/registers", payload, &reg); err != nil {
		return Register{}, err
	}
	return reg, nil
}

// GetRegister fetches a register by ID.
func (c *Client) GetRegister(ctx context.Context, id string) (Register, error) {
	var reg Register
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/registers/%s", id), nil, &reg); err != nil {
		return Register{}, err
	}
	return reg, nil
}

// ListRegisters lists registers filtered by the provided options.
func (c *Client) ListRegisters(ctx context.Context, opts RegisterListOptions) ([]Register, error) {
	params := url.Values{}
	for key, value := range opts.Labels {
		params.Add("label", fmt.Sprintf("%s=%s", key, value))
	}
	for key, value := range opts.HostLabels {
		params.Add("host_label", fmt.Sprintf("%s=%s", key, value))
	}

	endpoint := "/registers"
	if encoded := params.Encode(); encoded != "" {
		endpoint = endpoint + "?" + encoded
	}

	var resp []Register
	if err := c.doJSON(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateRegister updates mutable register fields.
func (c *Client) UpdateRegister(ctx context.Context, id string, payload RegisterUpdatePayload) (Register, error) {
	var reg Register
	if err := c.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/registers/%s", id), payload, &reg); err != nil {
		return Register{}, err
	}
	return reg, nil
}

// UpdateRegisterLabels updates register labels.
func (c *Client) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) (Register, error) {
	return c.UpdateRegister(ctx, id, RegisterUpdatePayload{Labels: normalizeLabels(labels)})
}

// ListRegisterEvents lists register change events for a register.
func (c *Client) ListRegisterEvents(ctx context.Context, id string) ([]RegisterEvent, error) {
	var events []RegisterEvent
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/registers/%s/events", id), nil, &events); err != nil {
		return nil, err
	}
	return events, nil
}

// DeleteRegister deletes a register by ID.
func (c *Client) DeleteRegister(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/registers/%s", id), nil, nil)
}

// CreateGrant creates a grant resource.
func (c *Client) CreateGrant(ctx context.Context, payload GrantCreatePayload) (Grant, error) {
	var grant Grant
	if err := c.doJSON(ctx, http.MethodPost, "/grants", payload, &grant); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

// GetGrant fetches a grant by ID.
func (c *Client) GetGrant(ctx context.Context, id string) (Grant, error) {
	var grant Grant
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/grants/%s", id), nil, &grant); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

// ListGrants lists all grants visible in the selected namespace.
func (c *Client) ListGrants(ctx context.Context) ([]Grant, error) {
	var grants []Grant
	if err := c.doJSON(ctx, http.MethodGet, "/grants", nil, &grants); err != nil {
		return nil, err
	}
	return grants, nil
}

// UpdateGrant updates the grant payload.
func (c *Client) UpdateGrant(ctx context.Context, id string, payload GrantUpdatePayload) (Grant, error) {
	var grant Grant
	if err := c.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/grants/%s", id), payload, &grant); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

// DeleteGrant deletes a grant by ID.
func (c *Client) DeleteGrant(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/grants/%s", id), nil, nil)
}

// CreateSchemaDefinition creates a schema definition resource.
func (c *Client) CreateSchemaDefinition(ctx context.Context, payload SchemaDefinitionCreatePayload) (SchemaDefinition, error) {
	var def SchemaDefinition
	if err := c.doJSON(ctx, http.MethodPost, "/schema-definitions", payload, &def); err != nil {
		return SchemaDefinition{}, err
	}
	return def, nil
}

// GetSchemaDefinition fetches a schema definition by ID.
func (c *Client) GetSchemaDefinition(ctx context.Context, id string) (SchemaDefinition, error) {
	var def SchemaDefinition
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/schema-definitions/%s", id), nil, &def); err != nil {
		return SchemaDefinition{}, err
	}
	return def, nil
}

// ListSchemaDefinitions lists all schema definitions in the namespace.
func (c *Client) ListSchemaDefinitions(ctx context.Context) ([]SchemaDefinition, error) {
	var defs []SchemaDefinition
	if err := c.doJSON(ctx, http.MethodGet, "/schema-definitions", nil, &defs); err != nil {
		return nil, err
	}
	return defs, nil
}

// DeleteSchemaDefinition deletes a schema definition by ID.
func (c *Client) DeleteSchemaDefinition(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/schema-definitions/%s", id), nil, nil)
}

// UpdateSchemaDefinitionLabels updates schema definition labels.
func (c *Client) UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) (SchemaDefinition, error) {
	var def SchemaDefinition
	if err := c.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/schema-definitions/%s/labels", id), LabelsPayload{Labels: normalizeLabels(labels)}, &def); err != nil {
		return SchemaDefinition{}, err
	}
	return def, nil
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, reqBody any, respBody any) error {
	if c == nil {
		return fmt.Errorf("grantory client not configured")
	}

	var payload io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("marshal %s request: %w", endpoint, err)
		}
		payload = bytes.NewReader(data)
	}

	rel, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("parse endpoint %q: %w", endpoint, err)
	}
	target := c.baseURL.ResolveReference(rel)

	req, err := http.NewRequestWithContext(ctx, method, target.String(), payload)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.namespace != "" {
		req.Header.Set("REMOTE_USER", c.namespace)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	} else if c.user != "" && c.password != "" {
		req.SetBasicAuth(c.user, c.password)
	}

	res, err := c.httpClient.Do(req)
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
		msg := parseAPIErrorMessage(data)
		if msg == "" {
			msg = http.StatusText(res.StatusCode)
		}
		return &APIError{StatusCode: res.StatusCode, Message: msg}
	}

	if respBody == nil || len(data) == 0 {
		return nil
	}

	if err := json.Unmarshal(data, respBody); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func normalizeLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return map[string]string{}
	}
	return labels
}

func parseAPIErrorMessage(data []byte) string {
	msg := strings.TrimSpace(string(data))
	if msg == "" {
		return ""
	}

	var body struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return msg
	}
	if strings.TrimSpace(body.Message) != "" {
		return strings.TrimSpace(body.Message)
	}
	if strings.TrimSpace(body.Error) != "" {
		return strings.TrimSpace(body.Error)
	}
	return msg
}
