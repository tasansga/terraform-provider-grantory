package provider

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

var errResourceNotFound = errors.New("grantory: resource not found")

type apiHost struct {
	ID        string            `json:"id"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt string            `json:"created_at"`
}

type hostLabelsPayload struct {
	Labels map[string]string `json:"labels"`
}

type apiRequest struct {
	ID        string            `json:"id"`
	HostID    string            `json:"host_id"`
	Payload   map[string]any    `json:"payload,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	HasGrant  bool              `json:"has_grant"`
	Grant     *apiRequestGrant  `json:"grant"`
	GrantID   string            `json:"grant_id,omitempty"`
	CreatedAt string            `json:"created_at"`
	UpdatedAt string            `json:"updated_at"`
}

type apiRequestGrant struct {
	GrantID string         `json:"grant_id"`
	Payload map[string]any `json:"payload"`
}

type apiRegister struct {
	ID        string            `json:"id"`
	HostID    string            `json:"host_id"`
	Payload   map[string]any    `json:"payload,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt string            `json:"created_at"`
	UpdatedAt string            `json:"updated_at"`
}

type apiGrant struct {
	ID        string          `json:"id"`
	RequestID string          `json:"request_id"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
}

type apiGrantCreatePayload struct {
	RequestID string         `json:"request_id"`
	Payload   map[string]any `json:"payload,omitempty"`
}

type requestListOptions struct {
	Labels     map[string]string
	HostLabels map[string]string
	HasGrant   *bool
}

type registerListOptions struct {
	Labels     map[string]string
	HostLabels map[string]string
}

type apiRequestUpdatePayload struct {
	Payload map[string]any    `json:"payload,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
}

type apiRegisterUpdatePayload struct {
	Labels map[string]string `json:"labels,omitempty"`
}

func (c *grantoryClient) createHost(ctx context.Context, host apiHost) (apiHost, error) {
	var created apiHost
	if err := c.doJSON(ctx, http.MethodPost, "/hosts", host, &created); err != nil {
		return apiHost{}, err
	}
	return created, nil
}

func (c *grantoryClient) getHost(ctx context.Context, id string) (apiHost, error) {
	var host apiHost
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/hosts/%s", id), nil, &host); err != nil {
		return apiHost{}, err
	}
	return host, nil
}

func (c *grantoryClient) deleteHost(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/hosts/%s", id), nil, nil)
}

func (c *grantoryClient) listHosts(ctx context.Context) ([]apiHost, error) {
	var hosts []apiHost
	if err := c.doJSON(ctx, http.MethodGet, "/hosts", nil, &hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}

func (c *grantoryClient) updateHostLabels(ctx context.Context, id string, labels map[string]string) (apiHost, error) {
	var updated apiHost
	payload := hostLabelsPayload{
		Labels: labels,
	}
	if err := c.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/hosts/%s/labels", id), payload, &updated); err != nil {
		return apiHost{}, err
	}
	return updated, nil
}

func (c *grantoryClient) createRequest(ctx context.Context, req apiRequest) (apiRequest, error) {
	var created apiRequest
	if err := c.doJSON(ctx, http.MethodPost, "/requests", req, &created); err != nil {
		return apiRequest{}, err
	}
	return created, nil
}

func (c *grantoryClient) getRequest(ctx context.Context, id string) (apiRequest, error) {
	var req apiRequest
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/requests/%s", id), nil, &req); err != nil {
		return apiRequest{}, err
	}
	return req, nil
}

func (c *grantoryClient) deleteRequest(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/requests/%s", id), nil, nil)
}

func (c *grantoryClient) deleteRegister(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/registers/%s", id), nil, nil)
}

func (c *grantoryClient) listRequests(ctx context.Context, opts requestListOptions) ([]apiRequest, error) {
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

	var resp []apiRequest
	if err := c.doJSON(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *grantoryClient) createRegister(ctx context.Context, reg apiRegister) (apiRegister, error) {
	var created apiRegister
	if err := c.doJSON(ctx, http.MethodPost, "/registers", reg, &created); err != nil {
		return apiRegister{}, err
	}
	return created, nil
}

func (c *grantoryClient) getRegister(ctx context.Context, id string) (apiRegister, error) {
	var reg apiRegister
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/registers/%s", id), nil, &reg); err != nil {
		return apiRegister{}, err
	}
	return reg, nil
}

func (c *grantoryClient) listRegisters(ctx context.Context, opts registerListOptions) ([]apiRegister, error) {
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

	var resp []apiRegister
	if err := c.doJSON(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *grantoryClient) updateRegister(ctx context.Context, id string, payload apiRegisterUpdatePayload) (apiRegister, error) {
	var updated apiRegister
	if err := c.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/registers/%s", id), payload, &updated); err != nil {
		return apiRegister{}, err
	}
	return updated, nil
}

func (c *grantoryClient) doJSON(ctx context.Context, method, endpoint string, reqBody any, respBody any) error {
	req, err := c.newRequest(ctx, method, endpoint, reqBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	} else if c.user != "" && c.password != "" {
		req.SetBasicAuth(c.user, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("perform request: %w", err)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		if cerr := resp.Body.Close(); cerr != nil {
			return fmt.Errorf("read response: %w (close error: %v)", err, cerr)
		}
		return fmt.Errorf("read response: %w", err)
	}
	if err := resp.Body.Close(); err != nil {
		return fmt.Errorf("close response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(bodyBytes))
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("%w: %s", errResourceNotFound, msg)
		}
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, msg)
	}

	if respBody == nil || len(bodyBytes) == 0 {
		return nil
	}

	if err := json.Unmarshal(bodyBytes, respBody); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (c *grantoryClient) newRequest(ctx context.Context, method, endpoint string, body any) (*http.Request, error) {
	if c == nil || c.baseURL == nil {
		return nil, fmt.Errorf("grantory client not configured for %s %s", method, endpoint)
	}

	var buf io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		buf = bytes.NewReader(payload)
	}

	rel, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint %q: %w", endpoint, err)
	}

	target := c.baseURL.ResolveReference(rel)
	req, err := http.NewRequestWithContext(ctx, method, target.String(), buf)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}
func (c *grantoryClient) createGrant(ctx context.Context, grant apiGrantCreatePayload) (apiGrant, error) {
	var created apiGrant
	if err := c.doJSON(ctx, http.MethodPost, "/grants", grant, &created); err != nil {
		return apiGrant{}, err
	}
	return created, nil
}

func (c *grantoryClient) getGrant(ctx context.Context, id string) (apiGrant, error) {
	var grant apiGrant
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/grants/%s", id), nil, &grant); err != nil {
		return apiGrant{}, err
	}
	return grant, nil
}

func (c *grantoryClient) listGrants(ctx context.Context) ([]apiGrant, error) {
	var grants []apiGrant
	if err := c.doJSON(ctx, http.MethodGet, "/grants", nil, &grants); err != nil {
		return nil, err
	}
	return grants, nil
}

func (c *grantoryClient) deleteGrant(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/grants/%s", id), nil, nil)
}

func (c *grantoryClient) updateRequest(ctx context.Context, id string, payload apiRequestUpdatePayload) (apiRequest, error) {
	var updated apiRequest
	if err := c.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/requests/%s", id), payload, &updated); err != nil {
		return apiRequest{}, err
	}
	return updated, nil
}
