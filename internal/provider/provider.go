package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/tasansga/terraform-provider-grantory/internal/api"
)

const (
	serverAttr   = "server"
	tokenAttr    = "token"
	userAttr     = "user"
	passwordAttr = "password"
	EnvToken     = "TOKEN"
	EnvUser      = "USER"
	EnvPassword  = "PASSWORD"
)

// New constructs the Grantory Terraform/OpenTofu provider with its configuration schema.
func New() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			serverAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "http://localhost:8080",
				Description: "URL of the Grantory server (http:// or https://) used for every API interaction. (default: http://localhost:8080)",
			},
			tokenAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc(EnvToken, nil),
				Description: "Bearer token for API requests (env: " + EnvToken + ").",
			},
			userAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Username for basic auth (env: " + EnvUser + ").",
			},
			passwordAttr: {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				Description: "Password for basic auth (env: " + EnvPassword +
					").",
			},
		},
		ConfigureContextFunc: configureProvider,
		ResourcesMap: map[string]*schema.Resource{
			"grantory_host":     resourceHost(),
			"grantory_request":  resourceRequest(),
			"grantory_register": resourceRegister(),
			"grantory_grant":    resourceGrant(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"grantory_host":      dataHost(),
			"grantory_hosts":     dataHosts(),
			"grantory_requests":  dataRequests(),
			"grantory_request":   dataRequest(),
			"grantory_register":  dataRegister(),
			"grantory_registers": dataRegisters(),
			"grantory_grants":    dataGrants(),
			"grantory_grant":     dataGrant(),
		},
	}
}

func configureProvider(ctx context.Context, d *schema.ResourceData) (any, diag.Diagnostics) {
	var diags diag.Diagnostics

	server := d.Get(serverAttr).(string)
	u, parseDiags := parseServerURL(server)
	if parseDiags.HasError() {
		return nil, parseDiags
	}

	token := strings.TrimSpace(d.Get(tokenAttr).(string))
	user := strings.TrimSpace(d.Get(userAttr).(string))
	password := strings.TrimSpace(d.Get(passwordAttr).(string))

	userSet := false
	if _, ok := d.GetOk(userAttr); ok {
		userSet = true
	}
	passwordSet := false
	if _, ok := d.GetOk(passwordAttr); ok {
		passwordSet = true
	}

	if !userSet && !passwordSet {
		envUser := strings.TrimSpace(os.Getenv(EnvUser))
		envPassword := strings.TrimSpace(os.Getenv(EnvPassword))
		if envUser != "" && envPassword != "" {
			user = envUser
			password = envPassword
		}
	}

	basicProvided := user != "" || password != ""

	if token != "" && basicProvided {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "conflicting authentication settings",
			Detail:   "token and user/password cannot be configured at the same time",
		})
		return nil, diags
	}
	if basicProvided && (user == "" || password == "") {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "incomplete basic auth credentials",
			Detail:   "both user and password must be provided for basic auth",
		})
		return nil, diags
	}

	client := &grantoryClient{
		baseURL:    u,
		httpClient: http.DefaultClient,
		token:      token,
		user:       user,
		password:   password,
	}
	diags = append(diags, warnOnAPIMismatch(ctx, client)...)
	return client, diags
}

func warnOnAPIMismatch(ctx context.Context, client *grantoryClient) diag.Diagnostics {
	var diags diag.Diagnostics
	if client == nil || client.baseURL == nil {
		return diags
	}

	serverMajor, err := fetchServerAPIMajor(ctx, client)
	if err != nil || serverMajor == "" || serverMajor == "unknown" {
		return diags
	}

	providerMajor := api.Major(api.APIVersion)
	if providerMajor == "" || providerMajor == "unknown" {
		return diags
	}

	if providerMajor != serverMajor {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "grantory API version mismatch",
			Detail: fmt.Sprintf(
				"provider expects API major %s but server reports %s",
				providerMajor,
				serverMajor,
			),
		})
	}

	return diags
}

func fetchServerAPIMajor(ctx context.Context, client *grantoryClient) (string, error) {
	metaURL := *client.baseURL
	if strings.HasSuffix(metaURL.Path, "/") {
		metaURL.Path += "meta"
	} else {
		metaURL.Path += "/meta"
	}
	metaURL.RawQuery = ""
	metaURL.Fragment = ""

	timeoutCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, metaURL.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			_ = cerr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	var payload struct {
		APIVersion string `json:"api_version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	return api.Major(payload.APIVersion), nil
}

func parseServerURL(raw string) (*url.URL, diag.Diagnostics) {
	var diags diag.Diagnostics
	if raw == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "grantory server address is required",
			Detail:   "the 'server' attribute must not be empty",
		})
		return nil, diags
	}

	u, err := url.Parse(raw)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "invalid grantory server URL",
			Detail:   err.Error(),
		})
		return nil, diags
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "unsupported grantory server scheme",
			Detail:   fmt.Sprintf("scheme %q is not supported", u.Scheme),
		})
		return nil, diags
	}
	if u.Host == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "grantory server host is missing",
			Detail:   "the URL must include a host",
		})
		return nil, diags
	}

	return u, diags
}

type grantoryClient struct {
	baseURL    *url.URL
	httpClient *http.Client
	token      string
	user       string
	password   string
}

func (c *grantoryClient) baseAddress() string {
	if c == nil || c.baseURL == nil {
		return ""
	}
	return c.baseURL.String()
}
