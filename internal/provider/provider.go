package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	apiclient "github.com/tasansga/terraform-provider-grantory/api/client"
	"github.com/tasansga/terraform-provider-grantory/internal/api"
	"github.com/tasansga/terraform-provider-grantory/internal/transport/sshunix"
)

const (
	serverAttr                   = "server"
	tokenAttr                    = "token"
	userAttr                     = "user"
	passwordAttr                 = "password"
	sshAddressAttr               = "ssh_address"
	sshUserAttr                  = "ssh_user"
	sshPrivateKeyPathAttr        = "ssh_private_key_path"
	sshUseAgentAttr              = "ssh_use_agent"
	sshAgentSocketPathAttr       = "ssh_agent_socket_path"
	sshKnownHostsPathAttr        = "ssh_known_hosts_path"
	sshInsecureHostKeyAttr       = "ssh_insecure_host_key"
	sshSocketPathAttr            = "ssh_socket_path"
	sshTimeoutSecondsAttr        = "ssh_timeout_seconds"
	sshBastionAddressAttr        = "ssh_bastion_address"
	sshBastionUserAttr           = "ssh_bastion_user"
	sshBastionPrivateKeyPathAttr = "ssh_bastion_private_key_path"

	defaultServerURL = "http://localhost:8080"
	sshModeBaseURL   = "http://grantory"

	EnvToken    = "TOKEN"
	EnvUser     = "USER"
	EnvPassword = "PASSWORD"
)

// New constructs the Grantory Terraform/OpenTofu provider with its configuration schema.
func New() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			serverAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URL of the Grantory server (http:// or https://) used for every API interaction. Defaults to " + defaultServerURL + " when SSH transport is not configured.",
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
			sshAddressAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "SSH target address in host:port format for unix-socket transport mode.",
			},
			sshUserAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "SSH username for unix-socket transport mode.",
			},
			sshPrivateKeyPathAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH private key file used for unix-socket transport mode.",
			},
			sshUseAgentAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable SSH agent authentication (reads from SSH_AUTH_SOCK by default).",
			},
			sshAgentSocketPathAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional path to SSH agent unix socket (overrides SSH_AUTH_SOCK).",
			},
			sshKnownHostsPathAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to OpenSSH known_hosts file for SSH host key validation (used for target and bastion).",
			},
			sshInsecureHostKeyAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Disable SSH host key validation (not recommended for production).",
			},
			sshSocketPathAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Remote unix socket path on the SSH target host.",
			},
			sshTimeoutSecondsAttr: {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     10,
				Description: "SSH dial and handshake timeout in seconds.",
			},
			sshBastionAddressAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional bastion SSH address in host:port format.",
			},
			sshBastionUserAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional bastion SSH username (defaults to ssh_user).",
			},
			sshBastionPrivateKeyPathAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional bastion private key path (defaults to ssh_private_key_path).",
			},
		},
		ConfigureContextFunc: configureProvider,
		ResourcesMap: map[string]*schema.Resource{
			"grantory_host":              resourceHost(),
			"grantory_request":           resourceRequest(),
			"grantory_register":          resourceRegister(),
			"grantory_grant":             resourceGrant(),
			"grantory_schema_definition": resourceSchemaDefinition(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"grantory_host":               dataHost(),
			"grantory_hosts":              dataHosts(),
			"grantory_requests":           dataRequests(),
			"grantory_request":            dataRequest(),
			"grantory_register":           dataRegister(),
			"grantory_registers":          dataRegisters(),
			"grantory_grants":             dataGrants(),
			"grantory_grant":              dataGrant(),
			"grantory_schema_definition":  dataSchemaDefinition(),
			"grantory_schema_definitions": dataSchemaDefinitions(),
		},
	}
}

func configureProvider(ctx context.Context, d *schema.ResourceData) (any, diag.Diagnostics) {
	var diags diag.Diagnostics

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

	sshCfg := readSSHConfig(d)
	sshMode := sshCfg.configured()

	server := strings.TrimSpace(d.Get(serverAttr).(string))
	if sshMode && server != "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "conflicting transport settings",
			Detail:   "configure either 'server' for HTTP(S) mode or SSH transport attributes, but not both",
		})
		return nil, diags
	}
	if !sshMode && server == "" {
		server = defaultServerURL
	}

	var (
		baseURL    string
		httpClient *http.Client
	)
	httpClient = http.DefaultClient
	if sshMode {
		if sshCfg.timeoutSeconds < 1 {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "invalid SSH timeout",
				Detail:   fmt.Sprintf("%s must be at least 1 second", sshTimeoutSecondsAttr),
			})
			return nil, diags
		}

		if missing := sshCfg.missingRequiredFields(); len(missing) > 0 {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "incomplete SSH transport configuration",
				Detail:   "missing required SSH fields: " + strings.Join(missing, ", "),
			})
			return nil, diags
		}

		sshHTTPClient, err := sshunix.NewHTTPClient(sshunix.Options{
			Address:               sshCfg.address,
			User:                  sshCfg.user,
			PrivateKeyPath:        sshCfg.privateKeyPath,
			UseAgent:              sshCfg.useAgent,
			AgentSocketPath:       sshCfg.agentSocketPath,
			KnownHostsPath:        sshCfg.knownHostsPath,
			InsecureHostKey:       sshCfg.insecureHostKey,
			SocketPath:            sshCfg.socketPath,
			Timeout:               time.Duration(sshCfg.timeoutSeconds) * time.Second,
			BastionAddress:        sshCfg.bastionAddress,
			BastionUser:           sshCfg.bastionUser,
			BastionPrivateKeyPath: sshCfg.bastionPrivateKeyPath,
		})
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "unable to configure SSH transport",
				Detail:   err.Error(),
			})
			return nil, diags
		}
		httpClient = sshHTTPClient
		baseURL = sshModeBaseURL
	} else {
		u, parseDiags := parseServerURL(server)
		if parseDiags.HasError() {
			return nil, parseDiags
		}
		baseURL = u.String()
	}

	client, err := apiclient.New(apiclient.Options{
		BaseURL:    baseURL,
		Token:      token,
		User:       user,
		Password:   password,
		HTTPClient: httpClient,
	})
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "unable to configure grantory client",
			Detail:   err.Error(),
		})
		return nil, diags
	}
	diags = append(diags, warnOnAPIMismatch(ctx, client)...)
	return client, diags
}

type sshConfig struct {
	address               string
	user                  string
	privateKeyPath        string
	useAgent              bool
	agentSocketPath       string
	knownHostsPath        string
	insecureHostKey       bool
	socketPath            string
	timeoutSeconds        int
	bastionAddress        string
	bastionUser           string
	bastionPrivateKeyPath string
}

func readSSHConfig(d *schema.ResourceData) sshConfig {
	agentSocketPath := strings.TrimSpace(d.Get(sshAgentSocketPathAttr).(string))
	useAgent := d.Get(sshUseAgentAttr).(bool) || agentSocketPath != ""
	return sshConfig{
		address:               strings.TrimSpace(d.Get(sshAddressAttr).(string)),
		user:                  strings.TrimSpace(d.Get(sshUserAttr).(string)),
		privateKeyPath:        strings.TrimSpace(d.Get(sshPrivateKeyPathAttr).(string)),
		useAgent:              useAgent,
		agentSocketPath:       agentSocketPath,
		knownHostsPath:        strings.TrimSpace(d.Get(sshKnownHostsPathAttr).(string)),
		insecureHostKey:       d.Get(sshInsecureHostKeyAttr).(bool),
		socketPath:            strings.TrimSpace(d.Get(sshSocketPathAttr).(string)),
		timeoutSeconds:        d.Get(sshTimeoutSecondsAttr).(int),
		bastionAddress:        strings.TrimSpace(d.Get(sshBastionAddressAttr).(string)),
		bastionUser:           strings.TrimSpace(d.Get(sshBastionUserAttr).(string)),
		bastionPrivateKeyPath: strings.TrimSpace(d.Get(sshBastionPrivateKeyPathAttr).(string)),
	}
}

func (c sshConfig) configured() bool {
	return c.address != "" ||
		c.user != "" ||
		c.privateKeyPath != "" ||
		c.useAgent ||
		c.agentSocketPath != "" ||
		c.knownHostsPath != "" ||
		c.insecureHostKey ||
		c.socketPath != "" ||
		c.bastionAddress != "" ||
		c.bastionUser != "" ||
		c.bastionPrivateKeyPath != ""
}

func (c sshConfig) missingRequiredFields() []string {
	missing := make([]string, 0, 5)
	if c.address == "" {
		missing = append(missing, sshAddressAttr)
	}
	if c.user == "" {
		missing = append(missing, sshUserAttr)
	}
	if c.privateKeyPath == "" && !c.useAgent {
		missing = append(missing, sshPrivateKeyPathAttr+" (or enable "+sshUseAgentAttr+")")
	}
	if c.socketPath == "" {
		missing = append(missing, sshSocketPathAttr)
	}
	if !c.insecureHostKey && c.knownHostsPath == "" {
		missing = append(missing, sshKnownHostsPathAttr)
	}
	sort.Strings(missing)
	return missing
}

func warnOnAPIMismatch(ctx context.Context, client *grantoryClient) diag.Diagnostics {
	var diags diag.Diagnostics
	if client == nil || client.BaseURL() == nil {
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
	metaURL := client.BaseURL()
	if metaURL == nil {
		return "", fmt.Errorf("grantory client not configured")
	}
	metaCopy := *metaURL
	metaURL = &metaCopy
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
	httpClient := http.DefaultClient
	if client != nil && client.HTTPClient() != nil {
		httpClient = client.HTTPClient()
	}
	resp, err := httpClient.Do(req)
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
