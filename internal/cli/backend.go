package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	apiclient "github.com/tasansga/terraform-provider-grantory/internal/api/client"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

type cliBackend interface {
	ListHosts(context.Context) ([]storage.Host, error)
	ListRequests(context.Context, *storage.RequestListFilters) ([]storage.Request, error)
	ListRegisters(context.Context, *storage.RegisterListFilters) ([]storage.Register, error)
	ListGrants(context.Context) ([]storage.Grant, error)
	ListSchemaDefinitions(context.Context) ([]storage.SchemaDefinition, error)
	GetHost(context.Context, string) (storage.Host, error)
	GetRequest(context.Context, string) (storage.Request, error)
	GetRegister(context.Context, string) (storage.Register, error)
	GetGrant(context.Context, string) (storage.Grant, error)
	GetSchemaDefinition(context.Context, string) (storage.SchemaDefinition, error)
	CreateRequest(context.Context, storage.Request) (storage.Request, error)
	CreateRegister(context.Context, storage.Register) (storage.Register, error)
	CreateGrant(context.Context, storage.Grant) (storage.Grant, error)
	CreateSchemaDefinition(context.Context, storage.SchemaDefinition) (storage.SchemaDefinition, error)
	DeleteHost(context.Context, string) error
	DeleteRequest(context.Context, string) error
	DeleteRegister(context.Context, string) error
	DeleteGrant(context.Context, string) error
	DeleteSchemaDefinition(context.Context, string) error
	UpdateHostLabels(context.Context, string, map[string]string) error
	UpdateRequestLabels(context.Context, string, map[string]string) error
	UpdateRegisterLabels(context.Context, string, map[string]string) error
	UpdateSchemaDefinitionLabels(context.Context, string, map[string]string) error
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

func newDirectBackend(store storage.Store) cliBackend {
	return &directBackend{store: store}
}

type directBackend struct {
	store storage.Store
}

func (d *directBackend) ListHosts(ctx context.Context) ([]storage.Host, error) {
	return d.store.ListHosts(ctx)
}

//go:noinline
func (d *directBackend) ListRequests(ctx context.Context, filters *storage.RequestListFilters) ([]storage.Request, error) {
	return d.store.ListRequests(ctx, filters)
}

//go:noinline
func (d *directBackend) ListRegisters(ctx context.Context, filters *storage.RegisterListFilters) ([]storage.Register, error) {
	return d.store.ListRegisters(ctx, filters)
}

//go:noinline
func (d *directBackend) ListGrants(ctx context.Context) ([]storage.Grant, error) {
	return d.store.ListGrants(ctx)
}

func (d *directBackend) ListSchemaDefinitions(ctx context.Context) ([]storage.SchemaDefinition, error) {
	return d.store.ListSchemaDefinitions(ctx)
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

func (d *directBackend) GetSchemaDefinition(ctx context.Context, id string) (storage.SchemaDefinition, error) {
	return d.store.GetSchemaDefinition(ctx, id)
}

func (d *directBackend) CreateRequest(ctx context.Context, req storage.Request) (storage.Request, error) {
	return d.store.CreateRequest(ctx, req)
}

func (d *directBackend) CreateRegister(ctx context.Context, reg storage.Register) (storage.Register, error) {
	return d.store.CreateRegister(ctx, reg)
}

func (d *directBackend) CreateGrant(ctx context.Context, grant storage.Grant) (storage.Grant, error) {
	return d.store.CreateGrant(ctx, grant)
}

func (d *directBackend) CreateSchemaDefinition(ctx context.Context, def storage.SchemaDefinition) (storage.SchemaDefinition, error) {
	return d.store.CreateSchemaDefinition(ctx, def)
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

func (d *directBackend) DeleteSchemaDefinition(ctx context.Context, id string) error {
	return d.store.DeleteSchemaDefinition(ctx, id)
}

func (d *directBackend) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) error {
	return d.store.UpdateHostLabels(ctx, id, labels)
}

func (d *directBackend) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) error {
	return d.store.UpdateRequestLabels(ctx, id, labels)
}

func (d *directBackend) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) error {
	return d.store.UpdateRegisterLabels(ctx, id, labels)
}

func (d *directBackend) UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) error {
	return d.store.UpdateSchemaDefinitionLabels(ctx, id, labels)
}

func newAPIBackend(namespace, rawURL, token, user, password string) (cliBackend, error) {
	client, err := apiclient.New(apiclient.Options{
		BaseURL:   rawURL,
		Token:     token,
		User:      user,
		Password:  password,
		Namespace: namespace,
	})
	if err != nil {
		return nil, err
	}

	return &apiBackend{
		client: client,
	}, nil
}

type apiBackend struct {
	client *apiclient.Client
}

func (a *apiBackend) ListHosts(ctx context.Context) ([]storage.Host, error) {
	hosts, err := a.client.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]storage.Host, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, hostToStorage(host))
	}
	return out, nil
}

//go:noinline
func (a *apiBackend) ListRequests(ctx context.Context, filters *storage.RequestListFilters) ([]storage.Request, error) {
	options := apiclient.RequestListOptions{}
	if filters != nil {
		options.Labels = filters.Labels
		options.HostLabels = filters.HostLabels
		options.HasGrant = filters.HasGrant
	}
	requests, err := a.client.ListRequests(ctx, options)
	if err != nil {
		return nil, err
	}
	out := make([]storage.Request, 0, len(requests))
	for _, req := range requests {
		out = append(out, requestToStorage(req))
	}
	return out, nil
}

//go:noinline
func (a *apiBackend) ListRegisters(ctx context.Context, filters *storage.RegisterListFilters) ([]storage.Register, error) {
	options := apiclient.RegisterListOptions{}
	if filters != nil {
		options.Labels = filters.Labels
		options.HostLabels = filters.HostLabels
	}
	registers, err := a.client.ListRegisters(ctx, options)
	if err != nil {
		return nil, err
	}
	out := make([]storage.Register, 0, len(registers))
	for _, reg := range registers {
		out = append(out, registerToStorage(reg))
	}
	return out, nil
}

//go:noinline
func (a *apiBackend) ListGrants(ctx context.Context) ([]storage.Grant, error) {
	grants, err := a.client.ListGrants(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]storage.Grant, 0, len(grants))
	for _, grant := range grants {
		out = append(out, grantToStorage(grant))
	}
	return out, nil
}

func (a *apiBackend) ListSchemaDefinitions(ctx context.Context) ([]storage.SchemaDefinition, error) {
	defs, err := a.client.ListSchemaDefinitions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]storage.SchemaDefinition, 0, len(defs))
	for _, def := range defs {
		out = append(out, schemaDefinitionToStorage(def))
	}
	return out, nil
}

//go:noinline
func (a *apiBackend) GetHost(ctx context.Context, id string) (storage.Host, error) {
	host, err := a.client.GetHost(ctx, id)
	if err != nil {
		return storage.Host{}, err
	}
	return hostToStorage(host), nil
}

//go:noinline
func (a *apiBackend) GetRequest(ctx context.Context, id string) (storage.Request, error) {
	req, err := a.client.GetRequest(ctx, id)
	if err != nil {
		return storage.Request{}, err
	}
	return requestToStorage(req), nil
}

//go:noinline
func (a *apiBackend) GetRegister(ctx context.Context, id string) (storage.Register, error) {
	reg, err := a.client.GetRegister(ctx, id)
	if err != nil {
		return storage.Register{}, err
	}
	return registerToStorage(reg), nil
}

//go:noinline
func (a *apiBackend) GetGrant(ctx context.Context, id string) (storage.Grant, error) {
	grant, err := a.client.GetGrant(ctx, id)
	if err != nil {
		return storage.Grant{}, err
	}
	return grantToStorage(grant), nil
}

func (a *apiBackend) GetSchemaDefinition(ctx context.Context, id string) (storage.SchemaDefinition, error) {
	def, err := a.client.GetSchemaDefinition(ctx, id)
	if err != nil {
		return storage.SchemaDefinition{}, err
	}
	return schemaDefinitionToStorage(def), nil
}

func (a *apiBackend) CreateRequest(ctx context.Context, req storage.Request) (storage.Request, error) {
	created, err := a.client.CreateRequest(ctx, apiclient.RequestCreatePayload{
		HostID:                    req.HostID,
		RequestSchemaDefinitionID: req.RequestSchemaDefinitionID,
		GrantSchemaDefinitionID:   req.GrantSchemaDefinitionID,
		UniqueKey:                 req.UniqueKey,
		Payload:                   req.Payload,
		Labels:                    req.Labels,
	})
	if err != nil {
		return storage.Request{}, err
	}
	return requestToStorage(created), nil
}

func (a *apiBackend) CreateRegister(ctx context.Context, reg storage.Register) (storage.Register, error) {
	created, err := a.client.CreateRegister(ctx, apiclient.RegisterCreatePayload{
		HostID:             reg.HostID,
		SchemaDefinitionID: reg.SchemaDefinitionID,
		UniqueKey:          reg.UniqueKey,
		Payload:            reg.Payload,
		Labels:             reg.Labels,
	})
	if err != nil {
		return storage.Register{}, err
	}
	return registerToStorage(created), nil
}

func (a *apiBackend) CreateGrant(ctx context.Context, grant storage.Grant) (storage.Grant, error) {
	created, err := a.client.CreateGrant(ctx, apiclient.GrantCreatePayload{
		RequestID: grant.RequestID,
		Payload:   grant.Payload,
	})
	if err != nil {
		return storage.Grant{}, err
	}
	return grantToStorage(created), nil
}

func (a *apiBackend) CreateSchemaDefinition(ctx context.Context, def storage.SchemaDefinition) (storage.SchemaDefinition, error) {
	created, err := a.client.CreateSchemaDefinition(ctx, apiclient.SchemaDefinitionCreatePayload{
		UniqueKey: def.UniqueKey,
		Schema:    def.Schema,
		Labels:    def.Labels,
	})
	if err != nil {
		return storage.SchemaDefinition{}, err
	}
	return schemaDefinitionToStorage(created), nil
}

//go:noinline
func (a *apiBackend) DeleteHost(ctx context.Context, id string) error {
	return a.client.DeleteHost(ctx, id)
}

//go:noinline
func (a *apiBackend) DeleteRequest(ctx context.Context, id string) error {
	return a.client.DeleteRequest(ctx, id)
}

//go:noinline
func (a *apiBackend) DeleteRegister(ctx context.Context, id string) error {
	return a.client.DeleteRegister(ctx, id)
}

//go:noinline
func (a *apiBackend) DeleteGrant(ctx context.Context, id string) error {
	return a.client.DeleteGrant(ctx, id)
}

func (a *apiBackend) DeleteSchemaDefinition(ctx context.Context, id string) error {
	return a.client.DeleteSchemaDefinition(ctx, id)
}

//go:noinline
func (a *apiBackend) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) error {
	_, err := a.client.UpdateHostLabels(ctx, id, labels)
	return err
}

func (a *apiBackend) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) error {
	_, err := a.client.UpdateRequestLabels(ctx, id, labels)
	return err
}

func (a *apiBackend) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) error {
	_, err := a.client.UpdateRegisterLabels(ctx, id, labels)
	return err
}

func (a *apiBackend) UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) error {
	_, err := a.client.UpdateSchemaDefinitionLabels(ctx, id, labels)
	return err
}

func hostToStorage(host apiclient.Host) storage.Host {
	return storage.Host{
		ID:        host.ID,
		UniqueKey: host.UniqueKey,
		Labels:    host.Labels,
		CreatedAt: host.CreatedAt,
	}
}

func requestToStorage(req apiclient.Request) storage.Request {
	return storage.Request{
		ID:                        req.ID,
		HostID:                    req.HostID,
		RequestSchemaDefinitionID: req.RequestSchemaDefinitionID,
		GrantSchemaDefinitionID:   req.GrantSchemaDefinitionID,
		UniqueKey:                 req.UniqueKey,
		Payload:                   req.Payload,
		Labels:                    req.Labels,
		HasGrant:                  req.HasGrant,
		CreatedAt:                 req.CreatedAt,
		UpdatedAt:                 req.UpdatedAt,
	}
}

func registerToStorage(reg apiclient.Register) storage.Register {
	return storage.Register{
		ID:                 reg.ID,
		HostID:             reg.HostID,
		SchemaDefinitionID: reg.SchemaDefinitionID,
		UniqueKey:          reg.UniqueKey,
		Payload:            reg.Payload,
		Labels:             reg.Labels,
		CreatedAt:          reg.CreatedAt,
		UpdatedAt:          reg.UpdatedAt,
	}
}

func grantToStorage(grant apiclient.Grant) storage.Grant {
	return storage.Grant{
		ID:        grant.ID,
		RequestID: grant.RequestID,
		Payload:   grant.Payload,
		CreatedAt: grant.CreatedAt,
		UpdatedAt: grant.UpdatedAt,
	}
}

func schemaDefinitionToStorage(def apiclient.SchemaDefinition) storage.SchemaDefinition {
	return storage.SchemaDefinition{
		ID:        def.ID,
		UniqueKey: def.UniqueKey,
		Schema:    def.Schema,
		Labels:    def.Labels,
		CreatedAt: def.CreatedAt,
	}
}
