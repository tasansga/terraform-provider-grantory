package service

import "context"

// Store is the persistence contract used by Service.
// Applications can implement this interface for custom storage backends.
type Store interface {
	Close() error

	CreateHost(ctx context.Context, payload HostCreatePayload) (Host, error)
	GetHost(ctx context.Context, id string) (Host, error)
	ListHosts(ctx context.Context) ([]Host, error)
	UpdateHostLabels(ctx context.Context, id string, labels map[string]string) (Host, error)
	DeleteHost(ctx context.Context, id string) error

	CreateRequest(ctx context.Context, payload RequestCreatePayload) (Request, error)
	GetRequest(ctx context.Context, id string) (Request, error)
	ListRequests(ctx context.Context, opts RequestListOptions) ([]Request, error)
	UpdateRequest(ctx context.Context, id string, payload RequestUpdatePayload) (Request, error)
	UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) (Request, error)
	DeleteRequest(ctx context.Context, id string) error

	CreateRegister(ctx context.Context, payload RegisterCreatePayload) (Register, error)
	GetRegister(ctx context.Context, id string) (Register, error)
	ListRegisters(ctx context.Context, opts RegisterListOptions) ([]Register, error)
	UpdateRegister(ctx context.Context, id string, payload RegisterUpdatePayload) (Register, error)
	UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) (Register, error)
	ListRegisterEvents(ctx context.Context, registerID string) ([]RegisterEvent, error)
	DeleteRegister(ctx context.Context, id string) error

	CreateGrant(ctx context.Context, payload GrantCreatePayload) (Grant, error)
	GetGrant(ctx context.Context, id string) (Grant, error)
	ListGrants(ctx context.Context) ([]Grant, error)
	UpdateGrant(ctx context.Context, id string, payload GrantUpdatePayload) (Grant, error)
	DeleteGrant(ctx context.Context, id string) error

	CreateSchemaDefinition(ctx context.Context, payload SchemaDefinitionCreatePayload) (SchemaDefinition, error)
	GetSchemaDefinition(ctx context.Context, id string) (SchemaDefinition, error)
	ListSchemaDefinitions(ctx context.Context) ([]SchemaDefinition, error)
	UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) (SchemaDefinition, error)
	DeleteSchemaDefinition(ctx context.Context, id string) error
}
