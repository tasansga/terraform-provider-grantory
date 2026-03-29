package server

import (
	"context"
	"errors"
	"time"

	apiservice "github.com/tasansga/terraform-provider-grantory/api/service"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

type serviceStoreAdapter struct {
	store storage.Store
}

func newServiceStoreAdapter(store storage.Store) apiservice.Store {
	return serviceStoreAdapter{store: store}
}

func (a serviceStoreAdapter) Close() error {
	return a.store.Close()
}

func (a serviceStoreAdapter) CreateHost(ctx context.Context, payload apiservice.HostCreatePayload) (apiservice.Host, error) {
	host, err := a.store.CreateHost(ctx, storage.Host{UniqueKey: payload.UniqueKey, Labels: payload.Labels})
	if err != nil {
		return apiservice.Host{}, mapStorageError(err)
	}
	return hostFromStorage(host), nil
}

func (a serviceStoreAdapter) GetHost(ctx context.Context, id string) (apiservice.Host, error) {
	host, err := a.store.GetHost(ctx, id)
	if err != nil {
		return apiservice.Host{}, mapStorageError(err)
	}
	return hostFromStorage(host), nil
}

func (a serviceStoreAdapter) ListHosts(ctx context.Context) ([]apiservice.Host, error) {
	hosts, err := a.store.ListHosts(ctx)
	if err != nil {
		return nil, mapStorageError(err)
	}
	out := make([]apiservice.Host, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, hostFromStorage(host))
	}
	return out, nil
}

func (a serviceStoreAdapter) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) (apiservice.Host, error) {
	if err := a.store.UpdateHostLabels(ctx, id, labels); err != nil {
		return apiservice.Host{}, mapStorageError(err)
	}
	return a.GetHost(ctx, id)
}

func (a serviceStoreAdapter) DeleteHost(ctx context.Context, id string) error {
	return mapStorageError(a.store.DeleteHost(ctx, id))
}

func (a serviceStoreAdapter) CreateRequest(ctx context.Context, payload apiservice.RequestCreatePayload) (apiservice.Request, error) {
	req, err := a.store.CreateRequest(ctx, storage.Request{
		HostID:                    payload.HostID,
		RequestSchemaDefinitionID: payload.RequestSchemaDefinitionID,
		GrantSchemaDefinitionID:   payload.GrantSchemaDefinitionID,
		UniqueKey:                 payload.UniqueKey,
		Payload:                   payload.Payload,
		Labels:                    payload.Labels,
	})
	if err != nil {
		return apiservice.Request{}, mapStorageError(err)
	}
	return a.GetRequest(ctx, req.ID)
}

func (a serviceStoreAdapter) GetRequest(ctx context.Context, id string) (apiservice.Request, error) {
	req, err := a.store.GetRequest(ctx, id)
	if err != nil {
		return apiservice.Request{}, mapStorageError(err)
	}
	return a.requestWithGrant(ctx, req)
}

func (a serviceStoreAdapter) ListRequests(ctx context.Context, opts apiservice.RequestListOptions) ([]apiservice.Request, error) {
	filters := storage.RequestListFilters{HasGrant: opts.HasGrant, Labels: opts.Labels, HostLabels: opts.HostLabels}
	requests, err := a.store.ListRequests(ctx, &filters)
	if err != nil {
		return nil, mapStorageError(err)
	}
	out := make([]apiservice.Request, 0, len(requests))
	for _, req := range requests {
		enriched, err := a.requestWithGrant(ctx, req)
		if err != nil {
			return nil, err
		}
		out = append(out, enriched)
	}
	return out, nil
}

func (a serviceStoreAdapter) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) (apiservice.Request, error) {
	if err := a.store.UpdateRequestLabels(ctx, id, labels); err != nil {
		return apiservice.Request{}, mapStorageError(err)
	}
	return a.GetRequest(ctx, id)
}

func (a serviceStoreAdapter) DeleteRequest(ctx context.Context, id string) error {
	return mapStorageError(a.store.DeleteRequest(ctx, id))
}

func (a serviceStoreAdapter) CreateRegister(ctx context.Context, payload apiservice.RegisterCreatePayload) (apiservice.Register, error) {
	reg, err := a.store.CreateRegister(ctx, storage.Register{
		HostID:             payload.HostID,
		SchemaDefinitionID: payload.SchemaDefinitionID,
		UniqueKey:          payload.UniqueKey,
		Payload:            payload.Payload,
		Labels:             payload.Labels,
	})
	if err != nil {
		return apiservice.Register{}, mapStorageError(err)
	}
	return a.GetRegister(ctx, reg.ID)
}

func (a serviceStoreAdapter) GetRegister(ctx context.Context, id string) (apiservice.Register, error) {
	reg, err := a.store.GetRegister(ctx, id)
	if err != nil {
		return apiservice.Register{}, mapStorageError(err)
	}
	return registerFromStorage(reg), nil
}

func (a serviceStoreAdapter) ListRegisters(ctx context.Context, opts apiservice.RegisterListOptions) ([]apiservice.Register, error) {
	filters := storage.RegisterListFilters{Labels: opts.Labels, HostLabels: opts.HostLabels}
	registers, err := a.store.ListRegisters(ctx, &filters)
	if err != nil {
		return nil, mapStorageError(err)
	}
	out := make([]apiservice.Register, 0, len(registers))
	for _, reg := range registers {
		out = append(out, registerFromStorage(reg))
	}
	return out, nil
}

func (a serviceStoreAdapter) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) (apiservice.Register, error) {
	if err := a.store.UpdateRegisterLabels(ctx, id, labels); err != nil {
		return apiservice.Register{}, mapStorageError(err)
	}
	return a.GetRegister(ctx, id)
}

func (a serviceStoreAdapter) DeleteRegister(ctx context.Context, id string) error {
	return mapStorageError(a.store.DeleteRegister(ctx, id))
}

func (a serviceStoreAdapter) CreateGrant(ctx context.Context, payload apiservice.GrantCreatePayload) (apiservice.Grant, error) {
	grant, err := a.store.CreateGrant(ctx, storage.Grant{RequestID: payload.RequestID, Payload: payload.Payload})
	if err != nil {
		return apiservice.Grant{}, mapStorageError(err)
	}
	return a.GetGrant(ctx, grant.ID)
}

func (a serviceStoreAdapter) GetGrant(ctx context.Context, id string) (apiservice.Grant, error) {
	grant, err := a.store.GetGrant(ctx, id)
	if err != nil {
		return apiservice.Grant{}, mapStorageError(err)
	}
	return grantFromStorage(grant), nil
}

func (a serviceStoreAdapter) ListGrants(ctx context.Context) ([]apiservice.Grant, error) {
	grants, err := a.store.ListGrants(ctx)
	if err != nil {
		return nil, mapStorageError(err)
	}
	out := make([]apiservice.Grant, 0, len(grants))
	for _, grant := range grants {
		out = append(out, grantFromStorage(grant))
	}
	return out, nil
}

func (a serviceStoreAdapter) DeleteGrant(ctx context.Context, id string) error {
	return mapStorageError(a.store.DeleteGrant(ctx, id))
}

func (a serviceStoreAdapter) CreateSchemaDefinition(ctx context.Context, payload apiservice.SchemaDefinitionCreatePayload) (apiservice.SchemaDefinition, error) {
	def, err := a.store.CreateSchemaDefinition(ctx, storage.SchemaDefinition{UniqueKey: payload.UniqueKey, Schema: payload.Schema, Labels: payload.Labels})
	if err != nil {
		return apiservice.SchemaDefinition{}, mapStorageError(err)
	}
	return a.GetSchemaDefinition(ctx, def.ID)
}

func (a serviceStoreAdapter) GetSchemaDefinition(ctx context.Context, id string) (apiservice.SchemaDefinition, error) {
	def, err := a.store.GetSchemaDefinition(ctx, id)
	if err != nil {
		return apiservice.SchemaDefinition{}, mapStorageError(err)
	}
	return schemaDefinitionFromStorage(def), nil
}

func (a serviceStoreAdapter) ListSchemaDefinitions(ctx context.Context) ([]apiservice.SchemaDefinition, error) {
	defs, err := a.store.ListSchemaDefinitions(ctx)
	if err != nil {
		return nil, mapStorageError(err)
	}
	out := make([]apiservice.SchemaDefinition, 0, len(defs))
	for _, def := range defs {
		out = append(out, schemaDefinitionFromStorage(def))
	}
	return out, nil
}

func (a serviceStoreAdapter) UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) (apiservice.SchemaDefinition, error) {
	if err := a.store.UpdateSchemaDefinitionLabels(ctx, id, labels); err != nil {
		return apiservice.SchemaDefinition{}, mapStorageError(err)
	}
	return a.GetSchemaDefinition(ctx, id)
}

func (a serviceStoreAdapter) DeleteSchemaDefinition(ctx context.Context, id string) error {
	return mapStorageError(a.store.DeleteSchemaDefinition(ctx, id))
}

func (a serviceStoreAdapter) requestWithGrant(ctx context.Context, req storage.Request) (apiservice.Request, error) {
	out := requestFromStorage(req)
	grant, found, err := a.store.GetGrantForRequest(ctx, req.ID)
	if err != nil {
		return apiservice.Request{}, mapStorageError(err)
	}
	if !found {
		return out, nil
	}
	out.GrantID = grant.ID
	out.Grant = map[string]any{
		"grant_id":   grant.ID,
		"created_at": grant.CreatedAt.Format(time.RFC3339Nano),
		"updated_at": grant.UpdatedAt.Format(time.RFC3339Nano),
		"payload":    grant.Payload,
	}
	return out, nil
}

func hostFromStorage(host storage.Host) apiservice.Host {
	return apiservice.Host{ID: host.ID, UniqueKey: host.UniqueKey, Labels: host.Labels, CreatedAt: host.CreatedAt}
}

func requestFromStorage(req storage.Request) apiservice.Request {
	return apiservice.Request{
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

func registerFromStorage(reg storage.Register) apiservice.Register {
	return apiservice.Register{ID: reg.ID, HostID: reg.HostID, SchemaDefinitionID: reg.SchemaDefinitionID, UniqueKey: reg.UniqueKey, Payload: reg.Payload, Labels: reg.Labels, CreatedAt: reg.CreatedAt, UpdatedAt: reg.UpdatedAt}
}

func grantFromStorage(grant storage.Grant) apiservice.Grant {
	return apiservice.Grant{ID: grant.ID, RequestID: grant.RequestID, Payload: grant.Payload, CreatedAt: grant.CreatedAt, UpdatedAt: grant.UpdatedAt}
}

func schemaDefinitionFromStorage(def storage.SchemaDefinition) apiservice.SchemaDefinition {
	return apiservice.SchemaDefinition{ID: def.ID, UniqueKey: def.UniqueKey, Schema: def.Schema, Labels: def.Labels, CreatedAt: def.CreatedAt}
}

func mapStorageError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, storage.ErrHostNotFound):
		return apiservice.ErrHostNotFound
	case errors.Is(err, storage.ErrHostAlreadyExists):
		return apiservice.ErrHostAlreadyExists
	case errors.Is(err, storage.ErrHostUniqueKeyConflict):
		return apiservice.ErrHostUniqueKeyConflict
	case errors.Is(err, storage.ErrRequestNotFound):
		return apiservice.ErrRequestNotFound
	case errors.Is(err, storage.ErrRequestAlreadyExists):
		return apiservice.ErrRequestAlreadyExists
	case errors.Is(err, storage.ErrRequestUniqueKeyConflict):
		return apiservice.ErrRequestUniqueKeyConflict
	case errors.Is(err, storage.ErrGrantNotFound):
		return apiservice.ErrGrantNotFound
	case errors.Is(err, storage.ErrGrantAlreadyExists):
		return apiservice.ErrGrantAlreadyExists
	case errors.Is(err, storage.ErrRegisterNotFound):
		return apiservice.ErrRegisterNotFound
	case errors.Is(err, storage.ErrRegisterAlreadyExists):
		return apiservice.ErrRegisterAlreadyExists
	case errors.Is(err, storage.ErrRegisterUniqueKeyConflict):
		return apiservice.ErrRegisterUniqueKeyConflict
	case errors.Is(err, storage.ErrSchemaDefinitionNotFound):
		return apiservice.ErrSchemaDefinitionNotFound
	case errors.Is(err, storage.ErrSchemaDefinitionAlreadyExists):
		return apiservice.ErrSchemaDefinitionAlreadyExists
	case errors.Is(err, storage.ErrSchemaDefinitionUniqueKeyConflict):
		return apiservice.ErrSchemaDefinitionUniqueKeyConflict
	case errors.Is(err, storage.ErrReferencedHostNotFound):
		return apiservice.ErrReferencedHostNotFound
	case errors.Is(err, storage.ErrReferencedRequestNotFound):
		return apiservice.ErrReferencedRequestNotFound
	default:
		return err
	}
}
