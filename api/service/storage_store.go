package service

import (
	"context"
	"errors"
	"time"

	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

// NewStoreFromDatabase opens a storage-backed Store using either sqlite or
// postgres depending on the database string.
func NewStoreFromDatabase(ctx context.Context, database string) (Store, error) {
	if storage.IsPostgresDSN(database) {
		return NewPostgresStore(ctx, database)
	}
	return NewSQLiteStore(ctx, database)
}

// NewSQLiteStore opens a sqlite-backed Store.
func NewSQLiteStore(ctx context.Context, database string) (Store, error) {
	st, err := storage.New(ctx, database)
	if err != nil {
		return nil, err
	}
	if err := st.Migrate(ctx); err != nil {
		_ = st.Close()
		return nil, err
	}
	return storageStore{store: st}, nil
}

// NewPostgresStore opens a postgres-backed Store.
func NewPostgresStore(ctx context.Context, dsn string) (Store, error) {
	st, err := storage.NewPostgres(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := st.Migrate(ctx); err != nil {
		_ = st.Close()
		return nil, err
	}
	return storageStore{store: st}, nil
}

type storageStore struct {
	store storage.Store
}

func (a storageStore) Close() error {
	return a.store.Close()
}

func (a storageStore) CreateHost(ctx context.Context, payload HostCreatePayload) (Host, error) {
	host, err := a.store.CreateHost(ctx, storage.Host{
		UniqueKey: payload.UniqueKey,
		Labels:    payload.Labels,
	})
	if err != nil {
		return Host{}, mapStorageError(err)
	}
	return hostFromStorage(host), nil
}

func (a storageStore) GetHost(ctx context.Context, id string) (Host, error) {
	host, err := a.store.GetHost(ctx, id)
	if err != nil {
		return Host{}, mapStorageError(err)
	}
	return hostFromStorage(host), nil
}

func (a storageStore) ListHosts(ctx context.Context) ([]Host, error) {
	hosts, err := a.store.ListHosts(ctx)
	if err != nil {
		return nil, mapStorageError(err)
	}
	out := make([]Host, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, hostFromStorage(host))
	}
	return out, nil
}

func (a storageStore) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) (Host, error) {
	if err := a.store.UpdateHostLabels(ctx, id, labels); err != nil {
		return Host{}, mapStorageError(err)
	}
	host, err := a.store.GetHost(ctx, id)
	if err != nil {
		return Host{}, mapStorageError(err)
	}
	return hostFromStorage(host), nil
}

func (a storageStore) DeleteHost(ctx context.Context, id string) error {
	return mapStorageError(a.store.DeleteHost(ctx, id))
}

func (a storageStore) CreateRequest(ctx context.Context, payload RequestCreatePayload) (Request, error) {
	req, err := a.store.CreateRequest(ctx, storage.Request{
		HostID:                    payload.HostID,
		RequestSchemaDefinitionID: payload.RequestSchemaDefinitionID,
		GrantSchemaDefinitionID:   payload.GrantSchemaDefinitionID,
		UniqueKey:                 payload.UniqueKey,
		Payload:                   payload.Payload,
		Mutable:                   payload.Mutable,
		Labels:                    payload.Labels,
	})
	if err != nil {
		return Request{}, mapStorageError(err)
	}
	return a.GetRequest(ctx, req.ID)
}

func (a storageStore) GetRequest(ctx context.Context, id string) (Request, error) {
	req, err := a.store.GetRequest(ctx, id)
	if err != nil {
		return Request{}, mapStorageError(err)
	}
	return a.requestWithGrant(ctx, req)
}

func (a storageStore) ListRequests(ctx context.Context, opts RequestListOptions) ([]Request, error) {
	filters := storage.RequestListFilters{
		HasGrant:   opts.HasGrant,
		Labels:     opts.Labels,
		HostLabels: opts.HostLabels,
	}
	requests, err := a.store.ListRequests(ctx, &filters)
	if err != nil {
		return nil, mapStorageError(err)
	}
	out := make([]Request, 0, len(requests))
	for _, req := range requests {
		enriched, err := a.requestWithGrant(ctx, req)
		if err != nil {
			return nil, err
		}
		out = append(out, enriched)
	}
	return out, nil
}

func (a storageStore) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) (Request, error) {
	return a.UpdateRequest(ctx, id, RequestUpdatePayload{Labels: &labels})
}

func (a storageStore) UpdateRequest(ctx context.Context, id string, payload RequestUpdatePayload) (Request, error) {
	if err := a.store.UpdateRequest(ctx, id, payload.Payload, payload.Labels); err != nil {
		return Request{}, mapStorageError(err)
	}
	return a.GetRequest(ctx, id)
}

func (a storageStore) DeleteRequest(ctx context.Context, id string) error {
	return mapStorageError(a.store.DeleteRequest(ctx, id))
}

func (a storageStore) CreateRegister(ctx context.Context, payload RegisterCreatePayload) (Register, error) {
	reg, err := a.store.CreateRegister(ctx, storage.Register{
		HostID:             payload.HostID,
		SchemaDefinitionID: payload.SchemaDefinitionID,
		UniqueKey:          payload.UniqueKey,
		Payload:            payload.Payload,
		Mutable:            payload.Mutable,
		Labels:             payload.Labels,
	})
	if err != nil {
		return Register{}, mapStorageError(err)
	}
	return a.GetRegister(ctx, reg.ID)
}

func (a storageStore) GetRegister(ctx context.Context, id string) (Register, error) {
	reg, err := a.store.GetRegister(ctx, id)
	if err != nil {
		return Register{}, mapStorageError(err)
	}
	return registerFromStorage(reg), nil
}

func (a storageStore) ListRegisters(ctx context.Context, opts RegisterListOptions) ([]Register, error) {
	filters := storage.RegisterListFilters{
		Labels:     opts.Labels,
		HostLabels: opts.HostLabels,
	}
	registers, err := a.store.ListRegisters(ctx, &filters)
	if err != nil {
		return nil, mapStorageError(err)
	}
	out := make([]Register, 0, len(registers))
	for _, reg := range registers {
		out = append(out, registerFromStorage(reg))
	}
	return out, nil
}

func (a storageStore) UpdateRegister(ctx context.Context, id string, payload RegisterUpdatePayload) (Register, error) {
	if err := a.store.UpdateRegister(ctx, id, payload.Payload, payload.Labels); err != nil {
		return Register{}, mapStorageError(err)
	}
	return a.GetRegister(ctx, id)
}

func (a storageStore) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) (Register, error) {
	return a.UpdateRegister(ctx, id, RegisterUpdatePayload{Labels: &labels})
}

func (a storageStore) ListRegisterEvents(ctx context.Context, registerID string) ([]RegisterEvent, error) {
	events, err := a.store.ListRegisterEvents(ctx, registerID)
	if err != nil {
		return nil, mapStorageError(err)
	}
	out := make([]RegisterEvent, 0, len(events))
	for _, event := range events {
		out = append(out, registerEventFromStorage(event))
	}
	return out, nil
}

func (a storageStore) DeleteRegister(ctx context.Context, id string) error {
	return mapStorageError(a.store.DeleteRegister(ctx, id))
}

func (a storageStore) CreateGrant(ctx context.Context, payload GrantCreatePayload) (Grant, error) {
	grant, err := a.store.CreateGrant(ctx, storage.Grant{
		RequestID:      payload.RequestID,
		RequestVersion: payload.RequestVersion,
		Payload:        payload.Payload,
	})
	if err != nil {
		return Grant{}, mapStorageError(err)
	}
	return a.GetGrant(ctx, grant.ID)
}

func (a storageStore) GetGrant(ctx context.Context, id string) (Grant, error) {
	grant, err := a.store.GetGrant(ctx, id)
	if err != nil {
		return Grant{}, mapStorageError(err)
	}
	return grantFromStorage(grant), nil
}

func (a storageStore) ListGrants(ctx context.Context) ([]Grant, error) {
	grants, err := a.store.ListGrants(ctx)
	if err != nil {
		return nil, mapStorageError(err)
	}
	out := make([]Grant, 0, len(grants))
	for _, grant := range grants {
		out = append(out, grantFromStorage(grant))
	}
	return out, nil
}

func (a storageStore) DeleteGrant(ctx context.Context, id string) error {
	return mapStorageError(a.store.DeleteGrant(ctx, id))
}

func (a storageStore) UpdateGrant(ctx context.Context, id string, payload GrantUpdatePayload) (Grant, error) {
	if err := a.store.UpdateGrant(ctx, id, payload.Payload, payload.RequestVersion); err != nil {
		return Grant{}, mapStorageError(err)
	}
	return a.GetGrant(ctx, id)
}

func (a storageStore) CreateSchemaDefinition(ctx context.Context, payload SchemaDefinitionCreatePayload) (SchemaDefinition, error) {
	def, err := a.store.CreateSchemaDefinition(ctx, storage.SchemaDefinition{
		UniqueKey: payload.UniqueKey,
		Schema:    payload.Schema,
		Labels:    payload.Labels,
	})
	if err != nil {
		return SchemaDefinition{}, mapStorageError(err)
	}
	return a.GetSchemaDefinition(ctx, def.ID)
}

func (a storageStore) GetSchemaDefinition(ctx context.Context, id string) (SchemaDefinition, error) {
	def, err := a.store.GetSchemaDefinition(ctx, id)
	if err != nil {
		return SchemaDefinition{}, mapStorageError(err)
	}
	return schemaDefinitionFromStorage(def), nil
}

func (a storageStore) ListSchemaDefinitions(ctx context.Context) ([]SchemaDefinition, error) {
	defs, err := a.store.ListSchemaDefinitions(ctx)
	if err != nil {
		return nil, mapStorageError(err)
	}
	out := make([]SchemaDefinition, 0, len(defs))
	for _, def := range defs {
		out = append(out, schemaDefinitionFromStorage(def))
	}
	return out, nil
}

func (a storageStore) UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) (SchemaDefinition, error) {
	if err := a.store.UpdateSchemaDefinitionLabels(ctx, id, labels); err != nil {
		return SchemaDefinition{}, mapStorageError(err)
	}
	return a.GetSchemaDefinition(ctx, id)
}

func (a storageStore) DeleteSchemaDefinition(ctx context.Context, id string) error {
	return mapStorageError(a.store.DeleteSchemaDefinition(ctx, id))
}

func (a storageStore) requestWithGrant(ctx context.Context, req storage.Request) (Request, error) {
	out := requestFromStorage(req)
	grant, found, err := a.store.GetGrantForRequest(ctx, req.ID)
	if err != nil {
		return Request{}, mapStorageError(err)
	}
	if !found {
		return out, nil
	}
	out.GrantID = grant.ID
	out.Grant = map[string]any{
		"grant_id":        grant.ID,
		"request_version": grant.RequestVersion,
		"created_at":      grant.CreatedAt.Format(time.RFC3339Nano),
		"updated_at":      grant.UpdatedAt.Format(time.RFC3339Nano),
		"payload":         grant.Payload,
	}
	return out, nil
}

func hostFromStorage(host storage.Host) Host {
	return Host{
		ID:        host.ID,
		UniqueKey: host.UniqueKey,
		Labels:    host.Labels,
		CreatedAt: host.CreatedAt,
	}
}

func requestFromStorage(req storage.Request) Request {
	return Request{
		ID:                        req.ID,
		HostID:                    req.HostID,
		RequestSchemaDefinitionID: req.RequestSchemaDefinitionID,
		GrantSchemaDefinitionID:   req.GrantSchemaDefinitionID,
		UniqueKey:                 req.UniqueKey,
		Payload:                   req.Payload,
		Mutable:                   req.Mutable,
		Version:                   req.Version,
		Labels:                    req.Labels,
		HasGrant:                  req.HasGrant,
		CreatedAt:                 req.CreatedAt,
		UpdatedAt:                 req.UpdatedAt,
	}
}

func registerFromStorage(reg storage.Register) Register {
	return Register{
		ID:                 reg.ID,
		HostID:             reg.HostID,
		SchemaDefinitionID: reg.SchemaDefinitionID,
		UniqueKey:          reg.UniqueKey,
		Payload:            reg.Payload,
		Mutable:            reg.Mutable,
		Labels:             reg.Labels,
		CreatedAt:          reg.CreatedAt,
		UpdatedAt:          reg.UpdatedAt,
	}
}

func registerEventFromStorage(event storage.RegisterEvent) RegisterEvent {
	return RegisterEvent{
		ID:         event.ID,
		RegisterID: event.RegisterID,
		EventType:  event.EventType,
		OldPayload: event.OldPayload,
		NewPayload: event.NewPayload,
		OldLabels:  event.OldLabels,
		NewLabels:  event.NewLabels,
		CreatedAt:  event.CreatedAt,
	}
}

func grantFromStorage(grant storage.Grant) Grant {
	return Grant{
		ID:             grant.ID,
		RequestID:      grant.RequestID,
		RequestVersion: grant.RequestVersion,
		Payload:        grant.Payload,
		CreatedAt:      grant.CreatedAt,
		UpdatedAt:      grant.UpdatedAt,
	}
}

func schemaDefinitionFromStorage(def storage.SchemaDefinition) SchemaDefinition {
	return SchemaDefinition{
		ID:        def.ID,
		UniqueKey: def.UniqueKey,
		Schema:    def.Schema,
		Labels:    def.Labels,
		CreatedAt: def.CreatedAt,
	}
}

func mapStorageError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, storage.ErrHostNotFound):
		return ErrHostNotFound
	case errors.Is(err, storage.ErrHostAlreadyExists):
		return ErrHostAlreadyExists
	case errors.Is(err, storage.ErrHostUniqueKeyConflict):
		return ErrHostUniqueKeyConflict
	case errors.Is(err, storage.ErrRequestNotFound):
		return ErrRequestNotFound
	case errors.Is(err, storage.ErrRequestAlreadyExists):
		return ErrRequestAlreadyExists
	case errors.Is(err, storage.ErrRequestUniqueKeyConflict):
		return ErrRequestUniqueKeyConflict
	case errors.Is(err, storage.ErrRequestImmutable):
		return ErrRequestImmutable
	case errors.Is(err, storage.ErrGrantNotFound):
		return ErrGrantNotFound
	case errors.Is(err, storage.ErrGrantAlreadyExists):
		return ErrGrantAlreadyExists
	case errors.Is(err, storage.ErrGrantRequestVersionConflict):
		return ErrGrantRequestVersionConflict
	case errors.Is(err, storage.ErrRegisterNotFound):
		return ErrRegisterNotFound
	case errors.Is(err, storage.ErrRegisterAlreadyExists):
		return ErrRegisterAlreadyExists
	case errors.Is(err, storage.ErrRegisterUniqueKeyConflict):
		return ErrRegisterUniqueKeyConflict
	case errors.Is(err, storage.ErrRegisterImmutable):
		return ErrRegisterImmutable
	case errors.Is(err, storage.ErrSchemaDefinitionNotFound):
		return ErrSchemaDefinitionNotFound
	case errors.Is(err, storage.ErrSchemaDefinitionAlreadyExists):
		return ErrSchemaDefinitionAlreadyExists
	case errors.Is(err, storage.ErrSchemaDefinitionUniqueKeyConflict):
		return ErrSchemaDefinitionUniqueKeyConflict
	case errors.Is(err, storage.ErrReferencedHostNotFound):
		return ErrReferencedHostNotFound
	case errors.Is(err, storage.ErrReferencedRequestNotFound):
		return ErrReferencedRequestNotFound
	default:
		return err
	}
}
