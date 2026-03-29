package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type fakeStore struct {
	closeFn                        func() error
	createHostFn                   func(context.Context, HostCreatePayload) (Host, error)
	getHostFn                      func(context.Context, string) (Host, error)
	listHostsFn                    func(context.Context) ([]Host, error)
	updateHostLabelsFn             func(context.Context, string, map[string]string) (Host, error)
	deleteHostFn                   func(context.Context, string) error
	createRequestFn                func(context.Context, RequestCreatePayload) (Request, error)
	getRequestFn                   func(context.Context, string) (Request, error)
	listRequestsFn                 func(context.Context, RequestListOptions) ([]Request, error)
	updateRequestFn                func(context.Context, string, RequestUpdatePayload) (Request, error)
	updateRequestLabelsFn          func(context.Context, string, map[string]string) (Request, error)
	deleteRequestFn                func(context.Context, string) error
	createRegisterFn               func(context.Context, RegisterCreatePayload) (Register, error)
	getRegisterFn                  func(context.Context, string) (Register, error)
	listRegistersFn                func(context.Context, RegisterListOptions) ([]Register, error)
	updateRegisterFn               func(context.Context, string, RegisterUpdatePayload) (Register, error)
	updateRegisterLabelsFn         func(context.Context, string, map[string]string) (Register, error)
	listRegisterEventsFn           func(context.Context, string) ([]RegisterEvent, error)
	deleteRegisterFn               func(context.Context, string) error
	createGrantFn                  func(context.Context, GrantCreatePayload) (Grant, error)
	getGrantFn                     func(context.Context, string) (Grant, error)
	listGrantsFn                   func(context.Context) ([]Grant, error)
	updateGrantFn                  func(context.Context, string, GrantUpdatePayload) (Grant, error)
	deleteGrantFn                  func(context.Context, string) error
	createSchemaDefinitionFn       func(context.Context, SchemaDefinitionCreatePayload) (SchemaDefinition, error)
	getSchemaDefinitionFn          func(context.Context, string) (SchemaDefinition, error)
	listSchemaDefinitionsFn        func(context.Context) ([]SchemaDefinition, error)
	updateSchemaDefinitionLabelsFn func(context.Context, string, map[string]string) (SchemaDefinition, error)
	deleteSchemaDefinitionFn       func(context.Context, string) error
}

func (f *fakeStore) Close() error {
	if f.closeFn == nil {
		return nil
	}
	return f.closeFn()
}

func (f *fakeStore) CreateHost(ctx context.Context, payload HostCreatePayload) (Host, error) {
	if f.createHostFn == nil {
		return Host{}, fmt.Errorf("unexpected CreateHost")
	}
	return f.createHostFn(ctx, payload)
}
func (f *fakeStore) GetHost(ctx context.Context, id string) (Host, error) {
	if f.getHostFn == nil {
		return Host{}, fmt.Errorf("unexpected GetHost")
	}
	return f.getHostFn(ctx, id)
}
func (f *fakeStore) ListHosts(ctx context.Context) ([]Host, error) {
	if f.listHostsFn == nil {
		return nil, fmt.Errorf("unexpected ListHosts")
	}
	return f.listHostsFn(ctx)
}
func (f *fakeStore) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) (Host, error) {
	if f.updateHostLabelsFn == nil {
		return Host{}, fmt.Errorf("unexpected UpdateHostLabels")
	}
	return f.updateHostLabelsFn(ctx, id, labels)
}
func (f *fakeStore) DeleteHost(ctx context.Context, id string) error {
	if f.deleteHostFn == nil {
		return fmt.Errorf("unexpected DeleteHost")
	}
	return f.deleteHostFn(ctx, id)
}
func (f *fakeStore) CreateRequest(ctx context.Context, payload RequestCreatePayload) (Request, error) {
	if f.createRequestFn == nil {
		return Request{}, fmt.Errorf("unexpected CreateRequest")
	}
	return f.createRequestFn(ctx, payload)
}
func (f *fakeStore) GetRequest(ctx context.Context, id string) (Request, error) {
	if f.getRequestFn == nil {
		return Request{}, fmt.Errorf("unexpected GetRequest")
	}
	return f.getRequestFn(ctx, id)
}
func (f *fakeStore) ListRequests(ctx context.Context, opts RequestListOptions) ([]Request, error) {
	if f.listRequestsFn == nil {
		return nil, fmt.Errorf("unexpected ListRequests")
	}
	return f.listRequestsFn(ctx, opts)
}
func (f *fakeStore) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) (Request, error) {
	if f.updateRequestLabelsFn == nil {
		return Request{}, fmt.Errorf("unexpected UpdateRequestLabels")
	}
	return f.updateRequestLabelsFn(ctx, id, labels)
}
func (f *fakeStore) UpdateRequest(ctx context.Context, id string, payload RequestUpdatePayload) (Request, error) {
	if f.updateRequestFn == nil {
		return Request{}, fmt.Errorf("unexpected UpdateRequest")
	}
	return f.updateRequestFn(ctx, id, payload)
}
func (f *fakeStore) DeleteRequest(ctx context.Context, id string) error {
	if f.deleteRequestFn == nil {
		return fmt.Errorf("unexpected DeleteRequest")
	}
	return f.deleteRequestFn(ctx, id)
}
func (f *fakeStore) CreateRegister(ctx context.Context, payload RegisterCreatePayload) (Register, error) {
	if f.createRegisterFn == nil {
		return Register{}, fmt.Errorf("unexpected CreateRegister")
	}
	return f.createRegisterFn(ctx, payload)
}
func (f *fakeStore) GetRegister(ctx context.Context, id string) (Register, error) {
	if f.getRegisterFn == nil {
		return Register{}, fmt.Errorf("unexpected GetRegister")
	}
	return f.getRegisterFn(ctx, id)
}
func (f *fakeStore) ListRegisters(ctx context.Context, opts RegisterListOptions) ([]Register, error) {
	if f.listRegistersFn == nil {
		return nil, fmt.Errorf("unexpected ListRegisters")
	}
	return f.listRegistersFn(ctx, opts)
}
func (f *fakeStore) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) (Register, error) {
	if f.updateRegisterLabelsFn == nil {
		return Register{}, fmt.Errorf("unexpected UpdateRegisterLabels")
	}
	return f.updateRegisterLabelsFn(ctx, id, labels)
}
func (f *fakeStore) UpdateRegister(ctx context.Context, id string, payload RegisterUpdatePayload) (Register, error) {
	if f.updateRegisterFn == nil {
		return Register{}, fmt.Errorf("unexpected UpdateRegister")
	}
	return f.updateRegisterFn(ctx, id, payload)
}
func (f *fakeStore) ListRegisterEvents(ctx context.Context, registerID string) ([]RegisterEvent, error) {
	if f.listRegisterEventsFn == nil {
		return nil, fmt.Errorf("unexpected ListRegisterEvents")
	}
	return f.listRegisterEventsFn(ctx, registerID)
}
func (f *fakeStore) DeleteRegister(ctx context.Context, id string) error {
	if f.deleteRegisterFn == nil {
		return fmt.Errorf("unexpected DeleteRegister")
	}
	return f.deleteRegisterFn(ctx, id)
}
func (f *fakeStore) CreateGrant(ctx context.Context, payload GrantCreatePayload) (Grant, error) {
	if f.createGrantFn == nil {
		return Grant{}, fmt.Errorf("unexpected CreateGrant")
	}
	return f.createGrantFn(ctx, payload)
}
func (f *fakeStore) GetGrant(ctx context.Context, id string) (Grant, error) {
	if f.getGrantFn == nil {
		return Grant{}, fmt.Errorf("unexpected GetGrant")
	}
	return f.getGrantFn(ctx, id)
}
func (f *fakeStore) ListGrants(ctx context.Context) ([]Grant, error) {
	if f.listGrantsFn == nil {
		return nil, fmt.Errorf("unexpected ListGrants")
	}
	return f.listGrantsFn(ctx)
}
func (f *fakeStore) DeleteGrant(ctx context.Context, id string) error {
	if f.deleteGrantFn == nil {
		return fmt.Errorf("unexpected DeleteGrant")
	}
	return f.deleteGrantFn(ctx, id)
}
func (f *fakeStore) UpdateGrant(ctx context.Context, id string, payload GrantUpdatePayload) (Grant, error) {
	if f.updateGrantFn == nil {
		return Grant{}, fmt.Errorf("unexpected UpdateGrant")
	}
	return f.updateGrantFn(ctx, id, payload)
}
func (f *fakeStore) CreateSchemaDefinition(ctx context.Context, payload SchemaDefinitionCreatePayload) (SchemaDefinition, error) {
	if f.createSchemaDefinitionFn == nil {
		return SchemaDefinition{}, fmt.Errorf("unexpected CreateSchemaDefinition")
	}
	return f.createSchemaDefinitionFn(ctx, payload)
}
func (f *fakeStore) GetSchemaDefinition(ctx context.Context, id string) (SchemaDefinition, error) {
	if f.getSchemaDefinitionFn == nil {
		return SchemaDefinition{}, fmt.Errorf("unexpected GetSchemaDefinition")
	}
	return f.getSchemaDefinitionFn(ctx, id)
}
func (f *fakeStore) ListSchemaDefinitions(ctx context.Context) ([]SchemaDefinition, error) {
	if f.listSchemaDefinitionsFn == nil {
		return nil, fmt.Errorf("unexpected ListSchemaDefinitions")
	}
	return f.listSchemaDefinitionsFn(ctx)
}
func (f *fakeStore) UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) (SchemaDefinition, error) {
	if f.updateSchemaDefinitionLabelsFn == nil {
		return SchemaDefinition{}, fmt.Errorf("unexpected UpdateSchemaDefinitionLabels")
	}
	return f.updateSchemaDefinitionLabelsFn(ctx, id, labels)
}
func (f *fakeStore) DeleteSchemaDefinition(ctx context.Context, id string) error {
	if f.deleteSchemaDefinitionFn == nil {
		return fmt.Errorf("unexpected DeleteSchemaDefinition")
	}
	return f.deleteSchemaDefinitionFn(ctx, id)
}

func TestServiceValidationRequiredFields(t *testing.T) {
	t.Parallel()

	svc := New(&fakeStore{})
	_, err := svc.CreateRequest(context.Background(), RequestCreatePayload{})
	if err == nil || !strings.Contains(err.Error(), "host_id is required") {
		t.Fatalf("expected host_id validation error, got %v", err)
	}

	_, err = svc.CreateRegister(context.Background(), RegisterCreatePayload{})
	if err == nil || !strings.Contains(err.Error(), "host_id is required") {
		t.Fatalf("expected host_id validation error, got %v", err)
	}

	_, err = svc.CreateGrant(context.Background(), GrantCreatePayload{})
	if err == nil || !strings.Contains(err.Error(), "request_id is required") {
		t.Fatalf("expected request_id validation error, got %v", err)
	}

	_, err = svc.UpdateGrant(context.Background(), "grant-1", GrantUpdatePayload{RequestVersion: 1})
	if err == nil || !strings.Contains(err.Error(), "payload is required") {
		t.Fatalf("expected payload validation error, got %v", err)
	}
}

func TestServiceSchemaValidationForRequestRegisterAndGrant(t *testing.T) {
	t.Parallel()

	validSchema := json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)
	store := &fakeStore{
		getSchemaDefinitionFn: func(context.Context, string) (SchemaDefinition, error) {
			return SchemaDefinition{ID: "def-1", Schema: validSchema}, nil
		},
		createRequestFn: func(context.Context, RequestCreatePayload) (Request, error) {
			return Request{ID: "req-1"}, nil
		},
		createRegisterFn: func(context.Context, RegisterCreatePayload) (Register, error) {
			return Register{ID: "reg-1"}, nil
		},
		getRequestFn: func(context.Context, string) (Request, error) {
			return Request{ID: "req-1", GrantSchemaDefinitionID: "def-1"}, nil
		},
		createGrantFn: func(context.Context, GrantCreatePayload) (Grant, error) {
			return Grant{ID: "gr-1"}, nil
		},
	}
	svc := New(store)

	_, err := svc.CreateRequest(context.Background(), RequestCreatePayload{
		HostID:                    "host-1",
		RequestSchemaDefinitionID: "def-1",
		Payload:                   map[string]any{"name": 123},
	})
	if err == nil || !strings.Contains(err.Error(), "does not match schema") {
		t.Fatalf("expected request schema mismatch, got %v", err)
	}

	_, err = svc.CreateRegister(context.Background(), RegisterCreatePayload{
		HostID:             "host-1",
		SchemaDefinitionID: "def-1",
		Payload:            map[string]any{"name": 123},
	})
	if err == nil || !strings.Contains(err.Error(), "does not match schema") {
		t.Fatalf("expected register schema mismatch, got %v", err)
	}

	_, err = svc.CreateGrant(context.Background(), GrantCreatePayload{
		RequestID:      "req-1",
		RequestVersion: 1,
		Payload:        map[string]any{"name": 123},
	})
	if err == nil || !strings.Contains(err.Error(), "does not match schema") {
		t.Fatalf("expected grant schema mismatch, got %v", err)
	}
}

func TestServicePropagatesSchemaDefinitionErrors(t *testing.T) {
	t.Parallel()

	store := &fakeStore{
		getSchemaDefinitionFn: func(context.Context, string) (SchemaDefinition, error) {
			return SchemaDefinition{}, ErrSchemaDefinitionNotFound
		},
	}
	svc := New(store)
	_, err := svc.CreateRequest(context.Background(), RequestCreatePayload{
		HostID:                    "host-1",
		RequestSchemaDefinitionID: "missing",
	})
	if !errors.Is(err, ErrSchemaDefinitionNotFound) {
		t.Fatalf("expected ErrSchemaDefinitionNotFound, got %v", err)
	}
}

func TestServiceCreateSchemaDefinitionValidation(t *testing.T) {
	t.Parallel()

	store := &fakeStore{
		createSchemaDefinitionFn: func(_ context.Context, payload SchemaDefinitionCreatePayload) (SchemaDefinition, error) {
			return SchemaDefinition{ID: "def-1", Schema: payload.Schema, CreatedAt: time.Now()}, nil
		},
	}
	svc := New(store)

	_, err := svc.CreateSchemaDefinition(context.Background(), SchemaDefinitionCreatePayload{
		Schema: json.RawMessage(`null`),
	})
	if err == nil || !strings.Contains(err.Error(), "schema is required") {
		t.Fatalf("expected required schema error, got %v", err)
	}

	_, err = svc.CreateSchemaDefinition(context.Background(), SchemaDefinitionCreatePayload{
		Schema: json.RawMessage(`{"type":"object",`),
	})
	if err == nil || !strings.Contains(err.Error(), "must be valid JSON") {
		t.Fatalf("expected invalid json error, got %v", err)
	}
}

func TestServiceUpdateRequestValidatesPayloadAgainstSchema(t *testing.T) {
	t.Parallel()

	validSchema := json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)
	store := &fakeStore{
		getRequestFn: func(context.Context, string) (Request, error) {
			return Request{ID: "req-1", Mutable: true, RequestSchemaDefinitionID: "def-1"}, nil
		},
		getSchemaDefinitionFn: func(context.Context, string) (SchemaDefinition, error) {
			return SchemaDefinition{ID: "def-1", Schema: validSchema}, nil
		},
	}
	svc := New(store)

	payload := map[string]any{"name": 123}
	_, err := svc.UpdateRequest(context.Background(), "req-1", RequestUpdatePayload{Payload: &payload})
	if err == nil || !strings.Contains(err.Error(), "does not match schema") {
		t.Fatalf("expected request schema mismatch, got %v", err)
	}
}

func TestServiceUpdateGrantValidatesPayloadAgainstSchema(t *testing.T) {
	t.Parallel()

	validSchema := json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)
	store := &fakeStore{
		getGrantFn: func(context.Context, string) (Grant, error) {
			return Grant{ID: "grant-1", RequestID: "req-1"}, nil
		},
		getRequestFn: func(context.Context, string) (Request, error) {
			return Request{ID: "req-1", Version: 1, GrantSchemaDefinitionID: "def-1"}, nil
		},
		getSchemaDefinitionFn: func(context.Context, string) (SchemaDefinition, error) {
			return SchemaDefinition{ID: "def-1", Schema: validSchema}, nil
		},
	}
	svc := New(store)

	_, err := svc.UpdateGrant(context.Background(), "grant-1", GrantUpdatePayload{
		RequestVersion: 1,
		Payload:        map[string]any{"name": 123},
	})
	if err == nil || !strings.Contains(err.Error(), "does not match schema") {
		t.Fatalf("expected grant schema mismatch, got %v", err)
	}
}

func TestServiceUpdateRequestReturnsImmutableBeforeSchemaValidation(t *testing.T) {
	t.Parallel()

	validSchema := json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)
	schemaLookups := 0
	store := &fakeStore{
		getRequestFn: func(context.Context, string) (Request, error) {
			return Request{ID: "req-1", Mutable: false, RequestSchemaDefinitionID: "def-1"}, nil
		},
		getSchemaDefinitionFn: func(context.Context, string) (SchemaDefinition, error) {
			schemaLookups++
			return SchemaDefinition{ID: "def-1", Schema: validSchema}, nil
		},
	}
	svc := New(store)

	payload := map[string]any{"name": 123}
	_, err := svc.UpdateRequest(context.Background(), "req-1", RequestUpdatePayload{Payload: &payload})
	if !errors.Is(err, ErrRequestImmutable) {
		t.Fatalf("expected ErrRequestImmutable, got %v", err)
	}
	if schemaLookups != 0 {
		t.Fatalf("expected no schema lookup on immutable request, got %d", schemaLookups)
	}
}

func TestServiceUpdateGrantReturnsVersionConflictBeforeSchemaValidation(t *testing.T) {
	t.Parallel()

	validSchema := json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)
	schemaLookups := 0
	store := &fakeStore{
		getGrantFn: func(context.Context, string) (Grant, error) {
			return Grant{ID: "grant-1", RequestID: "req-1"}, nil
		},
		getRequestFn: func(context.Context, string) (Request, error) {
			return Request{ID: "req-1", Version: 2, GrantSchemaDefinitionID: "def-1"}, nil
		},
		getSchemaDefinitionFn: func(context.Context, string) (SchemaDefinition, error) {
			schemaLookups++
			return SchemaDefinition{ID: "def-1", Schema: validSchema}, nil
		},
	}
	svc := New(store)

	_, err := svc.UpdateGrant(context.Background(), "grant-1", GrantUpdatePayload{
		RequestVersion: 1,
		Payload:        map[string]any{"name": 123},
	})
	if !errors.Is(err, ErrGrantRequestVersionConflict) {
		t.Fatalf("expected ErrGrantRequestVersionConflict, got %v", err)
	}
	if schemaLookups != 0 {
		t.Fatalf("expected no schema lookup on version conflict, got %d", schemaLookups)
	}
}
