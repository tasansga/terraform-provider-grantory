package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Service provides function-based Grantory operations over a Store backend.
type Service struct {
	store Store
}

func New(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) CreateHost(ctx context.Context, payload HostCreatePayload) (Host, error) {
	return s.store.CreateHost(ctx, payload)
}

func (s *Service) GetHost(ctx context.Context, id string) (Host, error) {
	return s.store.GetHost(ctx, id)
}

func (s *Service) ListHosts(ctx context.Context) ([]Host, error) {
	return s.store.ListHosts(ctx)
}

func (s *Service) UpdateHostLabels(ctx context.Context, id string, labels map[string]string) (Host, error) {
	return s.store.UpdateHostLabels(ctx, id, labels)
}

func (s *Service) DeleteHost(ctx context.Context, id string) error {
	return s.store.DeleteHost(ctx, id)
}

func (s *Service) CreateRequest(ctx context.Context, payload RequestCreatePayload) (Request, error) {
	if payload.HostID == "" {
		return Request{}, fmt.Errorf("host_id is required")
	}
	if payload.RequestSchemaDefinitionID != "" {
		def, err := s.store.GetSchemaDefinition(ctx, payload.RequestSchemaDefinitionID)
		if err != nil {
			return Request{}, err
		}
		if err := validateJSONInstance(def.Schema, payload.Payload, "request payload", "schema"); err != nil {
			return Request{}, err
		}
	}
	if payload.GrantSchemaDefinitionID != "" {
		if _, err := s.store.GetSchemaDefinition(ctx, payload.GrantSchemaDefinitionID); err != nil {
			return Request{}, err
		}
	}
	return s.store.CreateRequest(ctx, payload)
}

func (s *Service) GetRequest(ctx context.Context, id string) (Request, error) {
	return s.store.GetRequest(ctx, id)
}

func (s *Service) ListRequests(ctx context.Context, opts RequestListOptions) ([]Request, error) {
	return s.store.ListRequests(ctx, opts)
}

func (s *Service) UpdateRequestLabels(ctx context.Context, id string, labels map[string]string) (Request, error) {
	return s.store.UpdateRequestLabels(ctx, id, labels)
}

func (s *Service) DeleteRequest(ctx context.Context, id string) error {
	return s.store.DeleteRequest(ctx, id)
}

func (s *Service) CreateRegister(ctx context.Context, payload RegisterCreatePayload) (Register, error) {
	if payload.HostID == "" {
		return Register{}, fmt.Errorf("host_id is required")
	}
	if payload.SchemaDefinitionID != "" {
		def, err := s.store.GetSchemaDefinition(ctx, payload.SchemaDefinitionID)
		if err != nil {
			return Register{}, err
		}
		if err := validateJSONInstance(def.Schema, payload.Payload, "register payload", "schema"); err != nil {
			return Register{}, err
		}
	}
	return s.store.CreateRegister(ctx, payload)
}

func (s *Service) GetRegister(ctx context.Context, id string) (Register, error) {
	return s.store.GetRegister(ctx, id)
}

func (s *Service) ListRegisters(ctx context.Context, opts RegisterListOptions) ([]Register, error) {
	return s.store.ListRegisters(ctx, opts)
}

func (s *Service) UpdateRegister(ctx context.Context, id string, payload RegisterUpdatePayload) (Register, error) {
	if payload.Payload == nil && payload.Labels == nil {
		return Register{}, fmt.Errorf("payload and/or labels are required")
	}
	if payload.Payload != nil {
		reg, err := s.store.GetRegister(ctx, id)
		if err != nil {
			return Register{}, err
		}
		if reg.SchemaDefinitionID != "" {
			def, err := s.store.GetSchemaDefinition(ctx, reg.SchemaDefinitionID)
			if err != nil {
				return Register{}, err
			}
			if err := validateJSONInstance(def.Schema, *payload.Payload, "register payload", "schema"); err != nil {
				return Register{}, err
			}
		}
	}
	return s.store.UpdateRegister(ctx, id, payload)
}

func (s *Service) UpdateRegisterLabels(ctx context.Context, id string, labels map[string]string) (Register, error) {
	return s.UpdateRegister(ctx, id, RegisterUpdatePayload{Labels: &labels})
}

func (s *Service) ListRegisterEvents(ctx context.Context, registerID string) ([]RegisterEvent, error) {
	return s.store.ListRegisterEvents(ctx, registerID)
}

func (s *Service) DeleteRegister(ctx context.Context, id string) error {
	return s.store.DeleteRegister(ctx, id)
}

func (s *Service) CreateGrant(ctx context.Context, payload GrantCreatePayload) (Grant, error) {
	if payload.RequestID == "" {
		return Grant{}, fmt.Errorf("request_id is required")
	}
	req, err := s.store.GetRequest(ctx, payload.RequestID)
	if err != nil {
		return Grant{}, err
	}
	if req.GrantSchemaDefinitionID != "" {
		def, err := s.store.GetSchemaDefinition(ctx, req.GrantSchemaDefinitionID)
		if err != nil {
			return Grant{}, err
		}
		if err := validateJSONInstance(def.Schema, payload.Payload, "grant payload", "schema"); err != nil {
			return Grant{}, err
		}
	}
	return s.store.CreateGrant(ctx, payload)
}

func (s *Service) GetGrant(ctx context.Context, id string) (Grant, error) {
	return s.store.GetGrant(ctx, id)
}

func (s *Service) ListGrants(ctx context.Context) ([]Grant, error) {
	return s.store.ListGrants(ctx)
}

func (s *Service) DeleteGrant(ctx context.Context, id string) error {
	return s.store.DeleteGrant(ctx, id)
}

func (s *Service) CreateSchemaDefinition(ctx context.Context, payload SchemaDefinitionCreatePayload) (SchemaDefinition, error) {
	if err := requireJSONValue(payload.Schema, "schema"); err != nil {
		return SchemaDefinition{}, err
	}
	if err := validateJSONSchema(payload.Schema, "schema"); err != nil {
		return SchemaDefinition{}, err
	}
	return s.store.CreateSchemaDefinition(ctx, payload)
}

func (s *Service) GetSchemaDefinition(ctx context.Context, id string) (SchemaDefinition, error) {
	return s.store.GetSchemaDefinition(ctx, id)
}

func (s *Service) ListSchemaDefinitions(ctx context.Context) ([]SchemaDefinition, error) {
	return s.store.ListSchemaDefinitions(ctx)
}

func (s *Service) UpdateSchemaDefinitionLabels(ctx context.Context, id string, labels map[string]string) (SchemaDefinition, error) {
	return s.store.UpdateSchemaDefinitionLabels(ctx, id, labels)
}

func (s *Service) DeleteSchemaDefinition(ctx context.Context, id string) error {
	return s.store.DeleteSchemaDefinition(ctx, id)
}

func requireJSONValue(value json.RawMessage, field string) error {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("%s is required", field)
	}
	if !json.Valid(trimmed) {
		return fmt.Errorf("%s must be valid JSON", field)
	}
	return nil
}

func validateJSONSchema(value json.RawMessage, field string) error {
	_, err := compileJSONSchema(value, field)
	return err
}

func validateJSONInstance(schemaValue json.RawMessage, instance any, field, schemaField string) error {
	schema, err := compileJSONSchema(schemaValue, schemaField)
	if err != nil {
		return err
	}

	instanceBytes, err := json.Marshal(instance)
	if err != nil {
		return fmt.Errorf("%s must be valid JSON: %w", field, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(instanceBytes))
	if err != nil {
		return fmt.Errorf("%s must be valid JSON: %w", field, err)
	}
	if err := schema.Validate(doc); err != nil {
		return fmt.Errorf("%s does not match %s: %w", field, schemaField, err)
	}
	return nil
}

func compileJSONSchema(value json.RawMessage, field string) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(value))
	if err != nil {
		return nil, fmt.Errorf("%s must be valid JSON: %w", field, err)
	}

	resourceID := fmt.Sprintf("%s.json", field)
	if err := compiler.AddResource(resourceID, doc); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON Schema: %w", field, err)
	}
	schema, err := compiler.Compile(resourceID)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid JSON Schema: %w", field, err)
	}
	return schema, nil
}
