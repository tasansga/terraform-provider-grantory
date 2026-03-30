package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestServiceUpdateRegisterRequiresPayloadOrLabels(t *testing.T) {
	t.Parallel()

	svc := New(&fakeStore{})
	_, err := svc.UpdateRegister(context.Background(), "reg-1", RegisterUpdatePayload{})
	if err == nil || err.Error() != "payload and/or labels are required" {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestServiceUpdateRegisterValidatesPayloadAgainstSchema(t *testing.T) {
	t.Parallel()

	schema := json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)
	store := &fakeStore{
		getRegisterFn: func(context.Context, string) (Register, error) {
			return Register{ID: "reg-1", Mutable: true, SchemaDefinitionID: "def-1"}, nil
		},
		getSchemaDefinitionFn: func(context.Context, string) (SchemaDefinition, error) {
			return SchemaDefinition{ID: "def-1", Schema: schema}, nil
		},
	}
	svc := New(store)

	payload := map[string]any{"name": 1}
	_, err := svc.UpdateRegister(context.Background(), "reg-1", RegisterUpdatePayload{Payload: &payload})
	if err == nil || !strings.Contains(err.Error(), "does not match schema") {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestServiceUpdateRegisterPassesThroughStore(t *testing.T) {
	t.Parallel()

	payload := map[string]any{"name": "ok"}
	labels := map[string]string{"env": "prod"}
	store := &fakeStore{
		getRegisterFn: func(context.Context, string) (Register, error) {
			return Register{ID: "reg-1", Mutable: true}, nil
		},
		updateRegisterFn: func(_ context.Context, id string, p RegisterUpdatePayload) (Register, error) {
			if id != "reg-1" {
				t.Fatalf("unexpected id: %s", id)
			}
			if p.Payload == nil || (*p.Payload)["name"] != "ok" {
				t.Fatalf("unexpected payload: %#v", p.Payload)
			}
			if p.Labels == nil || (*p.Labels)["env"] != "prod" {
				t.Fatalf("unexpected labels: %#v", p.Labels)
			}
			return Register{ID: "reg-1"}, nil
		},
	}
	svc := New(store)

	updated, err := svc.UpdateRegister(context.Background(), "reg-1", RegisterUpdatePayload{Payload: &payload, Labels: &labels})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.ID != "reg-1" {
		t.Fatalf("unexpected updated register: %#v", updated)
	}
}

func TestServiceListRegisterEventsPassThrough(t *testing.T) {
	t.Parallel()

	store := &fakeStore{
		listRegisterEventsFn: func(_ context.Context, registerID string) ([]RegisterEvent, error) {
			if registerID != "reg-1" {
				t.Fatalf("unexpected register id: %s", registerID)
			}
			return []RegisterEvent{{ID: "evt-1", RegisterID: registerID, EventType: "created"}}, nil
		},
	}
	svc := New(store)

	events, err := svc.ListRegisterEvents(context.Background(), "reg-1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(events) != 1 || events[0].ID != "evt-1" {
		t.Fatalf("unexpected events: %#v", events)
	}
}

func TestServiceUpdateRegisterLabelsUsesUpdateRegister(t *testing.T) {
	t.Parallel()

	store := &fakeStore{
		updateRegisterFn: func(_ context.Context, _ string, p RegisterUpdatePayload) (Register, error) {
			if p.Labels == nil || (*p.Labels)["k"] != "v" {
				t.Fatalf("expected labels in update payload, got %#v", p.Labels)
			}
			return Register{ID: "reg-1"}, nil
		},
	}
	svc := New(store)

	_, err := svc.UpdateRegisterLabels(context.Background(), "reg-1", map[string]string{"k": "v"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestServiceUpdateRegisterPropagatesGetRegisterError(t *testing.T) {
	t.Parallel()

	store := &fakeStore{
		getRegisterFn: func(context.Context, string) (Register, error) {
			return Register{}, ErrRegisterNotFound
		},
	}
	svc := New(store)

	payload := map[string]any{"name": "x"}
	_, err := svc.UpdateRegister(context.Background(), "reg-1", RegisterUpdatePayload{Payload: &payload})
	if !errors.Is(err, ErrRegisterNotFound) {
		t.Fatalf("expected ErrRegisterNotFound, got %v", err)
	}
}

func TestServiceUpdateRegisterReturnsImmutableBeforeSchemaValidation(t *testing.T) {
	t.Parallel()

	schema := json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)
	schemaLookups := 0
	store := &fakeStore{
		getRegisterFn: func(context.Context, string) (Register, error) {
			return Register{ID: "reg-1", Mutable: false, SchemaDefinitionID: "def-1"}, nil
		},
		getSchemaDefinitionFn: func(context.Context, string) (SchemaDefinition, error) {
			schemaLookups++
			return SchemaDefinition{ID: "def-1", Schema: schema}, nil
		},
	}
	svc := New(store)

	payload := map[string]any{"name": 123}
	_, err := svc.UpdateRegister(context.Background(), "reg-1", RegisterUpdatePayload{Payload: &payload})
	if !errors.Is(err, ErrRegisterImmutable) {
		t.Fatalf("expected ErrRegisterImmutable, got %v", err)
	}
	if schemaLookups != 0 {
		t.Fatalf("expected no schema lookup on immutable register, got %d", schemaLookups)
	}
}
