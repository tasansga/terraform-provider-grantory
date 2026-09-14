package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

func TestNewSQLiteStoreAndServiceHappyPath(t *testing.T) {
	t.Parallel()

	store, err := NewSQLiteStore(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("new sqlite store: %v", err)
	}

	svc := New(store)
	host, err := svc.CreateHost(context.Background(), HostCreatePayload{
		UniqueKey: "host-1",
		Labels:    map[string]string{"env": "dev"},
	})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	if host.ID == "" {
		t.Fatalf("expected host id")
	}

	req, err := svc.CreateRequest(context.Background(), RequestCreatePayload{
		HostID:    host.ID,
		UniqueKey: "request-1",
		Payload:   map[string]any{"service": "api"},
		Labels:    map[string]string{"env": "dev"},
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if req.ID == "" {
		t.Fatalf("expected request id")
	}

	grant, err := svc.CreateGrant(context.Background(), GrantCreatePayload{
		RequestID:      req.ID,
		RequestVersion: req.Version,
		Payload:        map[string]any{"token": "abc"},
	})
	if err != nil {
		t.Fatalf("create grant: %v", err)
	}
	if grant.ID == "" {
		t.Fatalf("expected grant id")
	}

	loadedReq, err := svc.GetRequest(context.Background(), req.ID)
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	if !loadedReq.HasGrant {
		t.Fatalf("expected request has grant")
	}
	if loadedReq.GrantID == "" || loadedReq.Grant == nil {
		t.Fatalf("expected enriched grant on request")
	}
}

func TestStorageStoreErrorMapping(t *testing.T) {
	t.Parallel()

	store, err := NewSQLiteStore(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("new sqlite store: %v", err)
	}
	svc := New(store)

	_, err = svc.GetHost(context.Background(), "missing")
	if !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("expected ErrHostNotFound, got %v", err)
	}

	_, err = svc.CreateRequest(context.Background(), RequestCreatePayload{
		HostID:    "missing-host",
		UniqueKey: "request-1",
	})
	if !errors.Is(err, ErrReferencedHostNotFound) {
		t.Fatalf("expected ErrReferencedHostNotFound, got %v", err)
	}
}

func TestNewStoreFromDatabaseSelectsByDSNShape(t *testing.T) {
	t.Parallel()

	sqliteStore, err := NewStoreFromDatabase(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("new store from sqlite path: %v", err)
	}
	if _, ok := sqliteStore.(storageStore); !ok {
		t.Fatalf("expected storageStore concrete type")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = NewStoreFromDatabase(ctx, "postgres://127.0.0.1:1/test?sslmode=disable")
	if err == nil {
		t.Fatalf("expected postgres initialization error")
	}
}

func TestMapStorageError(t *testing.T) {
	t.Parallel()

	unrelatedErr := errors.New("something went wrong")

	tests := []struct {
		name     string
		input    error
		expected error
	}{
		{name: "nil error", input: nil, expected: nil},
		{name: "ErrHostNotFound", input: storage.ErrHostNotFound, expected: ErrHostNotFound},
		{name: "ErrHostAlreadyExists", input: storage.ErrHostAlreadyExists, expected: ErrHostAlreadyExists},
		{name: "ErrHostUniqueKeyConflict", input: storage.ErrHostUniqueKeyConflict, expected: ErrHostUniqueKeyConflict},
		{name: "ErrRequestNotFound", input: storage.ErrRequestNotFound, expected: ErrRequestNotFound},
		{name: "ErrRequestAlreadyExists", input: storage.ErrRequestAlreadyExists, expected: ErrRequestAlreadyExists},
		{name: "ErrRequestUniqueKeyConflict", input: storage.ErrRequestUniqueKeyConflict, expected: ErrRequestUniqueKeyConflict},
		{name: "ErrRequestImmutable", input: storage.ErrRequestImmutable, expected: ErrRequestImmutable},
		{name: "ErrGrantNotFound", input: storage.ErrGrantNotFound, expected: ErrGrantNotFound},
		{name: "ErrGrantAlreadyExists", input: storage.ErrGrantAlreadyExists, expected: ErrGrantAlreadyExists},
		{name: "ErrGrantRequestVersionConflict", input: storage.ErrGrantRequestVersionConflict, expected: ErrGrantRequestVersionConflict},
		{name: "ErrRegisterNotFound", input: storage.ErrRegisterNotFound, expected: ErrRegisterNotFound},
		{name: "ErrRegisterAlreadyExists", input: storage.ErrRegisterAlreadyExists, expected: ErrRegisterAlreadyExists},
		{name: "ErrRegisterUniqueKeyConflict", input: storage.ErrRegisterUniqueKeyConflict, expected: ErrRegisterUniqueKeyConflict},
		{name: "ErrRegisterImmutable", input: storage.ErrRegisterImmutable, expected: ErrRegisterImmutable},
		{name: "ErrSchemaDefinitionNotFound", input: storage.ErrSchemaDefinitionNotFound, expected: ErrSchemaDefinitionNotFound},
		{name: "ErrSchemaDefinitionAlreadyExists", input: storage.ErrSchemaDefinitionAlreadyExists, expected: ErrSchemaDefinitionAlreadyExists},
		{name: "ErrSchemaDefinitionUniqueKeyConflict", input: storage.ErrSchemaDefinitionUniqueKeyConflict, expected: ErrSchemaDefinitionUniqueKeyConflict},
		{name: "ErrReferencedHostNotFound", input: storage.ErrReferencedHostNotFound, expected: ErrReferencedHostNotFound},
		{name: "ErrReferencedRequestNotFound", input: storage.ErrReferencedRequestNotFound, expected: ErrReferencedRequestNotFound},
		{name: "ErrReplayDetected", input: storage.ErrReplayDetected, expected: ErrReplayDetected},
		{name: "ErrTimestampRegressed", input: storage.ErrTimestampRegressed, expected: ErrTimestampRegressed},
		{name: "ErrNotLeader", input: storage.ErrNotLeader, expected: ErrNotLeader},
		{name: "ErrLeadershipLost", input: storage.ErrLeadershipLost, expected: ErrLeadershipLost},
		{name: "wrapped ErrHostNotFound", input: fmt.Errorf("storage failed: %w", storage.ErrHostNotFound), expected: ErrHostNotFound},
		{name: "wrapped ErrReplayDetected", input: fmt.Errorf("storage failed: %w", storage.ErrReplayDetected), expected: ErrReplayDetected},
		{name: "wrapped ErrNotLeader", input: fmt.Errorf("storage failed: %w", storage.ErrNotLeader), expected: ErrNotLeader},
		{name: "wrapped ErrLeadershipLost", input: fmt.Errorf("storage failed: %w", storage.ErrLeadershipLost), expected: ErrLeadershipLost},
		{name: "unrelated error passthrough", input: unrelatedErr, expected: unrelatedErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapStorageError(tt.input)
			if !errors.Is(got, tt.expected) {
				t.Fatalf("MapStorageError(%v) = %v, expected %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNewStorageStore_Unwrap(t *testing.T) {
	t.Parallel()

	rawStore, err := storage.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("storage.New failed: %v", err)
	}
	defer rawStore.Close()

	wrappedStore := NewStorageStore(rawStore)
	unwrapper, ok := wrappedStore.(interface{ Unwrap() storage.Store })
	if !ok {
		t.Fatalf("expected NewStorageStore result to implement Unwrap() storage.Store")
	}
	if unwrapped := unwrapper.Unwrap(); unwrapped != rawStore {
		t.Fatalf("expected Unwrap() to return original store %v, got %v", rawStore, unwrapped)
	}
}

func TestErrGrantAlreadyCurrent_BackwardsCompatibility(t *testing.T) {
	t.Parallel()

	if ErrGrantAlreadyCurrent == nil {
		t.Fatalf("expected ErrGrantAlreadyCurrent to be non-nil")
	}
	expectedMsg := "grant already current"
	if ErrGrantAlreadyCurrent.Error() != expectedMsg {
		t.Fatalf("expected ErrGrantAlreadyCurrent message %q, got %q", expectedMsg, ErrGrantAlreadyCurrent.Error())
	}
}
