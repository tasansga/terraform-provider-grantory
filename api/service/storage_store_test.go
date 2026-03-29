package service

import (
	"context"
	"errors"
	"testing"
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
		RequestID: req.ID,
		Payload:   map[string]any{"token": "abc"},
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
