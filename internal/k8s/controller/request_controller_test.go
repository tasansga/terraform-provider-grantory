package controller

import (
	"testing"
)

func TestResolveJSONPointer(t *testing.T) {
	document := map[string]any{
		"foo": map[string]any{
			"bar": []any{"x", "y"},
		},
	}

	value, err := resolveJSONPointer(document, "/foo/bar/1")
	if err != nil {
		t.Fatalf("resolve json pointer: %v", err)
	}
	if value != "y" {
		t.Fatalf("expected y, got %v", value)
	}

	if _, err := resolveJSONPointer(document, "/foo/missing"); err == nil {
		t.Fatalf("expected error for missing pointer")
	}
}

func TestBuildGrantOutputData(t *testing.T) {
	raw := []byte(`{"a":{"b":1},"c":"v"}`)
	data, err := buildGrantOutputData(raw, map[string]string{
		"/c":   "name",
		"/a/b": "num",
	})
	if err != nil {
		t.Fatalf("build grant output data: %v", err)
	}
	if data["name"] != "v" {
		t.Fatalf("expected name=v, got %q", data["name"])
	}
	if data["num"] != "1" {
		t.Fatalf("expected num=1, got %q", data["num"])
	}

	payloadOnly, err := buildGrantOutputData(raw, nil)
	if err != nil {
		t.Fatalf("build payload output: %v", err)
	}
	if payloadOnly["payload.json"] == "" {
		t.Fatalf("expected payload.json to be set")
	}
}

func TestGrantPayloadRaw(t *testing.T) {
	// nil grant
	raw, err := grantPayloadRaw(nil)
	if err != nil || raw != nil {
		t.Fatalf("expected nil, nil for nil grant, got %v, %v", raw, err)
	}

	// grant with payload: nil
	raw, err = grantPayloadRaw(map[string]any{"id": "grant-1", "payload": nil})
	if err != nil || raw != nil {
		t.Fatalf("expected nil, nil when payload is nil, got %s, %v", raw, err)
	}

	// unwrapped grant (payload key absent)
	raw, err = grantPayloadRaw(map[string]any{"token": "unwrapped"})
	if err != nil {
		t.Fatalf("unexpected error for unwrapped grant: %v", err)
	}
	if string(raw) != `{"token":"unwrapped"}` {
		t.Fatalf("expected {\"token\":\"unwrapped\"}, got %s", raw)
	}

	// grant with valid nested payload
	raw, err = grantPayloadRaw(map[string]any{"id": "grant-1", "payload": map[string]any{"token": "xyz"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(raw) != `{"token":"xyz"}` {
		t.Fatalf("expected {\"token\":\"xyz\"}, got %s", raw)
	}
}
