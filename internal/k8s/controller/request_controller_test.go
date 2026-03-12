package controller

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
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

func TestRawExtensionToMap(t *testing.T) {
	raw := runtime.RawExtension{Raw: []byte(`{"k":"v"}`)}
	mapped, err := rawExtensionToMap(raw)
	if err != nil {
		t.Fatalf("rawExtensionToMap: %v", err)
	}
	if mapped["k"] != "v" {
		t.Fatalf("expected k=v, got %v", mapped["k"])
	}

	mapped, err = rawExtensionToMap(runtime.RawExtension{Raw: []byte(``)})
	if err != nil {
		t.Fatalf("rawExtensionToMap empty: %v", err)
	}
	if mapped != nil {
		t.Fatalf("expected empty raw extension to return nil")
	}
}

func TestRawExtensionToMapInvalid(t *testing.T) {
	_, err := rawExtensionToMap(runtime.RawExtension{Raw: []byte(`{`)})
	if err == nil {
		t.Fatalf("expected error for invalid json")
	}

	_, err = rawExtensionToMap(runtime.RawExtension{Raw: []byte(`["x"]`)})
	if err == nil {
		t.Fatalf("expected error for non-object json")
	}
}
