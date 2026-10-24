package jsonutil

import (
	"reflect"
	"testing"
)

func TestParsePayload(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      map[string]any
		expectErr bool
	}{
		{
			name:      "empty string",
			input:     "",
			want:      nil,
			expectErr: false,
		},
		{
			name:      "whitespace only",
			input:     "   \t\n  ",
			want:      nil,
			expectErr: false,
		},
		{
			name:      "valid object",
			input:     `{"key": "value", "num": 42}`,
			want:      map[string]any{"key": "value", "num": float64(42)},
			expectErr: false,
		},
		{
			name:      "empty object",
			input:     `{}`,
			want:      map[string]any{},
			expectErr: false,
		},
		{
			name:      "invalid json syntax",
			input:     `{invalid}`,
			want:      nil,
			expectErr: true,
		},
		{
			name:      "json array rejected",
			input:     `["item1", "item2"]`,
			want:      nil,
			expectErr: true,
		},
		{
			name:      "json primitive string rejected",
			input:     `"hello"`,
			want:      nil,
			expectErr: true,
		},
		{
			name:      "json primitive number rejected",
			input:     `123`,
			want:      nil,
			expectErr: true,
		},
		{
			name:      "json null rejected",
			input:     `null`,
			want:      nil,
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePayload(tc.input)
			if (err != nil) != tc.expectErr {
				t.Fatalf("ParsePayload(%q) err = %v, expectErr = %v", tc.input, err, tc.expectErr)
			}
			if !tc.expectErr && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParsePayload(%q) = %+v, want %+v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParsePatchPayload(t *testing.T) {
	// Empty string must return non-nil empty map for PATCH clear
	got, err := ParsePatchPayload("")
	if err != nil {
		t.Fatalf("unexpected error for empty string: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("expected non-nil empty map, got: %+v", got)
	}

	got, err = ParsePatchPayload("   \n ")
	if err != nil {
		t.Fatalf("unexpected error for whitespace: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("expected non-nil empty map, got: %+v", got)
	}

	got, err = ParsePatchPayload(`{"k": "v"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["k"] != "v" {
		t.Fatalf("expected k=v, got: %+v", got)
	}
}

func TestNormalizePayload(t *testing.T) {
	if got := NormalizePayload(nil); got != nil {
		t.Fatalf("expected nil for nil input, got: %+v", got)
	}
	if got := NormalizePayload(map[string]any{}); got != nil {
		t.Fatalf("expected nil for empty map, got: %+v", got)
	}
	m := map[string]any{"a": 1}
	if got := NormalizePayload(m); !reflect.DeepEqual(got, m) {
		t.Fatalf("expected %+v, got: %+v", m, got)
	}
}

func TestIsEmptyPayloadString(t *testing.T) {
	if !IsEmptyPayloadString("") {
		t.Errorf("expected empty string to be empty")
	}
	if !IsEmptyPayloadString("  \n ") {
		t.Errorf("expected whitespace to be empty")
	}
	if !IsEmptyPayloadString("{}") {
		t.Errorf("expected '{}' to be empty")
	}
	if IsEmptyPayloadString(`{"a": 1}`) {
		t.Errorf("expected non-empty json object to not be empty")
	}
	if IsEmptyPayloadString("invalid json") {
		t.Errorf("expected invalid json to not be empty")
	}
}
