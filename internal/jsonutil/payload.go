package jsonutil

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParsePayload parses a JSON string into a map[string]any.
// Empty or whitespace-only input returns (nil, nil).
// Non-object JSON (arrays, primitives, null, invalid syntax) returns an error.
func ParsePayload(payload string) (map[string]any, error) {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal([]byte(trimmed), &out); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	mapped, ok := out.(map[string]any)
	if !ok || mapped == nil {
		return nil, fmt.Errorf("payload must be a JSON object")
	}
	return mapped, nil
}

// ParsePatchPayload parses a JSON string for PATCH operations.
// Empty or whitespace-only input returns an explicit empty map (map[string]any{})
// so that JSON serializers include "payload": {} over the wire to clear remote state.
func ParsePatchPayload(payload string) (map[string]any, error) {
	if strings.TrimSpace(payload) == "" {
		return map[string]any{}, nil
	}
	return ParsePayload(payload)
}

// NormalizePayload returns nil if payload is nil or empty, or the payload unchanged.
func NormalizePayload(payload map[string]any) map[string]any {
	if len(payload) == 0 {
		return nil
	}
	return payload
}

// IsEmptyPayloadString returns true if the string is empty, whitespace, or "{}" / empty object.
func IsEmptyPayloadString(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return true
	}
	parsed, err := ParsePayload(trimmed)
	return err == nil && len(parsed) == 0
}
