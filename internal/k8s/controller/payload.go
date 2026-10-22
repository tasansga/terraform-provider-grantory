package controller

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
)

func rawExtensionToMap(raw runtime.RawExtension) (map[string]any, error) {
	if len(raw.Raw) == 0 {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal(raw.Raw, &out); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	mapped, ok := out.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("payload must be a JSON object")
	}
	return mapped, nil
}

func normalizePayload(payload map[string]any) map[string]any {
	if len(payload) == 0 {
		return nil
	}
	return payload
}
