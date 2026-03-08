package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func expandStringMap(input map[string]any) map[string]string {
	if len(input) == 0 {
		return nil
	}

	result := make(map[string]string, len(input))
	for key, value := range input {
		if value == nil {
			continue
		}

		str, ok := value.(string)
		if !ok {
			continue
		}

		result[key] = str
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func flattenStringMap(input map[string]string) map[string]any {
	if len(input) == 0 {
		return nil
	}

	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func expandAnyMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}

	result := make(map[string]any, len(input))
	for key, value := range input {
		if value == nil {
			continue
		}
		result[key] = value
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func parseJSONString(value string) (map[string]any, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(trimmed), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func parseRawJSON(value string) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	var decoded any
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return nil, err
	}
	normalized, err := json.Marshal(decoded)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(normalized), nil
}

func encodeMapToJSONString(value map[string]any) (string, error) {
	if value == nil {
		return "", nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func setJSONStringAttribute(d *schema.ResourceData, key string, value map[string]any) diag.Diagnostics {
	payload, err := encodeMapToJSONString(value)
	if err != nil {
		return diag.Diagnostics{{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("encode %s", key),
			Detail:   err.Error(),
		}}
	}
	if payload == "" {
		return nil
	}
	if err := d.Set(key, payload); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func hashAsJSON(value any) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func matchesLabelFilters(labels map[string]string, filters map[string]string) bool {
	if len(filters) == 0 {
		return true
	}
	if len(labels) == 0 {
		return false
	}
	for key, expected := range filters {
		if labels[key] != expected {
			return false
		}
	}
	return true
}
