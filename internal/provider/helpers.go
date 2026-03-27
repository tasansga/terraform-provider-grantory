package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	apiclient "github.com/tasansga/terraform-provider-grantory/api/client"
)

func isNotFound(err error) bool {
	return apiclient.IsNotFound(err)
}

func expandStringMap(input map[string]any) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		if value == nil {
			continue
		}
		if str, ok := value.(string); ok {
			output[key] = str
		}
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

func flattenStringMap(input map[string]string) map[string]any {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

func expandAnyMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		if value == nil {
			continue
		}
		output[key] = value
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

func parseJSONString(payload string) (map[string]any, error) {
	if strings.TrimSpace(payload) == "" {
		return nil, nil
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(payload), &parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func parseRawJSON(payload string) (json.RawMessage, error) {
	if strings.TrimSpace(payload) == "" {
		return nil, nil
	}
	if !json.Valid([]byte(payload)) {
		return nil, fmt.Errorf("invalid json")
	}
	return json.RawMessage(payload), nil
}

func encodeMapToJSONString(value map[string]any) (string, error) {
	if value == nil {
		return "", nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func setJSONStringAttribute(d *schema.ResourceData, key string, payload map[string]any) diag.Diagnostics {
	if payload == nil {
		if err := d.Set(key, nil); err != nil {
			return diag.FromErr(err)
		}
		return nil
	}
	value, err := encodeMapToJSONString(payload)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(key, value); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func hashAsJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
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
