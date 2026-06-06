package provider

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	apiclient "github.com/tasansga/terraform-provider-grantory/api/client"
)

func contextWithPrivateKey(ctx context.Context, d *schema.ResourceData) (context.Context, error) {
	var keyHex string

	if v, ok := d.GetOk("ed25519_private_key"); ok {
		keyHex = v.(string)
	}
	if v, ok := d.GetOk("ed25519_private_key_file"); ok {
		path := strings.TrimSpace(v.(string))
		if path != "" {
			content, err := os.ReadFile(path)
			if err != nil {
				return ctx, fmt.Errorf("failed to read ed25519_private_key_file: %w", err)
			}
			keyHex = string(content)
		}
	}
	if v, ok := d.GetOk("ed25519_private_key_env"); ok {
		envVar := strings.TrimSpace(v.(string))
		if envVar != "" {
			if envVal := os.Getenv(envVar); envVal != "" {
				keyHex = envVal
			}
		}
	}

	keyHex = strings.TrimSpace(keyHex)
	if keyHex == "" {
		return ctx, nil
	}

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return ctx, fmt.Errorf("failed to decode hex ed25519_private_key: %w", err)
	}
	if len(keyBytes) != ed25519.PrivateKeySize {
		return ctx, fmt.Errorf("invalid ed25519_private_key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(keyBytes))
	}
	return apiclient.WithPrivateKey(ctx, ed25519.PrivateKey(keyBytes)), nil
}

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
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return nil, nil
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil, err
	}
	if parsed == nil {
		return nil, fmt.Errorf("json object is required; null is not allowed")
	}
	return parsed, nil
}

func parseJSONPatchPayload(payload string) (map[string]any, error) {
	if strings.TrimSpace(payload) == "" {
		// PATCH endpoints require payload presence; empty object is explicit clear.
		return map[string]any{}, nil
	}
	return parseJSONString(payload)
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

func payloadChangeRequiresReplacement(d *schema.ResourceDiff) bool {
	if d == nil || !d.HasChange("payload") {
		return false
	}
	oldValue, newValue := d.GetChange("payload")
	if payloadStringsEquivalent(oldValue, newValue) {
		return false
	}
	mutable, ok := d.Get("mutable").(bool)
	if !ok {
		// Be conservative when mutable cannot be resolved.
		return true
	}
	return !mutable
}

func payloadDiffSuppress(_ string, old, new string, _ *schema.ResourceData) bool {
	return payloadStringsEquivalent(old, new)
}

func payloadStringsEquivalent(oldValue, newValue any) bool {
	oldStr, oldOK := oldValue.(string)
	newStr, newOK := newValue.(string)
	if !oldOK || !newOK {
		return false
	}
	if oldStr == newStr {
		return true
	}
	return isEmptyPayloadString(oldStr) && isEmptyPayloadString(newStr)
}

func isEmptyPayloadString(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return true
	}
	parsed, err := parseJSONString(trimmed)
	return err == nil && len(parsed) == 0
}
