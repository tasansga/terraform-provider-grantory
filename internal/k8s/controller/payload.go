package controller

import "github.com/tasansga/terraform-provider-grantory/internal/jsonutil"

func parsePayloadString(payload string) (map[string]any, error) {
	return jsonutil.ParsePayload(payload)
}

func normalizePayload(payload map[string]any) map[string]any {
	return jsonutil.NormalizePayload(payload)
}
