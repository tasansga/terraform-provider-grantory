package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

func TestExpandStringMapSkipsInvalidValues(t *testing.T) {
	t.Parallel()

	result := expandStringMap(map[string]any{
		"valid":   "value",
		"nil":     nil,
		"numeric": 1,
	})
	assert.Equal(t, map[string]string{"valid": "value"}, result)
	assert.Nil(t, expandStringMap(map[string]any{}))
}

func TestFlattenStringMapReturnsValue(t *testing.T) {
	t.Parallel()

	input := map[string]string{"env": "prod"}
	flattened := flattenStringMap(input)
	assert.Equal(t, map[string]any{"env": "prod"}, flattened)
	assert.Nil(t, flattenStringMap(nil))
}

func TestExpandAnyMapFiltersNilValues(t *testing.T) {
	t.Parallel()

	entries := map[string]any{"keep": "value", "skip": nil}
	result := expandAnyMap(entries)
	assert.Equal(t, map[string]any{"keep": "value"}, result)
	assert.Nil(t, expandAnyMap(map[string]any{}))
}

func TestParseAndEncodeJSONString(t *testing.T) {
	t.Parallel()

	empty, err := parseJSONString("  ")
	assert.NoError(t, err)
	assert.Nil(t, empty)

	decoded, err := parseJSONString("{\"key\": \"value\"}")
	assert.NoError(t, err)
	assert.Equal(t, map[string]any{"key": "value"}, decoded)

	_, err = parseJSONString("null")
	assert.Error(t, err)

	encoded, err := encodeMapToJSONString(decoded)
	assert.NoError(t, err)
	assert.JSONEq(t, "{\"key\":\"value\"}", encoded)
	emptyPayload, err := encodeMapToJSONString(nil)
	assert.NoError(t, err)
	assert.Empty(t, emptyPayload)
}

func TestSetJSONStringAttributeClearsValue(t *testing.T) {
	t.Parallel()

	resource := &schema.Resource{Schema: map[string]*schema.Schema{
		"payload": {Type: schema.TypeString},
	}}
	data := schema.TestResourceDataRaw(t, resource.Schema, nil)

	diags := setJSONStringAttribute(data, "payload", nil)
	assert.Empty(t, diags)
	assert.Equal(t, "", data.Get("payload"))

	payload := map[string]any{"name": "test"}
	diags = setJSONStringAttribute(data, "payload", payload)
	assert.Empty(t, diags)
	assert.Equal(t, "{\"name\":\"test\"}", data.Get("payload"))

	diags = setJSONStringAttribute(data, "payload", map[string]any{})
	assert.Empty(t, diags)
	assert.Equal(t, "{}", data.Get("payload"))
}

func TestHashAsJSONIsDeterministic(t *testing.T) {
	t.Parallel()

	first, err := hashAsJSON(map[string]any{"k": "v"})
	assert.NoError(t, err)
	second, err := hashAsJSON(map[string]any{"k": "v"})
	assert.NoError(t, err)
	assert.Equal(t, first, second)
}

func TestExtractMap(t *testing.T) {
	t.Parallel()

	assert.Nil(t, extractMap(nil))
	assert.Nil(t, extractMap(123))
	value := map[string]any{"key": "value"}
	assert.Equal(t, value, extractMap(value))
}

func TestPayloadDiffSuppress(t *testing.T) {
	t.Parallel()

	assert.True(t, payloadDiffSuppress("payload", "", "{}", nil))
	assert.True(t, payloadDiffSuppress("payload", "{ }", "", nil))
	assert.True(t, payloadDiffSuppress("payload", "{}", "{ }", nil))
	assert.False(t, payloadDiffSuppress("payload", "", "null", nil))
	assert.False(t, payloadDiffSuppress("payload", "{}", "null", nil))
	assert.False(t, payloadDiffSuppress("payload", "", "{\"x\":1}", nil))
	assert.False(t, payloadDiffSuppress("payload", "{\"x\":1}", "{\"y\":1}", nil))
}
