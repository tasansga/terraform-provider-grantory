package raft

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

func TestEncodeDecodeCreateRequestCommand(t *testing.T) {
	req := storage.Request{
		ID:        "req-123",
		HostID:    "host-abc",
		UniqueKey: "key-1",
		Payload:   map[string]any{"cluster": "k8s-prod"},
		Labels:    map[string]string{"env": "prod"},
		Version:   1,
		CreatedAt: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC),
	}

	cmd, err := NewCommand("production", CmdCreateRequest, req.CreatedAt, req)
	require.NoError(t, err)

	data, err := cmd.Encode()
	require.NoError(t, err)

	decoded, err := DecodeCommand(data)
	require.NoError(t, err)

	assert.Equal(t, "production", decoded.Namespace)
	assert.Equal(t, CmdCreateRequest, decoded.Type)
	assert.True(t, req.CreatedAt.Equal(decoded.Timestamp))

	var decodedReq storage.Request
	err = json.Unmarshal(decoded.Payload, &decodedReq)
	require.NoError(t, err)
	assert.Equal(t, req.ID, decodedReq.ID)
	assert.Equal(t, req.HostID, decodedReq.HostID)
	assert.Equal(t, req.Payload["cluster"], decodedReq.Payload["cluster"])
}

func TestEncodeDecodeAllCommandTypes(t *testing.T) {
	commandTypes := []CommandType{
		CmdCreateHost,
		CmdDeleteHost,
		CmdUpdateHostLabels,
		CmdRecordSignature,
		CmdCreateRequest,
		CmdUpdateRequest,
		CmdUpdateRequestLabels,
		CmdDeleteRequest,
		CmdCreateRegister,
		CmdUpdateRegister,
		CmdUpdateRegisterLabels,
		CmdDeleteRegister,
		CmdCreateGrant,
		CmdUpdateGrant,
		CmdDeleteGrant,
		CmdCreateSchemaDefinition,
		CmdUpdateSchemaDefinitionLabels,
		CmdDeleteSchemaDefinition,
	}

	now := time.Now()
	for _, ct := range commandTypes {
		t.Run(string(ct), func(t *testing.T) {
			cmd, err := NewCommand("test-ns", ct, now, map[string]string{"dummy": "data"})
			require.NoError(t, err)
			assert.Equal(t, "test-ns", cmd.Namespace)
			assert.Equal(t, ct, cmd.Type)
			assert.Equal(t, now.UTC(), cmd.Timestamp)

			encoded, err := cmd.Encode()
			require.NoError(t, err)

			decoded, err := DecodeCommand(encoded)
			require.NoError(t, err)
			assert.Equal(t, cmd.Namespace, decoded.Namespace)
			assert.Equal(t, cmd.Type, decoded.Type)
			assert.True(t, cmd.Timestamp.Equal(decoded.Timestamp))

			var payload map[string]string
			err = json.Unmarshal(decoded.Payload, &payload)
			require.NoError(t, err)
			assert.Equal(t, "data", payload["dummy"])
		})
	}
}

func TestNewCommandMarshalFailure(t *testing.T) {
	unserializablePayload := make(chan int)
	_, err := NewCommand("ns", CmdCreateHost, time.Now(), unserializablePayload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal raft command payload")
}

func TestDecodeCommandFailure(t *testing.T) {
	invalidData := []byte("invalid-json")
	_, err := DecodeCommand(invalidData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode raft command")
}

func TestPayloadStructures(t *testing.T) {
	t.Run("DeletePayload", func(t *testing.T) {
		p := DeletePayload{ID: "del-1"}
		cmd, err := NewCommand("ns", CmdDeleteHost, time.Now(), p)
		require.NoError(t, err)

		var decoded DeletePayload
		err = json.Unmarshal(cmd.Payload, &decoded)
		require.NoError(t, err)
		assert.Equal(t, p.ID, decoded.ID)
	})

	t.Run("UpdateLabelsPayload", func(t *testing.T) {
		p := UpdateLabelsPayload{ID: "host-1", Labels: map[string]string{"k": "v"}}
		cmd, err := NewCommand("ns", CmdUpdateHostLabels, time.Now(), p)
		require.NoError(t, err)

		var decoded UpdateLabelsPayload
		err = json.Unmarshal(cmd.Payload, &decoded)
		require.NoError(t, err)
		assert.Equal(t, p.ID, decoded.ID)
		assert.Equal(t, p.Labels, decoded.Labels)
	})

	t.Run("UpdateRequestPayload", func(t *testing.T) {
		payload := map[string]any{"key": "val"}
		labels := map[string]string{"env": "stage"}
		p := UpdateRequestPayload{ID: "req-1", Payload: &payload, Labels: &labels}
		cmd, err := NewCommand("ns", CmdUpdateRequest, time.Now(), p)
		require.NoError(t, err)

		var decoded UpdateRequestPayload
		err = json.Unmarshal(cmd.Payload, &decoded)
		require.NoError(t, err)
		assert.Equal(t, p.ID, decoded.ID)
		assert.Equal(t, (*p.Payload)["key"], (*decoded.Payload)["key"])
		assert.Equal(t, *p.Labels, *decoded.Labels)
	})

	t.Run("UpdateRegisterPayload", func(t *testing.T) {
		payload := map[string]any{"data": "entry"}
		labels := map[string]string{"type": "svc"}
		p := UpdateRegisterPayload{ID: "reg-1", Payload: &payload, Labels: &labels}
		cmd, err := NewCommand("ns", CmdUpdateRegister, time.Now(), p)
		require.NoError(t, err)

		var decoded UpdateRegisterPayload
		err = json.Unmarshal(cmd.Payload, &decoded)
		require.NoError(t, err)
		assert.Equal(t, p.ID, decoded.ID)
		assert.Equal(t, (*p.Payload)["data"], (*decoded.Payload)["data"])
		assert.Equal(t, *p.Labels, *decoded.Labels)
	})

	t.Run("UpdateGrantPayload", func(t *testing.T) {
		payload := map[string]any{"token": "xyz"}
		p := UpdateGrantPayload{ID: "grant-1", Payload: payload, RequestVersion: 2}
		cmd, err := NewCommand("ns", CmdUpdateGrant, time.Now(), p)
		require.NoError(t, err)

		var decoded UpdateGrantPayload
		err = json.Unmarshal(cmd.Payload, &decoded)
		require.NoError(t, err)
		assert.Equal(t, p.ID, decoded.ID)
		assert.Equal(t, p.Payload["token"], decoded.Payload["token"])
		assert.Equal(t, p.RequestVersion, decoded.RequestVersion)
	})

	t.Run("UpdateGrantPayload_EmptyMap", func(t *testing.T) {
		p := UpdateGrantPayload{
			ID:             "grant-empty",
			Payload:        map[string]any{},
			RequestVersion: 1,
		}
		data, err := json.Marshal(p)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"payload":{}`)

		var decoded UpdateGrantPayload
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, "grant-empty", decoded.ID)
		assert.NotNil(t, decoded.Payload)
		assert.Empty(t, decoded.Payload)
		assert.Equal(t, 1, decoded.RequestVersion)
	})

	t.Run("RecordSignaturePayload", func(t *testing.T) {
		exp := time.Date(2026, 9, 6, 13, 0, 0, 0, time.UTC)
		p := RecordSignaturePayload{HostID: "h-1", Timestamp: 12345678, Nonce: "nonce-1", ExpiresAt: exp}
		cmd, err := NewCommand("ns", CmdRecordSignature, time.Now(), p)
		require.NoError(t, err)

		var decoded RecordSignaturePayload
		err = json.Unmarshal(cmd.Payload, &decoded)
		require.NoError(t, err)
		assert.Equal(t, p.HostID, decoded.HostID)
		assert.Equal(t, p.Timestamp, decoded.Timestamp)
		assert.Equal(t, p.Nonce, decoded.Nonce)
		assert.True(t, p.ExpiresAt.Equal(decoded.ExpiresAt))
	})
}
