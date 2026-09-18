package raft

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClusterStatusResponseJSON(t *testing.T) {
	resp := ClusterStatusResponse{
		NodeID:     "node-1",
		Role:       "leader",
		IsLeader:   true,
		LeaderAddr: "127.0.0.1:9300",
		Servers: []ServerInfo{
			{
				ID:       "node-1",
				Address:  "127.0.0.1:9300",
				Suffrage: "Voter",
			},
		},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded ClusterStatusResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, resp, decoded)
}

func TestClusterStatusResponseJSON_AutoJoinStatus(t *testing.T) {
	resp := ClusterStatusResponse{
		NodeID:         "node-1",
		Role:           "leader",
		IsLeader:       true,
		LeaderAddr:     "127.0.0.1:9300",
		AutoJoinStatus: "joined",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded ClusterStatusResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, resp, decoded)

	// omitempty when empty
	emptyResp := ClusterStatusResponse{
		NodeID: "node-2",
	}
	emptyData, err := json.Marshal(emptyResp)
	require.NoError(t, err)
	assert.NotContains(t, string(emptyData), "auto_join_status")
}

func TestClusterJoinRequestJSON(t *testing.T) {
	req := ClusterJoinRequest{
		NodeID:      "node-2",
		Address:     "127.0.0.1:9302",
		HTTPAddress: "https://127.0.0.1:8443",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded ClusterJoinRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, req, decoded)
}

func TestClusterRemoveRequestJSON(t *testing.T) {
	req := ClusterRemoveRequest{
		NodeID:  "node-3",
		Address: "127.0.0.1:9303",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded ClusterRemoveRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, req, decoded)
}

func TestFormatBearerToken(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "whitespace only",
			input:    "   \t\n ",
			expected: "",
		},
		{
			name:     "bearer prefix only without token",
			input:    "Bearer ",
			expected: "",
		},
		{
			name:     "bearer word only without token",
			input:    "Bearer",
			expected: "",
		},
		{
			name:     "raw secret token without prefix",
			input:    "my-secret-token",
			expected: "Bearer my-secret-token",
		},
		{
			name:     "already prefixed with Bearer",
			input:    "Bearer my-secret-token",
			expected: "Bearer my-secret-token",
		},
		{
			name:     "prefixed with lowercase bearer",
			input:    "bearer my-secret-token",
			expected: "Bearer my-secret-token",
		},
		{
			name:     "prefixed with uppercase BEARER and whitespace",
			input:    "  BEARER   my-secret-token  ",
			expected: "Bearer my-secret-token",
		},
		{
			name:     "secret containing bearer without space prefix",
			input:    "bearerToken123",
			expected: "Bearer bearerToken123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, FormatBearerToken(tt.input))
		})
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "whitespace only",
			input:    "   \t\n ",
			expected: "",
		},
		{
			name:     "raw secret token without prefix",
			input:    "my-secret-token",
			expected: "my-secret-token",
		},
		{
			name:     "prefixed with standard Bearer",
			input:    "Bearer my-secret-token",
			expected: "my-secret-token",
		},
		{
			name:     "prefixed with lowercase bearer",
			input:    "bearer my-secret-token",
			expected: "my-secret-token",
		},
		{
			name:     "prefixed with uppercase BEARER and whitespace",
			input:    "  BEARER   my-secret-token  ",
			expected: "my-secret-token",
		},
		{
			name:     "secret containing bearer without space prefix",
			input:    "bearerToken123",
			expected: "bearerToken123",
		},
		{
			name:     "bearer word only",
			input:    "Bearer",
			expected: "",
		},
		{
			name:     "bearer with trailing space",
			input:    "Bearer ",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ExtractBearerToken(tt.input))
		})
	}
}

func TestApplyClusterAuth(t *testing.T) {
	t.Parallel()

	// Should not panic on nil request
	ApplyClusterAuth(nil, "my-secret")

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080", nil)
	require.NoError(t, err)

	ApplyClusterAuth(req, "")
	assert.Empty(t, req.Header.Get("Authorization"))

	ApplyClusterAuth(req, "   ")
	assert.Empty(t, req.Header.Get("Authorization"))

	ApplyClusterAuth(req, "Bearer")
	assert.Empty(t, req.Header.Get("Authorization"))

	ApplyClusterAuth(req, "Bearer ")
	assert.Empty(t, req.Header.Get("Authorization"))

	ApplyClusterAuth(req, "my-token")
	assert.Equal(t, "Bearer my-token", req.Header.Get("Authorization"))

	ApplyClusterAuth(req, "Bearer another-token")
	assert.Equal(t, "Bearer another-token", req.Header.Get("Authorization"))
}

func TestApplyClusterAuth_NilHeader(t *testing.T) {
	t.Parallel()

	req := &http.Request{}
	require.Nil(t, req.Header)

	ApplyClusterAuth(req, "secret")
	require.NotNil(t, req.Header)
	assert.Equal(t, "Bearer secret", req.Header.Get("Authorization"))
}
