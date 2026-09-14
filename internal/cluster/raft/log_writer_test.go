package raft

import (
	"bytes"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRaftLogWriter(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := logrus.New()
	logger.SetOutput(buf)
	logger.SetLevel(logrus.DebugLevel)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})

	entry := logger.WithField("component", "raft")
	writer := NewRaftLogWriter(entry, logrus.InfoLevel)
	require.NotNil(t, writer)

	t.Run("writes message at specified level", func(t *testing.T) {
		buf.Reset()
		n, err := writer.Write([]byte("raft started successfully\n"))
		require.NoError(t, err)
		assert.Equal(t, len("raft started successfully\n"), n)

		output := buf.String()
		assert.Contains(t, output, "level=info")
		assert.Contains(t, output, "component=raft")
		assert.Contains(t, output, "msg=\"raft started successfully\"")
	})

	t.Run("skips empty and whitespace-only messages", func(t *testing.T) {
		buf.Reset()
		n, err := writer.Write([]byte("   \n\t  \n"))
		require.NoError(t, err)
		assert.Equal(t, len("   \n\t  \n"), n)
		assert.Empty(t, buf.String())
	})

	t.Run("maps log prefixes to logrus levels and strips prefix", func(t *testing.T) {
		tests := []struct {
			input           string
			expectedLevel   string
			expectedMessage string
		}{
			{"[DEBUG] raft: heartbeat sent", "level=debug", "raft: heartbeat sent"},
			{"[INFO] raft: entering leader state", "level=info", "raft: entering leader state"},
			{"[WARN] raft: election timeout reached", "level=warning", "raft: election timeout reached"},
			{"[ERR] raft: failed to contact peer", "level=error", "raft: failed to contact peer"},
			{"[ERROR] raft: quorum loss detected", "level=error", "raft: quorum loss detected"},
		}

		for _, tc := range tests {
			t.Run(tc.input, func(t *testing.T) {
				buf.Reset()
				n, err := writer.Write([]byte(tc.input + "\n"))
				require.NoError(t, err)
				assert.Equal(t, len(tc.input+"\n"), n)
				assert.Contains(t, buf.String(), tc.expectedLevel)
				assert.Contains(t, buf.String(), "msg=\""+tc.expectedMessage+"\"")
				assert.NotContains(t, buf.String(), "[DEBUG]")
				assert.NotContains(t, buf.String(), "[INFO]")
				assert.NotContains(t, buf.String(), "[WARN]")
				assert.NotContains(t, buf.String(), "[ERR]")
				assert.NotContains(t, buf.String(), "[ERROR]")
			})
		}
	})

	t.Run("maps log prefixes with timestamps to logrus levels and strips prefix", func(t *testing.T) {
		tests := []struct {
			input           string
			expectedLevel   string
			expectedMessage string
		}{
			{"2026/09/09 14:00:00 [DEBUG] raft: heartbeat sent", "level=debug", "raft: heartbeat sent"},
			{"2026/09/09 14:00:00.123 [WARN] election timeout", "level=warning", "election timeout"},
			{"2026/09/09 11:24:01 [INFO] raft: entering leader state", "level=info", "raft: entering leader state"},
			{"2026/09/09 11:24:01 [ERR] raft: failed to contact peer", "level=error", "raft: failed to contact peer"},
			{"2026/09/09 11:24:01 [ERROR] raft: quorum loss detected", "level=error", "raft: quorum loss detected"},
			{"2026-09-09T11:24:01Z [DEBUG] raft: probe peer", "level=debug", "raft: probe peer"},
		}

		for _, tc := range tests {
			t.Run(tc.input, func(t *testing.T) {
				buf.Reset()
				n, err := writer.Write([]byte(tc.input + "\n"))
				require.NoError(t, err)
				assert.Equal(t, len(tc.input+"\n"), n)
				assert.Contains(t, buf.String(), tc.expectedLevel)
				assert.Contains(t, buf.String(), "msg=\""+tc.expectedMessage+"\"")
				assert.NotContains(t, buf.String(), "[DEBUG]")
				assert.NotContains(t, buf.String(), "[INFO]")
				assert.NotContains(t, buf.String(), "[WARN]")
				assert.NotContains(t, buf.String(), "[ERR]")
				assert.NotContains(t, buf.String(), "[ERROR]")
				assert.NotContains(t, buf.String(), "2026/09/09")
				assert.NotContains(t, buf.String(), "2026-09-09T")
			})
		}
	})

	t.Run("unprefixed message uses fallback level", func(t *testing.T) {
		buf.Reset()
		wWarn := NewRaftLogWriter(entry, logrus.WarnLevel)
		n, err := wWarn.Write([]byte("unprefixed warning message\n"))
		require.NoError(t, err)
		assert.Equal(t, len("unprefixed warning message\n"), n)
		assert.Contains(t, buf.String(), "level=warning")
		assert.Contains(t, buf.String(), "unprefixed warning message")
	})
}
