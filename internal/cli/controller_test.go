package cli

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tasansga/terraform-provider-grantory/internal/config"
)

func TestResolveLogLevel(t *testing.T) {
	t.Run("default level when unset", func(t *testing.T) {
		cmd := NewRootCommand()
		subCmd, _, err := cmd.Find([]string{"controller"})
		require.NoError(t, err)

		level, err := resolveLogLevel(subCmd)
		require.NoError(t, err)
		assert.Equal(t, config.DefaultLogLevel, level)
	})

	t.Run("level from flag before subcommand", func(t *testing.T) {
		cmd := NewRootCommand()
		require.NoError(t, cmd.ParseFlags([]string{"--log-level=debug"}))
		subCmd, _, err := cmd.Find([]string{"controller"})
		require.NoError(t, err)

		level, err := resolveLogLevel(subCmd)
		require.NoError(t, err)
		assert.Equal(t, logrus.DebugLevel, level)
	})

	t.Run("level from flag after subcommand", func(t *testing.T) {
		cmd := NewRootCommand()
		cmd.SetArgs([]string{"controller", "--log-level=trace"})
		// Find controller subcommand and parse flags as cobra would
		subCmd, args, err := cmd.Find([]string{"controller", "--log-level=trace"})
		require.NoError(t, err)
		require.NoError(t, subCmd.ParseFlags(args))

		level, err := resolveLogLevel(subCmd)
		require.NoError(t, err)
		assert.Equal(t, logrus.TraceLevel, level)
	})

	t.Run("level from LOG_LEVEL env var", func(t *testing.T) {
		t.Setenv(config.EnvLogLevel, "warn")
		cmd := NewRootCommand()
		subCmd, _, err := cmd.Find([]string{"controller"})
		require.NoError(t, err)

		level, err := resolveLogLevel(subCmd)
		require.NoError(t, err)
		assert.Equal(t, logrus.WarnLevel, level)
	})

	t.Run("GRANTORY_CONTROLLER_LOG_LEVEL overrides LOG_LEVEL", func(t *testing.T) {
		t.Setenv(config.EnvLogLevel, "warn")
		t.Setenv(EnvGrantoryControllerLogLevel, "debug")
		cmd := NewRootCommand()
		subCmd, _, err := cmd.Find([]string{"controller"})
		require.NoError(t, err)

		level, err := resolveLogLevel(subCmd)
		require.NoError(t, err)
		assert.Equal(t, logrus.DebugLevel, level)
	})

	t.Run("flag overrides both env vars", func(t *testing.T) {
		t.Setenv(config.EnvLogLevel, "warn")
		t.Setenv(EnvGrantoryControllerLogLevel, "error")
		cmd := NewRootCommand()
		require.NoError(t, cmd.ParseFlags([]string{"--log-level=info"}))
		subCmd, _, err := cmd.Find([]string{"controller"})
		require.NoError(t, err)

		level, err := resolveLogLevel(subCmd)
		require.NoError(t, err)
		assert.Equal(t, logrus.InfoLevel, level)
	})

	t.Run("invalid log level returns error", func(t *testing.T) {
		t.Setenv(config.EnvLogLevel, "not-a-level")
		cmd := NewRootCommand()
		subCmd, _, err := cmd.Find([]string{"controller"})
		require.NoError(t, err)

		_, err = resolveLogLevel(subCmd)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid log level")
	})

	t.Run("isolated from invalid server config env vars", func(t *testing.T) {
		t.Setenv("UNIX_SOCKET_MODE", "invalid-mode")
		cmd := NewRootCommand()
		subCmd, _, err := cmd.Find([]string{"controller"})
		require.NoError(t, err)

		level, err := resolveLogLevel(subCmd)
		require.NoError(t, err)
		assert.Equal(t, config.DefaultLogLevel, level)
	})
}

func TestResolveBoolFlagOrEnv(t *testing.T) {
	t.Run("env var with 1 and true", func(t *testing.T) {
		cmd := NewRootCommand()
		subCmd, _, err := cmd.Find([]string{"controller"})
		require.NoError(t, err)

		t.Setenv(EnvGrantoryControllerAutoCreateHost, "1")
		assert.True(t, resolveBoolFlagOrEnv(subCmd, FlagAutoCreateHost, EnvGrantoryControllerAutoCreateHost))

		t.Setenv(EnvGrantoryControllerAutoCreateHost, "true")
		assert.True(t, resolveBoolFlagOrEnv(subCmd, FlagAutoCreateHost, EnvGrantoryControllerAutoCreateHost))

		t.Setenv(EnvGrantoryControllerAutoCreateHost, "0")
		assert.False(t, resolveBoolFlagOrEnv(subCmd, FlagAutoCreateHost, EnvGrantoryControllerAutoCreateHost))

		t.Setenv(EnvGrantoryControllerAutoCreateHost, "false")
		assert.False(t, resolveBoolFlagOrEnv(subCmd, FlagAutoCreateHost, EnvGrantoryControllerAutoCreateHost))
	})

	t.Run("flag overrides env var", func(t *testing.T) {
		t.Setenv(EnvGrantoryControllerAutoCreateHost, "false")
		cmd := NewRootCommand()
		subCmd, args, err := cmd.Find([]string{"controller", "--auto-create-host=true"})
		require.NoError(t, err)
		require.NoError(t, subCmd.ParseFlags(args))

		assert.True(t, resolveBoolFlagOrEnv(subCmd, FlagAutoCreateHost, EnvGrantoryControllerAutoCreateHost))
	})
}
