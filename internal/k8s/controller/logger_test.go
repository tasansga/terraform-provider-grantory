package controller

import (
	"bytes"
	"testing"

	"github.com/go-logr/logr"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ctrl "sigs.k8s.io/controller-runtime"
)

func TestSetupLogger_NilDefaultsToStandardLogger(t *testing.T) {
	var buf bytes.Buffer
	origOut := logrus.StandardLogger().Out
	t.Cleanup(func() {
		logrus.SetOutput(origOut)
		SetupLogger(nil)
	})
	logrus.SetOutput(&buf)

	var l logr.Logger
	require.NotPanics(t, func() {
		l = SetupLogger(nil)
	})
	require.NotNil(t, l)

	l.WithName("test-nil").Info("message from nil setup", "key", "val")
	assert.Contains(t, buf.String(), "message from nil setup")
	assert.Contains(t, buf.String(), "key=val")

	// Also verify package-level ctrl.Log routes through
	ctrl.Log.WithName("test-ctrl-log").Info("ctrl log message", "key2", "val2")
	assert.Contains(t, buf.String(), "ctrl log message")
}

func TestSetupLogger_TypedNilSafety(t *testing.T) {
	var buf bytes.Buffer
	origOut := logrus.StandardLogger().Out
	t.Cleanup(func() {
		logrus.SetOutput(origOut)
		SetupLogger(nil)
	})
	logrus.SetOutput(&buf)

	var nilLogger *logrus.Logger
	require.NotPanics(t, func() {
		l := SetupLogger(nilLogger)
		require.NotNil(t, l)
		l.Info("typed nil logger test")
	})
	assert.Contains(t, buf.String(), "typed nil logger test")

	buf.Reset()
	var nilEntry *logrus.Entry
	require.NotPanics(t, func() {
		l := SetupLogger(nilEntry)
		require.NotNil(t, l)
		l.Info("typed nil entry test")
	})
	assert.Contains(t, buf.String(), "typed nil entry test")
}

func TestSetupLogger_CustomLoggerAndEntry(t *testing.T) {
	t.Cleanup(func() {
		SetupLogger(nil)
	})

	var buf bytes.Buffer
	customLogger := logrus.New()
	customLogger.SetOutput(&buf)
	customLogger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})

	t.Run("with custom logger", func(t *testing.T) {
		buf.Reset()
		var l logr.Logger
		require.NotPanics(t, func() {
			l = SetupLogger(customLogger)
		})
		require.NotNil(t, l)

		l.WithName("test-custom").Info("custom logger message", "foo", "bar")
		assert.Contains(t, buf.String(), "custom logger message")
		assert.Contains(t, buf.String(), "foo=bar")
	})

	t.Run("with pre-configured logrus entry", func(t *testing.T) {
		buf.Reset()
		entry := customLogger.WithField("component", "k8s-controller")
		var l logr.Logger
		require.NotPanics(t, func() {
			l = SetupLogger(entry)
		})
		require.NotNil(t, l)

		l.Info("message from entry")
		assert.Contains(t, buf.String(), "message from entry")
		assert.Contains(t, buf.String(), "component=k8s-controller")
	})
}
