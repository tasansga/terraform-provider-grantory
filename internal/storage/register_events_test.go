package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegisterPayloadUpdateRequiresMutable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)

	reg, err := store.CreateRegister(ctx, Register{
		HostID:  host.ID,
		Payload: map[string]any{"v": "one"},
	})
	require.NoError(t, err)
	require.False(t, reg.Mutable)

	newPayload := map[string]any{"v": "two"}
	err = store.UpdateRegister(ctx, reg.ID, &newPayload, nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrRegisterImmutable))

	loaded, err := store.GetRegister(ctx, reg.ID)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"v": "one"}, loaded.Payload)
}

func TestRegisterEventsTrackCreateUpdateDelete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := New(ctx, ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.Migrate(ctx))

	host, err := store.CreateHost(ctx, Host{})
	require.NoError(t, err)

	reg, err := store.CreateRegister(ctx, Register{
		HostID:    host.ID,
		Mutable:   true,
		Payload:   map[string]any{"v": "one"},
		Labels:    map[string]string{"env": "dev"},
		UniqueKey: "reg:event:test",
	})
	require.NoError(t, err)

	newPayload := map[string]any{"v": "two"}
	require.NoError(t, store.UpdateRegister(ctx, reg.ID, &newPayload, nil))

	newLabels := map[string]string{"env": "prod"}
	require.NoError(t, store.UpdateRegister(ctx, reg.ID, nil, &newLabels))

	events, err := store.ListRegisterEvents(ctx, reg.ID)
	require.NoError(t, err)
	require.Len(t, events, 3)
	var payloadUpdated, labelsUpdated bool
	for _, event := range events {
		switch event.EventType {
		case "payload_updated":
			payloadUpdated = true
			require.Equal(t, map[string]any{"v": "one"}, event.OldPayload)
			require.Equal(t, map[string]any{"v": "two"}, event.NewPayload)
		case "labels_updated":
			labelsUpdated = true
			require.Equal(t, map[string]string{"env": "dev"}, event.OldLabels)
			require.Equal(t, map[string]string{"env": "prod"}, event.NewLabels)
		}
	}
	require.True(t, payloadUpdated, "missing payload_updated event")
	require.True(t, labelsUpdated, "missing labels_updated event")

	require.NoError(t, store.DeleteRegister(ctx, reg.ID))
	events, err = store.ListRegisterEvents(ctx, reg.ID)
	require.ErrorIs(t, err, ErrRegisterNotFound)
	require.Nil(t, events)
}
