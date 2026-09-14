package raft

import (
	"context"
	"errors"
	"testing"
	"time"

	hashiraft "github.com/hashicorp/raft"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
	"github.com/tasansga/terraform-provider-grantory/internal/store"
)

func TestBarrier_UninitializedRaft(t *testing.T) {
	t.Parallel()

	var nilNode *RaftNode
	err := nilNode.Barrier(context.Background())
	require.Error(t, err)
	assert.Equal(t, "raft not initialized", err.Error())

	uninitNode := &RaftNode{}
	err = uninitNode.Barrier(context.Background())
	require.Error(t, err)
	assert.Equal(t, "raft not initialized", err.Error())
}

func TestBarrier_NonLeaderReturnsErrNotLeaderImmediately(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"node-1=127.0.0.1:0"},
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	// Follower node must not be leader
	require.False(t, node.IsLeader())

	// Calling Barrier on non-leader must return storage.ErrNotLeader immediately
	start := time.Now()
	err = node.Barrier(ctx)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, storage.ErrNotLeader)
	assert.Less(t, elapsed, 1*time.Second)

	node.barrierMu.Lock()
	assert.Nil(t, node.activeBarrier)
	assert.Nil(t, node.pendingBarrier)
	node.barrierMu.Unlock()
}

func TestBarrier_NodeContextCancelledReturnsErrLeadershipLost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// Cancel node context
	node.nodeCancel()

	// Calling Barrier when node context is cancelled must return storage.ErrLeadershipLost
	err = node.Barrier(ctx)
	require.ErrorIs(t, err, storage.ErrLeadershipLost)

	node.barrierMu.Lock()
	assert.Nil(t, node.activeBarrier)
	assert.Nil(t, node.pendingBarrier)
	node.barrierMu.Unlock()
}

func TestBarrier_PendingFailsFastOnNonLeaderActiveRound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftNodeID:          "node-1",
		RaftBootstrapExpect: 3,
		RaftPeers:           []string{"node-1=127.0.0.1:0"},
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.False(t, node.IsLeader())

	// Setup active and pending barriers
	activeRound := &barrierRound{done: make(chan struct{})}
	pendingRound := &barrierRound{done: make(chan struct{})}

	node.barrierMu.Lock()
	node.activeBarrier = activeRound
	node.pendingBarrier = pendingRound
	node.barrierMu.Unlock()

	// Execute active round
	start := time.Now()
	node.runBarrierRound(activeRound)
	elapsed := time.Since(start)

	// Both active and pending rounds must finish immediately without a 10s timeout
	assert.Less(t, elapsed, 2*time.Second)

	select {
	case <-activeRound.done:
		require.ErrorIs(t, activeRound.err, storage.ErrNotLeader)
	case <-time.After(2 * time.Second):
		t.Fatal("activeRound did not complete")
	}

	select {
	case <-pendingRound.done:
		require.ErrorIs(t, pendingRound.err, storage.ErrNotLeader)
	case <-time.After(2 * time.Second):
		t.Fatal("pendingRound did not fail fast")
	}

	node.barrierMu.Lock()
	assert.Nil(t, node.activeBarrier)
	assert.Nil(t, node.pendingBarrier)
	node.barrierMu.Unlock()
}

func TestBarrier_PendingFailsFastOnLeadershipLossDuringActiveBarrier(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	nsStore, err := store.NewNamespaceStore(ctx, dir)
	require.NoError(t, err)

	cfg := config.Config{
		RaftBind:            "127.0.0.1:0",
		RaftBootstrapExpect: 1,
	}

	node, err := NewRaftNode(ctx, cfg, nsStore, dir)
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	require.Eventually(t, func() bool {
		return node.IsLeader()
	}, 5*time.Second, 50*time.Millisecond)

	// Setup active round
	activeRound := &barrierRound{done: make(chan struct{})}
	node.barrierMu.Lock()
	node.activeBarrier = activeRound
	node.barrierMu.Unlock()

	// Queue a barrier request which becomes pendingBarrier
	pendingErrCh := make(chan error, 1)
	go func() {
		pendingErrCh <- node.Barrier(ctx)
	}()

	require.Eventually(t, func() bool {
		node.barrierMu.Lock()
		defer node.barrierMu.Unlock()
		return node.pendingBarrier != nil
	}, 2*time.Second, 10*time.Millisecond)

	// Cancel node context to simulate leadership loss / shutdown during active barrier
	node.nodeCancel()

	start := time.Now()
	// Run activeRound; defer will see nodeCtx cancelled and fail pendingBarrier fast
	node.runBarrierRound(activeRound)

	select {
	case err := <-pendingErrCh:
		require.ErrorIs(t, err, storage.ErrLeadershipLost)
		assert.Less(t, time.Since(start), 2*time.Second)
	case <-time.After(2 * time.Second):
		t.Fatal("pending barrier did not fail fast")
	}

	node.barrierMu.Lock()
	assert.Nil(t, node.activeBarrier)
	assert.Nil(t, node.pendingBarrier)
	node.barrierMu.Unlock()
}

func TestBarrier_PendingFailsFastOnActiveRoundLeadershipLostError(t *testing.T) {
	// Directly test that when active round experiences ErrLeadershipLost or ErrNotLeader,
	// the pending barrier fails immediately with the error and is not executed.
	for _, testErr := range []error{hashiraft.ErrLeadershipLost, hashiraft.ErrNotLeader} {
		t.Run(testErr.Error(), func(t *testing.T) {
			node := &RaftNode{}
			activeRound := &barrierRound{done: make(chan struct{}), err: testErr}
			pendingRound := &barrierRound{done: make(chan struct{})}

			node.activeBarrier = activeRound
			node.pendingBarrier = pendingRound

			// Simulate promotion block from runBarrierRound defer
			node.barrierMu.Lock()
			node.activeBarrier = node.pendingBarrier
			node.pendingBarrier = nil
			if node.activeBarrier != nil {
				if !node.IsLeader() || (node.nodeCtx != nil && node.nodeCtx.Err() != nil) ||
					(activeRound.err != nil && (errors.Is(activeRound.err, hashiraft.ErrNotLeader) || errors.Is(activeRound.err, hashiraft.ErrLeadershipLost))) {
					node.activeBarrier.err = activeRound.err
					if node.activeBarrier.err == nil {
						node.activeBarrier.err = storage.ErrLeadershipLost
					}
					close(node.activeBarrier.done)
					node.activeBarrier = nil
				} else {
					go node.runBarrierRound(node.activeBarrier)
				}
			}
			close(activeRound.done)
			node.barrierMu.Unlock()

			select {
			case <-pendingRound.done:
				require.ErrorIs(t, pendingRound.err, testErr)
			case <-time.After(1 * time.Second):
				t.Fatal("pendingRound did not fail fast")
			}

			node.barrierMu.Lock()
			assert.Nil(t, node.activeBarrier)
			assert.Nil(t, node.pendingBarrier)
			node.barrierMu.Unlock()
		})
	}
}

type mockBarrierFuture struct {
	err error
}

func (m mockBarrierFuture) Error() error {
	return m.err
}

func TestBarrier_TranslatesSentinelErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		raftErr     error
		expectedErr error
	}{
		{
			name:        "translates hashiraft.ErrNotLeader to storage.ErrNotLeader",
			raftErr:     hashiraft.ErrNotLeader,
			expectedErr: storage.ErrNotLeader,
		},
		{
			name:        "translates hashiraft.ErrLeadershipLost to storage.ErrLeadershipLost",
			raftErr:     hashiraft.ErrLeadershipLost,
			expectedErr: storage.ErrLeadershipLost,
		},
		{
			name:        "wraps generic raft error",
			raftErr:     errors.New("connection reset by peer"),
			expectedErr: errors.New("raft barrier failed: connection reset by peer"),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			node := &RaftNode{
				isLeaderOverride: func() bool { return true },
				barrierOverride: func(time.Duration) hashiraft.Future {
					return mockBarrierFuture{err: tt.raftErr}
				},
			}

			err := node.Barrier(context.Background())
			require.Error(t, err)
			if tt.raftErr == hashiraft.ErrNotLeader || tt.raftErr == hashiraft.ErrLeadershipLost {
				assert.ErrorIs(t, err, tt.expectedErr)
			} else {
				assert.Equal(t, tt.expectedErr.Error(), err.Error())
			}
		})
	}
}

func TestBarrier_PreCanceledContext(t *testing.T) {
	t.Parallel()

	called := false
	node := &RaftNode{
		isLeaderOverride: func() bool { return true },
		barrierOverride: func(time.Duration) hashiraft.Future {
			called = true
			return mockBarrierFuture{}
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := node.Barrier(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, called, "barrier override should not have been called")

	node.barrierMu.Lock()
	assert.Nil(t, node.activeBarrier)
	assert.Nil(t, node.pendingBarrier)
	node.barrierMu.Unlock()
}
