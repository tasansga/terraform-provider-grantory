package raft

import (
	"context"
	"errors"
	"fmt"
	"time"

	hashiraft "github.com/hashicorp/raft"

	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

const (
	// DefaultBarrierTimeout is the maximum duration to wait for a Raft barrier round to complete.
	DefaultBarrierTimeout = 10 * time.Second
)

type barrierRound struct {
	done chan struct{}
	err  error
}

// Barrier verifies leadership and ensures all prior operations have been committed and applied.
// It uses round-based barrier batching to coalesce concurrent requests while guaranteeing
// strict linearizability for newly arrived reads.
func (n *RaftNode) Barrier(ctx context.Context) error {
	if n == nil || (n.raft == nil && n.barrierOverride == nil) {
		return errors.New("raft not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !n.IsLeader() {
		return storage.ErrNotLeader
	}
	if n.nodeCtx != nil && n.nodeCtx.Err() != nil {
		return storage.ErrLeadershipLost
	}

	var round *barrierRound
	n.barrierMu.Lock()
	if n.activeBarrier == nil {
		round = &barrierRound{done: make(chan struct{})}
		n.activeBarrier = round
		go n.runBarrierRound(round)
	} else {
		if n.pendingBarrier == nil {
			n.pendingBarrier = &barrierRound{done: make(chan struct{})}
		}
		round = n.pendingBarrier
	}
	n.barrierMu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-round.done:
		return round.err
	}
}

func (n *RaftNode) runBarrierRound(round *barrierRound) {
	defer func() {
		if r := recover(); r != nil {
			round.err = fmt.Errorf("barrier panic: %v", r)
		}
		n.barrierMu.Lock()
		n.activeBarrier = n.pendingBarrier
		n.pendingBarrier = nil
		if n.activeBarrier != nil {
			if !n.IsLeader() || (n.nodeCtx != nil && n.nodeCtx.Err() != nil) ||
				(round.err != nil && (errors.Is(round.err, storage.ErrNotLeader) || errors.Is(round.err, storage.ErrLeadershipLost) || errors.Is(round.err, hashiraft.ErrNotLeader) || errors.Is(round.err, hashiraft.ErrLeadershipLost))) {
				n.activeBarrier.err = round.err
				if n.activeBarrier.err == nil {
					n.activeBarrier.err = storage.ErrLeadershipLost
				}
				close(n.activeBarrier.done)
				n.activeBarrier = nil
			} else {
				go n.runBarrierRound(n.activeBarrier)
			}
		}
		close(round.done)
		n.barrierMu.Unlock()
	}()

	var future hashiraft.Future
	if n.barrierOverride != nil {
		future = n.barrierOverride(DefaultBarrierTimeout)
	} else {
		future = n.raft.Barrier(DefaultBarrierTimeout)
	}
	if err := future.Error(); err != nil {
		if errors.Is(err, hashiraft.ErrNotLeader) {
			round.err = storage.ErrNotLeader
		} else if errors.Is(err, hashiraft.ErrLeadershipLost) {
			round.err = storage.ErrLeadershipLost
		} else {
			round.err = fmt.Errorf("raft barrier failed: %w", err)
		}
	}
}
