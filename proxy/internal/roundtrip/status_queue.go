package roundtrip

import (
	"context"
	"errors"
	"hash/fnv"
	"sync"
	"time"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

// statusQueueShards bounds how many status updates are in flight to management at
// once. Every update is a unary SendStatusUpdate call.
const statusQueueShards = 16

// statusQueueDepth is the buffer per shard. A full shard blocks the caller until
// there is room or its context ends, so the mapping loop cannot run arbitrarily
// far ahead of management.
const statusQueueDepth = 1024

// statusCallTimeout bounds one status call, so a call that never returns cannot
// hold up the rest of its shard.
const statusCallTimeout = 30 * time.Second

// errStatusQueueStopped is returned for an update offered after the queue stopped.
var errStatusQueueStopped = errors.New("status queue stopped")

type statusUpdate struct {
	serviceID types.ServiceID
	call      func(ctx context.Context) error
}

// statusQueue sends status updates to management off the caller's goroutine.
// Every update for one service goes to the same shard and so reaches management
// in the order it was queued: an error or a disconnect never overtakes an
// earlier connect for the same service.
type statusQueue struct {
	ctx    context.Context
	cancel context.CancelFunc
	shards []chan statusUpdate
	wg     sync.WaitGroup
}

func newStatusQueue(parent context.Context, shards, depth int) *statusQueue {
	ctx, cancel := context.WithCancel(parent)
	q := &statusQueue{ctx: ctx, cancel: cancel, shards: make([]chan statusUpdate, shards)}
	for i := range q.shards {
		ch := make(chan statusUpdate, depth)
		q.shards[i] = ch
		q.wg.Add(1)
		go q.run(ch)
	}
	return q
}

func (q *statusQueue) run(ch chan statusUpdate) {
	defer q.wg.Done()
	for {
		select {
		case <-q.ctx.Done():
			return
		case u := <-ch:
			callCtx, cancel := context.WithTimeout(q.ctx, statusCallTimeout)
			_ = u.call(callCtx)
			cancel()
		}
	}
}

// stop ends the workers and waits for them. Updates still queued are dropped.
// Safe to call more than once.
func (q *statusQueue) stop() {
	q.cancel()
	q.wg.Wait()
}

func (q *statusQueue) shard(serviceID types.ServiceID) chan statusUpdate {
	h := fnv.New32a()
	_, _ = h.Write([]byte(serviceID))
	return q.shards[h.Sum32()%uint32(len(q.shards))]
}

// enqueue queues an update without waiting for management. Room in the shard is
// taken even when ctx has already ended; ctx only limits the wait for room. It
// returns ctx's error or errStatusQueueStopped when the update was dropped.
func (q *statusQueue) enqueue(ctx context.Context, u statusUpdate) error {
	if q.ctx.Err() != nil {
		return errStatusQueueStopped
	}
	ch := q.shard(u.serviceID)
	select {
	case ch <- u:
		return nil
	default:
	}
	select {
	case ch <- u:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-q.ctx.Done():
		return errStatusQueueStopped
	}
}
