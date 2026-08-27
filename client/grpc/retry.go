package grpc

import (
	"context"
	"errors"
	"time"

	"github.com/cenkalti/backoff/v4"
)

// ChangeWatcher exposes OS network availability transitions.
type ChangeWatcher interface {
	Changed() <-chan struct{}
}

// Retry mirrors backoff.Retry, but the sleep between attempts also wakes on
// OS network availability transitions: an operation cut down by a network
// change retries the moment the network settles instead of sleeping through
// the recovery. A nil watcher never fires, leaving plain backoff.Retry
// behavior.
func Retry(ctx context.Context, operation backoff.Operation, bo backoff.BackOff, watcher ChangeWatcher) error {
	bo.Reset()
	for {
		err := operation()
		if err == nil {
			return nil
		}

		var permanent *backoff.PermanentError
		if errors.As(err, &permanent) {
			return permanent.Err
		}

		next := bo.NextBackOff()
		if next == backoff.Stop {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return err
		}

		var changed <-chan struct{}
		if watcher != nil {
			changed = watcher.Changed()
		}
		timer := time.NewTimer(next)
		select {
		case <-timer.C:
		case <-changed:
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}
