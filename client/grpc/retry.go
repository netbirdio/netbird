package grpc

import (
	"context"
	"errors"

	"github.com/cenkalti/backoff/v4"

	"github.com/netbirdio/netbird/client/hbwatch"
)

// ChangeWatcher exposes OS network availability transitions.
type ChangeWatcher interface {
	Changed() <-chan struct{}
}

// Retry mirrors backoff.Retry, but the sleep between attempts also wakes on
// OS network availability transitions: an operation cut down by a network
// change retries the moment the network settles instead of sleeping through
// the recovery. On a mobile client the sleep is hbwatch.WaitRetryDelay, so
// a device wake past the wall deadline ends it too. A nil watcher never
// fires, leaving plain backoff.Retry behavior.
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
		if err := hbwatch.WaitRetryDelay(ctx, next, changed); err != nil {
			return err
		}
	}
}
