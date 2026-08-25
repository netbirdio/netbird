package netsweep

import (
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/netbirdio/netbird/client/netstate"
)

const quickRetryDelay = 200 * time.Millisecond

type quickRetryBackoff struct {
	backoff.BackOff
	sweeper  *Sweeper
	netState *netstate.State
	used     bool
}

func newQuickRetryBackoff(bo backoff.BackOff, sweeper *Sweeper, netState *netstate.State) *quickRetryBackoff {
	return &quickRetryBackoff{
		BackOff:  bo,
		sweeper:  sweeper,
		netState: netState,
	}
}

func (b *quickRetryBackoff) NextBackOff() time.Duration {
	if !b.used && b.sweeper.markedRecently() && b.netState.IsOnline() {
		b.used = true
		return quickRetryDelay
	}
	return b.BackOff.NextBackOff()
}

func (b *quickRetryBackoff) Reset() {
	b.used = false
	b.BackOff.Reset()
}
