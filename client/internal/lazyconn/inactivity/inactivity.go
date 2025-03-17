package inactivity

import (
	"context"
	"time"

	"github.com/netbirdio/netbird/client/internal/peer"
)

const (
	inactivityThreshold = 60 * time.Minute // idle after 1 hour inactivity
)

type Monitor struct {
	id     peer.ConnID
	timer  *time.Timer
	cancel context.CancelFunc
}

func NewInactivityMonitor(peerID peer.ConnID) *Monitor {
	i := &Monitor{
		id:    peerID,
		timer: time.NewTimer(0),
	}
	i.timer.Stop()
	return i
}

func (i *Monitor) Start(ctx context.Context, timeoutChan chan peer.ConnID) {
	i.timer.Reset(inactivityThreshold)
	defer i.timer.Stop()

	ctx, i.cancel = context.WithCancel(ctx)
	defer i.cancel()

	select {
	case <-i.timer.C:
		select {
		case timeoutChan <- i.id:
		case <-ctx.Done():
			return
		}
	case <-ctx.Done():
		return
	}
}

func (i *Monitor) Stop() {
	if i.cancel == nil {
		return
	}
	i.cancel()
}

func (i *Monitor) PauseTimer() {
	i.timer.Stop()
}

func (i *Monitor) ResetTimer() {
	i.timer.Reset(inactivityThreshold)
}
