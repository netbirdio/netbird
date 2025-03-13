package inactivity

import (
	"context"
	"time"

	"github.com/netbirdio/netbird/client/internal/peer"
)

const (
	inactivityThreshold = 30 * time.Second // idle after 1 hour inactivity
)

type InactivityMonitor struct {
	id     peer.ConnID
	timer  *time.Timer
	cancel context.CancelFunc
}

func NewInactivityMonitor(peerID peer.ConnID) *InactivityMonitor {
	i := &InactivityMonitor{
		id:    peerID,
		timer: time.NewTimer(0),
	}
	i.timer.Stop()
	return i
}

func (i *InactivityMonitor) Start(ctx context.Context, timeoutChan chan peer.ConnID) {
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

func (i *InactivityMonitor) Stop() {
	i.cancel()
}

func (i *InactivityMonitor) PauseTimer() {
	i.timer.Stop()
}

func (i *InactivityMonitor) ResetTimer() {
	i.timer.Reset(inactivityThreshold)
}
