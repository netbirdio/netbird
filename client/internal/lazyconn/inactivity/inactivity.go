package inactivity

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	inactivityThreshold = 30 * time.Second // idle after 1 hour inactivity
)

type InactivityMonitor struct {
	peerID string
	timer  *time.Timer
	cancel context.CancelFunc
}

func NewInactivityMonitor(peerID string) *InactivityMonitor {
	i := &InactivityMonitor{
		peerID: peerID,
		timer:  time.NewTimer(0),
	}
	i.timer.Stop()
	return i
}

func (i *InactivityMonitor) Start(ctx context.Context, timeoutChan chan string) {
	i.timer.Reset(inactivityThreshold)
	defer i.timer.Stop()

	ctx, i.cancel = context.WithCancel(ctx)
	defer i.cancel()

	select {
	case <-i.timer.C:
		select {
		case timeoutChan <- i.peerID:
			log.Infof("--- idle timeout for peer: %s", i.peerID)
		case <-ctx.Done():
			return
		}
	case <-ctx.Done():
		return
	}
}

func (i *InactivityMonitor) Stop() {
	log.Info("--- cancel idle timer")
	i.cancel()
}

func (i *InactivityMonitor) PauseTimer() {
	log.Info("--- hangup idle timer")
	i.timer.Stop()
}

func (i *InactivityMonitor) ResetTimer() {
	log.Info("--- resetting idle timer")
	i.timer.Reset(inactivityThreshold)
}
