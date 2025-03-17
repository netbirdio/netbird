package inactivity

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/netbirdio/netbird/client/internal/peer"
)

const (
	defaultInactivityThreshold = 60 * time.Minute // idle after 1 hour inactivity
)

type Monitor struct {
	id                  peer.ConnID
	timer               *time.Timer
	cancel              context.CancelFunc
	inactivityThreshold time.Duration
}

func NewInactivityMonitor(peerID peer.ConnID) *Monitor {
	i := &Monitor{
		id:                  peerID,
		timer:               time.NewTimer(0),
		inactivityThreshold: inactivityThreshold(),
	}
	i.timer.Stop()
	return i
}

func (i *Monitor) Start(ctx context.Context, timeoutChan chan peer.ConnID) {
	i.timer.Reset(i.inactivityThreshold)
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
	i.timer.Reset(i.inactivityThreshold)
}

func inactivityThreshold() time.Duration {
	envValue := os.Getenv("NB_INACTIVITY_THRESHOLD")
	if envValue == "" {
		return defaultInactivityThreshold
	}

	parsedMinutes, err := strconv.Atoi(envValue)
	if err != nil || parsedMinutes <= 0 {
		return defaultInactivityThreshold
	}

	return time.Duration(parsedMinutes) * time.Minute
}
