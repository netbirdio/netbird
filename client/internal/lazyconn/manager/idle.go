package manager

import (
	"context"
	"time"
)

const (
	idleTimeout = 60 * time.Minute // went to idle after 1 hour inactivity
)

type IdleWatch struct {
	onIdle chan struct{}
	timer  *time.Timer
}

func NewIdleWatch() *IdleWatch {
	i := &IdleWatch{
		onIdle: make(chan struct{}, 1),
		timer:  time.NewTimer(0),
	}
	i.timer.Stop()
	return i
}

// call on open connection
func (i *IdleWatch) Start(ctx context.Context) {
	i.timer.Reset(idleTimeout)
	defer i.timer.Stop()

	select {
	case <-i.timer.C:
		select {
		case i.Idle <- struct{}{}:
		default:
		}
	case <-ctx.Done():
		return
	}
}

func (i *IdleWatch) Stop() {
	// todo implement
}

// call when connected
func (i *IdleWatch) HangUp() {
	i.timer.Stop()
}

// call when switch to None priority
func (i *IdleWatch) Reset() {
	i.timer.Reset(idleTimeout)
}
