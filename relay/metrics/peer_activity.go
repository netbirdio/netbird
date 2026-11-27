package metrics

import (
	"sync/atomic"
	"time"
)

type PeerActivity struct {
	lastActive atomic.Int64
}

func NewPeerActivity() *PeerActivity {
	return &PeerActivity{}
}

func (a *PeerActivity) Mark() {
	a.lastActive.Store(time.Now().UnixNano())
}

func (a *PeerActivity) Idle(now time.Time) bool {
	lastActive := a.lastActive.Load()
	if lastActive == 0 {
		return true
	}
	return now.Sub(time.Unix(0, lastActive)) > idleTimeout
}
