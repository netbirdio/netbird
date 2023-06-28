package keepalive

import (
	"sync"
	"time"

	"google.golang.org/grpc"
)

type ioMonitor struct {
	mu         sync.Mutex
	streamLock sync.Mutex
	grpc.ServerStream
	lastSeen time.Time
}

func (l *ioMonitor) sendMsg(m interface{}) error {
	l.updateLastSeen()
	l.streamLock.Lock()
	defer l.streamLock.Unlock()
	return l.ServerStream.SendMsg(m)
}

func (l *ioMonitor) updateLastSeen() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastSeen = time.Now()
}

func (l *ioMonitor) getLastSeen() time.Time {
	l.mu.Lock()
	t := l.lastSeen
	l.mu.Unlock()
	return t
}
