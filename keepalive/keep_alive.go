package keepalive

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	GrpcVersionHeaderKey = "version"

	reversProxyHeaderKey = "x-netbird-peer"
	keepAliveInterval    = 30 * time.Second
)

type KeepAlive struct {
	sync.RWMutex
	ticker       *time.Ticker
	done         chan struct{}
	streams      map[string]*ioMonitor
	keepAliveMsg interface{}
}

func NewKeepAlive(keepAliveMsg interface{}) *KeepAlive {
	ka := &KeepAlive{
		ticker:       time.NewTicker(1 * time.Second),
		done:         make(chan struct{}),
		streams:      make(map[string]*ioMonitor),
		keepAliveMsg: keepAliveMsg,
	}
	go ka.start()
	return ka
}

func (k *KeepAlive) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		address, supported := k.keepAliveIsSupported(stream.Context())
		if !supported {
			return handler(srv, stream)
		}

		m := &ioMonitor{
			sync.Mutex{},
			stream,
			time.Now(),
		}

		k.addIoMonitor(address, m)

		return handler(srv, m)
	}
}

func (k *KeepAlive) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		address, supported := k.keepAliveIsSupported(ctx)
		if supported {
			k.updateLastSeen(address)
		}
		return handler(ctx, req)
	}
}

func (k *KeepAlive) Stop() {
	select {
	case k.done <- struct{}{}:
		k.ticker.Stop()
		return
	default:
	}
}

func (k *KeepAlive) start() {
	for {
		select {
		case <-k.done:
			return
		case t := <-k.ticker.C:
			k.checkKeepAlive(t)
		}
	}
}

func (k *KeepAlive) checkKeepAlive(now time.Time) {
	k.Lock()
	defer k.Unlock()
	for addr, m := range k.streams {
		if k.isKeepAliveOutDated(now, m) {
			continue
		}
		err := k.sendKeepAlive(m)
		if err != nil {
			log.Debugf("stop keepalive for: %s", addr)
			delete(k.streams, addr)
		}
	}
}

func (k *KeepAlive) keepAliveIsSupported(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Warnf("metadata not found")
		return "", false
	}

	peerAddress := k.addressFromHeader(md)
	if peerAddress == "" {
		log.Debugf("peer is not using reverse proxy")
		return "", false
	}

	if len(md.Get(GrpcVersionHeaderKey)) == 0 {
		log.Debugf("version info not found")
		return "", false
	}
	return peerAddress, true
}

func (k *KeepAlive) addIoMonitor(address string, m *ioMonitor) {
	k.Lock()
	defer k.Unlock()
	k.streams[address] = m
}

func (k *KeepAlive) sendKeepAlive(m *ioMonitor) error {
	return m.sendMsg(k.keepAliveMsg)
}

func (k *KeepAlive) updateLastSeen(address string) {
	k.RLock()
	m, ok := k.streams[address]
	k.RUnlock()
	if !ok {
		return
	}
	m.updateLastSeen()
}

func (k *KeepAlive) addressFromHeader(md metadata.MD) string {
	peer := md.Get(reversProxyHeaderKey)
	if len(peer) == 0 {
		return ""
	}
	return peer[0]
}

func (k *KeepAlive) isKeepAliveOutDated(now time.Time, m *ioMonitor) bool {
	return now.Sub(m.getLastSeen()) < keepAliveInterval
}
