package client

import (
	"context"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	relayAuth "github.com/netbirdio/netbird/shared/relay/auth/hmac"
)

type foreignRelay struct {
	client  *Client
	created time.Time
	inUse   int
}

type ForeignRelaysStore struct {
	mu      sync.RWMutex
	clients map[string]*foreignRelay

	group singleflight.Group

	ctx                  context.Context
	tokenStore           *relayAuth.TokenStore
	peerID               string
	mtu                  uint16
	transportFallback    *transportFallback
	onDisconnect         func(string)
	keepUnusedServerTime time.Duration
}

func NewForeignRelaysStore(ctx context.Context, tokenStore *relayAuth.TokenStore, peerID string, mtu uint16, transportFallback *transportFallback, onDisconnect func(string), keepUnusedServerTime time.Duration) *ForeignRelaysStore {
	return &ForeignRelaysStore{
		clients:              make(map[string]*foreignRelay),
		ctx:                  ctx,
		tokenStore:           tokenStore,
		peerID:               peerID,
		mtu:                  mtu,
		transportFallback:    transportFallback,
		onDisconnect:         onDisconnect,
		keepUnusedServerTime: keepUnusedServerTime,
	}
}

func (f *ForeignRelaysStore) OpenConn(ctx context.Context, peerKey string, remoteRelayServer RelayServer) (net.Conn, error) {
	fr, err := f.acquire(remoteRelayServer)
	if err != nil {
		return nil, err
	}
	defer f.release(fr)

	return fr.client.OpenConn(ctx, peerKey)
}

func (f *ForeignRelaysStore) acquire(remoteRelayServer RelayServer) (*foreignRelay, error) {
	f.mu.Lock()
	if fr, ok := f.clients[remoteRelayServer.Addr]; ok {
		fr.inUse++
		f.mu.Unlock()
		return fr, nil
	}
	f.mu.Unlock()

	v, err, _ := f.group.Do(remoteRelayServer.Addr, func() (any, error) {
		f.mu.RLock()
		fr, ok := f.clients[remoteRelayServer.Addr]
		f.mu.RUnlock()
		if ok {
			return fr, nil
		}

		relayClient := NewClientWithServerIP(remoteRelayServer.Addr, remoteRelayServer.IP, f.tokenStore, f.peerID, f.mtu)
		relayClient.SetTransportFallback(f.transportFallback)
		if err := relayClient.Connect(f.ctx); err != nil {
			return nil, err
		}
		relayClient.SetOnDisconnectListener(f.onDisconnect)

		f.mu.Lock()
		fr = &foreignRelay{client: relayClient, created: time.Now()}
		f.clients[remoteRelayServer.Addr] = fr
		f.mu.Unlock()
		return fr, nil
	})
	if err != nil {
		return nil, err
	}

	fr := v.(*foreignRelay)
	f.mu.Lock()
	if cur, ok := f.clients[remoteRelayServer.Addr]; !ok || cur != fr {
		f.mu.Unlock()
		return f.acquire(remoteRelayServer)
	}
	fr.inUse++
	f.mu.Unlock()
	return fr, nil
}

func (f *ForeignRelaysStore) release(fr *foreignRelay) {
	f.mu.Lock()
	fr.inUse--
	f.mu.Unlock()
}

func (f *ForeignRelaysStore) evict(serverAddress string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.clients[serverAddress]; ok {
		delete(f.clients, serverAddress)
		log.Debugf("evicted disconnected foreign relay client: %s", serverAddress)
	}
}

func (f *ForeignRelaysStore) cleanupUnused() {
	f.mu.Lock()
	defer f.mu.Unlock()

	for addr, fr := range f.clients {
		if time.Since(fr.created) <= f.keepUnusedServerTime {
			continue
		}
		if fr.inUse > 0 {
			continue
		}
		if fr.client.HasConns() {
			continue
		}
		fr.client.SetOnDisconnectListener(nil)
		go func() {
			_ = fr.client.Close()
		}()
		log.Debugf("clean up unused relay server connection: %s", addr)
		delete(f.clients, addr)
	}
}

func (f *ForeignRelaysStore) states() []RelayConnState {
	f.mu.RLock()
	clients := make([]*Client, 0, len(f.clients))
	for _, fr := range f.clients {
		clients = append(clients, fr.client)
	}
	f.mu.RUnlock()

	states := make([]RelayConnState, 0, len(clients))
	for _, c := range clients {
		states = append(states, relayConnState(c))
	}
	return states
}
