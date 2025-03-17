package internal

import (
	"context"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/lazyconn/manager"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
)

const (
	envDisableLazyConn = "NB_LAZY_CONN_DISABLE"
)

// ConnMgr coordinates both lazy connections (established on-demand) and permanent peer connections.
//
// The connection manager is responsible for:
// - Managing lazy connections via the lazyConnManager
// - Maintaining a list of excluded peers that should always have permanent connections
// - Handling connection establishment based on peer signaling
type ConnMgr struct {
	peerStore   *peerstore.Store
	lazyConnMgr *manager.Manager

	connStateListener *peer.ConnectionListener

	mu        sync.Mutex
	wg        sync.WaitGroup
	ctx       context.Context
	ctxCancel context.CancelFunc
}

func NewConnMgr(peerStore *peerstore.Store, iface lazyconn.WGIface, dispatcher *peer.ConnectionDispatcher) *ConnMgr {
	var lazyConnMgr *manager.Manager
	if os.Getenv(envDisableLazyConn) != "true" {
		lazyConnMgr = manager.NewManager(iface, dispatcher)
	}

	e := &ConnMgr{
		peerStore:   peerStore,
		lazyConnMgr: lazyConnMgr,
	}
	return e
}

func (e *ConnMgr) Start(parentCtx context.Context) {
	if e.lazyConnMgr == nil {
		log.Infof("lazy connection manager is disabled")
		return
	}

	ctx, cancel := context.WithCancel(parentCtx)
	e.ctx = ctx
	e.ctxCancel = cancel

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.lazyConnMgr.Start(ctx, e.onActive, e.onInactive)
	}()
}

func (e *ConnMgr) AddExcludeFromLazyConnection(peerID string) {
	e.lazyConnMgr.ExcludePeer(peerID)
}

func (e *ConnMgr) AddPeerConn(peerKey string, conn *peer.Conn) (exists bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if success := e.peerStore.AddPeerConn(peerKey, conn); !success {
		return true
	}

	if !e.isStartedWithLazyMgr() {
		if err := conn.Open(e.ctx); err != nil {
			conn.Log.Errorf("failed to open connection: %v", err)
		}
		return
	}

	lazyPeerCfg := lazyconn.PeerConfig{
		PublicKey:  peerKey,
		AllowedIPs: conn.WgConfig().AllowedIps,
		PeerConnID: conn.ConnID(),
		Log:        conn.Log,
	}
	excluded, err := e.lazyConnMgr.AddPeer(lazyPeerCfg)
	if err != nil {
		conn.Log.Errorf("failed to add peer to lazyconn manager: %v", err)
		if err := conn.Open(e.ctx); err != nil {
			conn.Log.Errorf("failed to open connection: %v", err)
		}
		return
	}

	if excluded {
		conn.Log.Infof("peer is on lazy conn manager exclude list, opening connection")
		if err := conn.Open(e.ctx); err != nil {
			conn.Log.Errorf("failed to open connection: %v", err)
		}
		return
	}

	conn.Log.Infof("peer added to lazy conn manager")
	return
}

func (e *ConnMgr) OnSignalMsg(peerKey string) (*peer.Conn, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	conn, ok := e.peerStore.PeerConn(peerKey)
	if !ok {
		return nil, false
	}

	if !e.isStartedWithLazyMgr() {
		return conn, true
	}

	if found := e.lazyConnMgr.ActivatePeer(peerKey); found {
		if err := conn.Open(e.ctx); err != nil {
			conn.Log.Errorf("failed to open connection: %v", err)
		}
	}
	return conn, true
}

func (e *ConnMgr) RemovePeerConn(peerKey string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	conn, ok := e.peerStore.Remove(peerKey)
	if !ok {
		return
	}
	defer conn.Close()

	if !e.isStartedWithLazyMgr() {
		return
	}

	e.lazyConnMgr.RemovePeer(peerKey)
	conn.Log.Infof("removed peer from lazy conn manager")
}

func (e *ConnMgr) Close() {
	if !e.isStartedWithLazyMgr() {
		return
	}

	e.ctxCancel()
	e.wg.Wait()
	e.lazyConnMgr = nil
}

func (e *ConnMgr) onActive(peerID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.peerStore.PeerConnOpen(e.ctx, peerID)
}

func (e *ConnMgr) onInactive(peerID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.peerStore.PeerConnClose(peerID)
}

func (e *ConnMgr) isStartedWithLazyMgr() bool {
	return e.lazyConnMgr != nil && e.ctxCancel != nil
}
