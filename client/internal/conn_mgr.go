package internal

import (
	"context"
	"os"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/lazyconn/manager"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peer/dispatcher"
	"github.com/netbirdio/netbird/client/internal/peerstore"
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

	mu        sync.Mutex
	wg        sync.WaitGroup
	ctx       context.Context
	ctxCancel context.CancelFunc
}

func NewConnMgr(engineConfig *EngineConfig, statusRecorder *peer.Status, peerStore *peerstore.Store, iface lazyconn.WGIface, dispatcher *dispatcher.ConnectionDispatcher) *ConnMgr {
	e := &ConnMgr{
		peerStore: peerStore,
	}
	if engineConfig.LazyConnectionEnabled || lazyconn.IsLazyConnEnabledByEnv() {
		cfg := manager.Config{
			InactivityThreshold: inactivityThresholdEnv(),
		}
		e.lazyConnMgr = manager.NewManager(cfg, iface, dispatcher)
		statusRecorder.UpdateLazyConnection(true)
	} else {
		statusRecorder.UpdateLazyConnection(false)
	}
	return e
}

func (e *ConnMgr) Start(parentCtx context.Context) {
	if e.lazyConnMgr == nil {
		log.Infof("lazy connection manager is disabled")
		e.ctx = parentCtx
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

// SetExcludeList sets the list of peer IDs that should always have permanent connections.
func (e *ConnMgr) SetExcludeList(peerIDs []string) {
	if e.lazyConnMgr == nil {
		return
	}

	excludedPeers := make([]lazyconn.PeerConfig, 0, len(peerIDs))

	for _, peerID := range peerIDs {
		var peerConn *peer.Conn
		var exists bool
		if peerConn, exists = e.peerStore.PeerConn(peerID); !exists {
			continue
		}

		lazyPeerCfg := lazyconn.PeerConfig{
			PublicKey:  peerID,
			AllowedIPs: peerConn.WgConfig().AllowedIps,
			PeerConnID: peerConn.ConnID(),
			Log:        peerConn.Log,
		}
		excludedPeers = append(excludedPeers, lazyPeerCfg)
	}

	added := e.lazyConnMgr.ExcludePeer(e.ctx, excludedPeers)
	for _, peerID := range added {
		var peerConn *peer.Conn
		var exists bool
		if peerConn, exists = e.peerStore.PeerConn(peerID); !exists {
			// if the peer not exist in the store, it means that the engine will call the AddPeerConn in next step
			continue
		}

		peerConn.Log.Infof("peer has been added to lazy connection exclude list, opening permanent connection")
		if err := peerConn.Open(e.ctx); err != nil {
			peerConn.Log.Errorf("failed to open connection: %v", err)
		}
	}
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

	if !lazyconn.IsSupported(conn.AgentVersionString()) {
		conn.Log.Warnf("peer does not support lazy connection (%s), open permanent connection", conn.AgentVersionString())
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
		conn.Log.Infof("activated peer from inactive state")
		if err := conn.Open(e.ctx); err != nil {
			conn.Log.Errorf("failed to open connection: %v", err)
		}
	}
	return conn, true
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

func inactivityThresholdEnv() *time.Duration {
	envValue := os.Getenv(lazyconn.EnvInactivityThreshold)
	if envValue == "" {
		return nil
	}

	parsedMinutes, err := strconv.Atoi(envValue)
	if err != nil || parsedMinutes <= 0 {
		return nil
	}

	d := time.Duration(parsedMinutes) * time.Minute
	return &d
}
