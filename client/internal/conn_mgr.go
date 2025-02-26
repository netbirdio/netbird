package internal

import (
	"context"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	lazyConnManager "github.com/netbirdio/netbird/client/internal/lazyconn/manager"
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
	lazyConnMgr *lazyConnManager.Manager
	peerStore   *peerstore.Store

	excludes map[string]struct{}
}

func NewConnMgr(peerStore *peerstore.Store, iface lazyconn.WGIface) *ConnMgr {
	var lazyConnMgr *lazyConnManager.Manager
	if os.Getenv(envDisableLazyConn) != "true" {
		lazyConnMgr = lazyConnManager.NewManager(iface)
	}

	e := &ConnMgr{
		peerStore:   peerStore,
		lazyConnMgr: lazyConnMgr,
	}
	return e
}

func (e *ConnMgr) Start(ctx context.Context) {
	if e.lazyConnMgr == nil {
		log.Infof("lazy connection manager is disabled")
		return
	}

	e.lazyConnMgr.Start(ctx)
	go e.receiveLazyConnEvents(ctx)
}

func (e *ConnMgr) AddExcludeFromLazyConnection(peerID string) {
	e.excludes[peerID] = struct{}{}
}

func (e *ConnMgr) AddPeerConn(peerKey string, conn *peer.Conn) (exists bool) {
	if success := e.peerStore.AddPeerConn(peerKey, conn); !success {
		return true
	}

	if e.lazyConnMgr == nil {
		conn.Open()
		return
	}

	_, exists = e.excludes[peerKey]
	if exists {
		conn.Open()
		return
	}

	lazyPeerCfg := lazyconn.PeerConfig{
		PublicKey:  peerKey,
		AllowedIPs: conn.WgConfig().AllowedIps,
	}
	if err := e.lazyConnMgr.AddPeer(lazyPeerCfg); err != nil {
		log.Errorf("failed to add peer to lazyconn manager: %v", err)
		conn.Open()
	}
	return
}

func (e *ConnMgr) OnSignalMsg(peerKey string) (*peer.Conn, bool) {
	conn, ok := e.peerStore.PeerConn(peerKey)
	if !ok {
		return nil, false
	}

	if e.lazyConnMgr == nil {
		return conn, true
	}

	if ok := e.lazyConnMgr.RemovePeer(peerKey); ok {
		conn.Open()
	}
	return conn, true
}

func (e *ConnMgr) RemovePeerConn(peerKey string) {
	conn, ok := e.peerStore.Remove(peerKey)
	if ok {
		conn.Close()
	}

	if e.lazyConnMgr == nil {
		return
	}

	e.lazyConnMgr.RemovePeer(peerKey)
}

func (e *ConnMgr) Close() {
	if e.lazyConnMgr == nil {
		return
	}
	// todo wait for receiveLazyConnEvents to finish
	e.lazyConnMgr.Close()
}

func (e *ConnMgr) receiveLazyConnEvents(ctx context.Context) {
	for {
		select {
		case peerID := <-e.lazyConnMgr.PeerActivityChan:
			e.peerStore.PeerConnOpen(peerID)
		case <-ctx.Done():
		}
	}
}
