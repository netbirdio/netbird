package peer

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/iface"
)

const defaultWgKeepAlive = 25 * time.Second

type WgConfig struct {
	WgListenAddr string
	RemoteKey    string
	WgInterface  *iface.WGIface
	AllowedIps   string
	PreSharedKey *wgtypes.Key
}

type wgPeerManager struct {
	wgConfig WgConfig

	remoteAddr *net.UDPAddr
}

func newWgPeerManager(wgConfig WgConfig) *wgPeerManager {
	return &wgPeerManager{
		wgConfig: wgConfig,
	}
}

func (mgr *wgPeerManager) configureWgPeer(localDirectMode, remoteDirectMode, userspaceBind bool, remoteConn net.Conn, remoteWgPort int) error {
	var err error
	mgr.remoteAddr, err = net.ResolveUDPAddr("udp", remoteConn.RemoteAddr().String())
	if err != nil {
		return err
	}

	if remoteDirectMode {
		mgr.remoteAddr.Port = remoteWgPort
	}

	if userspaceBind && localDirectMode {
		return mgr.updateWgPeer()
	}

	if localDirectMode && remoteDirectMode {
		return mgr.updateWgPeer()
	}

	mgr.remoteAddr, err = net.ResolveUDPAddr("udp", mgr.wgConfig.WgListenAddr)
	if err != nil {
		return err
	}
	return mgr.updateWgPeer()
}

// Close removes peer from the WireGuard interface
func (mgr *wgPeerManager) close() error {
	return mgr.wgConfig.WgInterface.RemovePeer(mgr.wgConfig.RemoteKey)
}

func (mgr *wgPeerManager) updateWgPeer() error {
	return mgr.wgConfig.WgInterface.UpdatePeer(mgr.wgConfig.RemoteKey, mgr.wgConfig.AllowedIps, defaultWgKeepAlive,
		mgr.remoteAddr, mgr.wgConfig.PreSharedKey)
}
