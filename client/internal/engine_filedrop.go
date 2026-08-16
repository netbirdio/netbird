package internal

import (
	"context"
	"net"
	"net/netip"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/filedrop"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/peer"
)

type filedropResolver struct {
	status *peer.Status
}

// ResolvePeer implements filedrop.PeerResolver.
func (r filedropResolver) ResolvePeer(addr netip.Addr) (filedrop.PeerKey, string, bool) {
	state, ok := r.status.PeerStateByIP(addr.String())
	if !ok {
		return "", "", false
	}
	return filedrop.PeerKey(state.PubKey), state.FQDN, true
}

func (e *Engine) startFileDrop() {
	if e.fileDrop == nil || e.fileDropRunning || e.wgInterface == nil {
		return
	}
	if e.config.BlockInbound {
		log.Info("file drop receiver is disabled because inbound connections are blocked")
		e.setFileDropTunnel()
		return
	}

	wgAddr := e.wgInterface.Address()
	addr := netip.AddrPortFrom(wgAddr.IP, filedrop.Port)
	resolver := filedropResolver{status: e.statusRecorder}

	netstackNet := e.wgInterface.GetNet()
	if err := e.fileDrop.StartReceiver(e.ctx, addr, netstackNet, resolver); err != nil {
		log.Errorf("failed to start file drop receiver: %v", err)
		return
	}

	bound := e.fileDrop.ReceiverPort()
	if bound == 0 {
		bound = filedrop.Port
	}
	e.fileDropPort = bound

	if v6 := wgAddr.IPv6; v6.IsValid() {
		if err := e.fileDrop.AddReceiverListener(e.ctx, netip.AddrPortFrom(v6, bound)); err != nil {
			log.Warnf("failed to add IPv6 file drop listener: %v", err)
		}
	}

	if netstackNet != nil {
		if registrar, ok := e.firewall.(interface {
			RegisterNetstackService(protocol nftypes.Protocol, port uint16)
		}); ok {
			registrar.RegisterNetstackService(nftypes.TCP, bound)
		}
	}

	if bound != filedrop.Port {
		e.signaler.SetFiledropPort(bound)
	}

	e.setFileDropTunnel()
	e.fileDropRunning = true
}

// recordFiledropPort stores the file drop port a peer advertised over signaling;
// a value that does not fit a port is treated as the default.
func (e *Engine) recordFiledropPort(peerKey string, port uint32) {
	if e.fileDrop == nil {
		return
	}
	if port > 65535 {
		port = 0
	}
	e.fileDrop.Ports().Set(filedrop.PeerKey(peerKey), uint16(port))
}

func (e *Engine) setFileDropTunnel() {
	var dial filedrop.DialFunc
	if netstackNet := e.wgInterface.GetNet(); netstackNet != nil {
		dial = func(ctx context.Context, _, addr string) (net.Conn, error) {
			addrPort, err := netip.ParseAddrPort(addr)
			if err != nil {
				return nil, err
			}
			return netstackNet.DialContextTCPAddrPort(ctx, addrPort)
		}
	} else {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}

	e.fileDrop.SetTunnel(dial, e.statusRecorder.GetLocalPeerState().FQDN)
}

func (e *Engine) stopFileDrop() {
	if e.fileDrop == nil {
		return
	}

	if e.fileDropRunning {
		if netstackNet := e.wgInterface.GetNet(); netstackNet != nil {
			if registrar, ok := e.firewall.(interface {
				UnregisterNetstackService(protocol nftypes.Protocol, port uint16)
			}); ok {
				registrar.UnregisterNetstackService(nftypes.TCP, e.fileDropPort)
			}
		}
		e.signaler.SetFiledropPort(0)
	}

	if err := e.fileDrop.StopReceiver(); err != nil {
		log.Warnf("failed to stop file drop receiver: %v", err)
	}
	e.fileDropRunning = false
	e.fileDropPort = 0
}
