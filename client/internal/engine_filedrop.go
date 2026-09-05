package internal

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"

	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/filedrop"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/peer"
)

const fileDropWatchName = "the file drop receiver"

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
	e.setFileDropTunnel()
	e.fileDrop.SetReceivingChangeHandler(e.onFileDropPolicyChange)

	if e.config.BlockInbound {
		log.Info("file drop receiver is disabled because inbound connections are blocked")
		return
	}
	if !e.fileDrop.ReceivingEnabled() {
		log.Info("file drop receiver is not started because receiving is turned off")
		return
	}

	wgAddr := e.wgInterface.Address()
	if !e.overlayAddrReady(wgAddr.IP) {
		log.Infof("file drop receiver waits for the overlay address %s", wgAddr.IP)
		e.armOverlayWatch(fileDropWatchName, e.restartFileDrop)
		return
	}

	addr := netip.AddrPortFrom(wgAddr.IP, fileDropListenPort())
	resolver := filedropResolver{status: e.statusRecorder}

	netstackNet := e.wgInterface.GetNet()
	if err := e.fileDrop.StartReceiver(e.ctx, addr, netstackNet, resolver, fileDropListenControl(e.wgInterface)); err != nil {
		log.Errorf("failed to start file drop receiver: %v", err)
		return
	}

	bound := e.fileDrop.ReceiverPort()
	if bound == 0 {
		bound = addr.Port()
	}
	e.fileDropPort = bound

	if v6 := wgAddr.IPv6; v6.IsValid() {
		if err := e.fileDrop.AddReceiverListener(e.ctx, netip.AddrPortFrom(v6, bound)); err != nil {
			log.Warnf("failed to add IPv6 file drop listener: %v", err)
			e.armOverlayWatch(fileDropWatchName, e.restartFileDrop)
		}
	}

	if netstackNet != nil {
		if registrar, ok := e.firewall.(interface {
			RegisterNetstackService(protocol nftypes.Protocol, port uint16)
		}); ok {
			registrar.RegisterNetstackService(nftypes.TCP, bound)
		}
	}

	e.setupFileDropPortRedirection(bound)

	e.fileDropRunning = true
}

// setupFileDropPortRedirection keeps the tunnel-side port fixed when the receiver
// could not bind it, so senders always reach the well-known port.
func (e *Engine) setupFileDropPortRedirection(bound uint16) {
	if e.firewall == nil || bound == filedrop.Port {
		return
	}

	for _, addr := range e.fileDropLocalAddrs() {
		if err := e.firewall.AddInboundDNAT(addr, firewallManager.ProtocolTCP, filedrop.Port, bound); err != nil {
			log.Warnf("failed to add file drop port redirection on %s: %v", addr, err)
			continue
		}
		log.Infof("file drop port redirection enabled: %s:%d -> %s:%d", addr, filedrop.Port, addr, bound)
	}
}

func (e *Engine) removeFileDropPortRedirection(bound uint16) {
	if e.firewall == nil || bound == 0 || bound == filedrop.Port {
		return
	}

	for _, addr := range e.fileDropLocalAddrs() {
		if err := e.firewall.RemoveInboundDNAT(addr, firewallManager.ProtocolTCP, filedrop.Port, bound); err != nil {
			log.Warnf("failed to remove file drop port redirection on %s: %v", addr, err)
			continue
		}
		log.Debugf("file drop port redirection removed: %s:%d -> %s:%d", addr, filedrop.Port, addr, bound)
	}
}

func (e *Engine) fileDropLocalAddrs() []netip.Addr {
	if e.wgInterface == nil {
		return nil
	}

	wgAddr := e.wgInterface.Address()
	var addrs []netip.Addr
	if wgAddr.IP.IsValid() {
		addrs = append(addrs, wgAddr.IP)
	}
	if wgAddr.IPv6.IsValid() {
		addrs = append(addrs, wgAddr.IPv6)
	}
	return addrs
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
		dial = fileDropOSDial(e.wgInterface)
	}

	e.fileDrop.SetTunnel(dial, e.statusRecorder.GetLocalPeerState().FQDN)
}

// restartFileDrop gives the receiver listeners on the interface as it is now.
// The listeners are bound to the overlay address of the interface being swapped
// out and do not survive it: Android renews the tun on every route change, which
// leaves the IPv4 listener dead with accept4: invalid argument. A receiver that
// is not running is started rather than skipped, since the reason it is down may
// be the very bind this rebind can now make. See Engine.rebindOverlayListeners.
func (e *Engine) restartFileDrop() error {
	if e.fileDrop == nil || e.wgInterface == nil {
		return nil
	}

	if !e.fileDropRunning {
		e.startFileDrop()
		return nil
	}

	e.stopFileDrop()
	e.startFileDrop()
	return nil
}

// onFileDropPolicyChange binds or unbinds the receiver after the profile turned
// receiving on or off. The work is handed to a goroutine because it needs
// syncMsgMux, which the caller (a settings RPC) must not wait on and which the
// engine may itself hold while calling into the manager.
func (e *Engine) onFileDropPolicyChange() {
	if e.ctx.Err() != nil {
		return
	}

	e.shutdownWg.Add(1)
	go func() {
		defer e.shutdownWg.Done()

		e.syncMsgMux.Lock()
		defer e.syncMsgMux.Unlock()

		if e.fileDrop == nil || e.ctx.Err() != nil {
			return
		}
		if e.fileDrop.ReceivingEnabled() {
			e.startFileDrop()
			return
		}
		if e.fileDropRunning {
			e.unbindFileDropReceiver()
			if err := e.fileDrop.DisableReceiving(); err != nil {
				log.Warnf("failed to stop file drop receiver: %v", err)
			}
			e.fileDropRunning = false
			e.fileDropPort = 0
		}
	}()
}

// unbindFileDropReceiver releases what the bind claimed outside the receiver
// itself. The caller must hold syncMsgMux.
func (e *Engine) unbindFileDropReceiver() {
	if netstackNet := e.wgInterface.GetNet(); netstackNet != nil {
		if registrar, ok := e.firewall.(interface {
			UnregisterNetstackService(protocol nftypes.Protocol, port uint16)
		}); ok {
			registrar.UnregisterNetstackService(nftypes.TCP, e.fileDropPort)
		}
	}
	e.removeFileDropPortRedirection(e.fileDropPort)
}

func (e *Engine) stopFileDrop() {
	if e.fileDrop == nil {
		return
	}
	e.fileDrop.SetReceivingChangeHandler(nil)
	e.fileDrop.ClearTunnel()

	if e.fileDropRunning {
		e.unbindFileDropReceiver()
	}

	if err := e.fileDrop.StopReceiver(); err != nil {
		log.Warnf("failed to stop file drop receiver: %v", err)
	}
	e.fileDropRunning = false
	e.fileDropPort = 0
}

// fileDropListenPort is the port the receiver tries to bind locally; the
// tunnel-side port stays filedrop.Port whatever this resolves to.
func fileDropListenPort() uint16 {
	raw := os.Getenv(filedrop.EnvPort)
	if raw == "" {
		return filedrop.Port
	}

	port, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		log.Warnf("invalid %s value %q, using %d", filedrop.EnvPort, raw, filedrop.Port)
		return filedrop.Port
	}
	return uint16(port)
}
