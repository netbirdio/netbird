package internal

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	log "github.com/sirupsen/logrus"

	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	rdpserver "github.com/netbirdio/netbird/client/rdp/server"
)

type rdpServer interface {
	Start(ctx context.Context, addr netip.AddrPort) error
	Stop() error
	GetPendingStore() *rdpserver.PendingStore
}

func (e *Engine) setupRDPPortRedirection() error {
	if e.firewall == nil || e.wgInterface == nil {
		return nil
	}

	localAddr := e.wgInterface.Address().IP
	if !localAddr.IsValid() {
		return errors.New("invalid local NetBird address")
	}

	if err := e.firewall.AddInboundDNAT(localAddr, firewallManager.ProtocolTCP, rdpserver.DefaultRDPAuthPort, rdpserver.InternalRDPAuthPort); err != nil {
		return fmt.Errorf("add RDP auth port redirection: %w", err)
	}
	log.Infof("RDP auth port redirection enabled: %s:%d -> %s:%d",
		localAddr, rdpserver.DefaultRDPAuthPort, localAddr, rdpserver.InternalRDPAuthPort)

	return nil
}

func (e *Engine) cleanupRDPPortRedirection() error {
	if e.firewall == nil || e.wgInterface == nil {
		return nil
	}

	localAddr := e.wgInterface.Address().IP
	if !localAddr.IsValid() {
		return errors.New("invalid local NetBird address")
	}

	if err := e.firewall.RemoveInboundDNAT(localAddr, firewallManager.ProtocolTCP, rdpserver.DefaultRDPAuthPort, rdpserver.InternalRDPAuthPort); err != nil {
		return fmt.Errorf("remove RDP auth port redirection: %w", err)
	}
	log.Debugf("RDP auth port redirection removed: %s:%d -> %s:%d",
		localAddr, rdpserver.DefaultRDPAuthPort, localAddr, rdpserver.InternalRDPAuthPort)

	return nil
}

func (e *Engine) startRDPServer() error {
	if e.wgInterface == nil {
		return errors.New("wg interface not initialized")
	}

	wgAddr := e.wgInterface.Address()

	cfg := &rdpserver.Config{
		NetworkAddr: wgAddr.Network,
	}

	server := rdpserver.New(cfg)

	netbirdIP := wgAddr.IP
	listenAddr := netip.AddrPortFrom(netbirdIP, rdpserver.InternalRDPAuthPort)

	if err := server.Start(e.ctx, listenAddr); err != nil {
		return fmt.Errorf("start RDP auth server: %w", err)
	}

	e.rdpServer = server

	if netstackNet := e.wgInterface.GetNet(); netstackNet != nil {
		if registrar, ok := e.firewall.(interface {
			RegisterNetstackService(protocol nftypes.Protocol, port uint16)
		}); ok {
			registrar.RegisterNetstackService(nftypes.TCP, rdpserver.InternalRDPAuthPort)
			log.Debugf("registered RDP auth service with netstack for TCP:%d", rdpserver.InternalRDPAuthPort)
		}
	}

	if err := e.setupRDPPortRedirection(); err != nil {
		log.Warnf("failed to setup RDP auth port redirection: %v", err)
	}

	return nil
}

func (e *Engine) stopRDPServer() error {
	if e.rdpServer == nil {
		return nil
	}

	if err := e.cleanupRDPPortRedirection(); err != nil {
		log.Warnf("failed to cleanup RDP auth port redirection: %v", err)
	}

	if netstackNet := e.wgInterface.GetNet(); netstackNet != nil {
		if registrar, ok := e.firewall.(interface {
			UnregisterNetstackService(protocol nftypes.Protocol, port uint16)
		}); ok {
			registrar.UnregisterNetstackService(nftypes.TCP, rdpserver.InternalRDPAuthPort)
			log.Debugf("unregistered RDP auth service from netstack for TCP:%d", rdpserver.InternalRDPAuthPort)
		}
	}

	log.Info("stopping RDP auth server")
	err := e.rdpServer.Stop()
	e.rdpServer = nil
	if err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	return nil
}
