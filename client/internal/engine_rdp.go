package internal

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	log "github.com/sirupsen/logrus"

	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	sshauth "github.com/netbirdio/netbird/client/ssh/auth"
	rdpserver "github.com/netbirdio/netbird/client/rdp/server"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	sshuserhash "github.com/netbirdio/netbird/shared/sshauth"
)

type rdpServer interface {
	Start(ctx context.Context, addr netip.AddrPort) error
	Stop() error
	GetPendingStore() *rdpserver.PendingStore
	UpdateRDPAuth(config *sshauth.Config)
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

// updateRDP handles starting/stopping the RDP server based on the config flag.
func (e *Engine) updateRDP() error {
	if !e.config.ServerRDPAllowed {
		if e.rdpServer != nil {
			log.Info("RDP passthrough disabled, stopping RDP auth server")
		}
		return e.stopRDPServer()
	}

	if e.config.BlockInbound {
		log.Info("RDP server is disabled because inbound connections are blocked")
		return e.stopRDPServer()
	}

	if e.rdpServer != nil {
		log.Debug("RDP auth server is already running")
		return nil
	}

	return e.startRDPServer()
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

	// Register the credential provider DLL dynamically (Windows only)
	if err := rdpserver.RegisterCredentialProvider(); err != nil {
		log.Warnf("failed to register RDP credential provider (passwordless RDP will not work): %v", err)
	}

	log.Info("RDP passthrough enabled")
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

	// Unregister the credential provider DLL (Windows only)
	if err := rdpserver.UnregisterCredentialProvider(); err != nil {
		log.Warnf("failed to unregister RDP credential provider: %v", err)
	}

	log.Info("stopping RDP auth server")
	err := e.rdpServer.Stop()
	e.rdpServer = nil
	if err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	return nil
}

// updateRDPServerAuth reuses the SSH authorization config for RDP access control.
// This means the same user/machine-user mappings that control SSH access also control RDP.
func (e *Engine) updateRDPServerAuth(sshAuth *mgmProto.SSHAuth) {
	if sshAuth == nil || e.rdpServer == nil {
		return
	}

	protoUsers := sshAuth.GetAuthorizedUsers()
	authorizedUsers := make([]sshuserhash.UserIDHash, len(protoUsers))
	for i, hash := range protoUsers {
		if len(hash) != 16 {
			log.Warnf("invalid hash length %d, expected 16 - skipping RDP server auth update", len(hash))
			return
		}
		authorizedUsers[i] = sshuserhash.UserIDHash(hash)
	}

	machineUsers := make(map[string][]uint32)
	for osUser, indexes := range sshAuth.GetMachineUsers() {
		machineUsers[osUser] = indexes.GetIndexes()
	}

	authConfig := &sshauth.Config{
		UserIDClaim:     sshAuth.GetUserIDClaim(),
		AuthorizedUsers: authorizedUsers,
		MachineUsers:    machineUsers,
	}

	e.rdpServer.UpdateRDPAuth(authConfig)
}
