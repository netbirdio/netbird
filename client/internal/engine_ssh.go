package internal

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	log "github.com/sirupsen/logrus"

	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface/netstack"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	sshauth "github.com/netbirdio/netbird/client/ssh/auth"
	sshconfig "github.com/netbirdio/netbird/client/ssh/config"
	sshserver "github.com/netbirdio/netbird/client/ssh/server"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	sshuserhash "github.com/netbirdio/netbird/shared/sshauth"
)

type sshServer interface {
	Start(ctx context.Context, addr netip.AddrPort) error
	Stop() error
	GetStatus() (bool, []sshserver.SessionInfo)
	UpdateSSHAuth(config *sshauth.Config)
}

func (e *Engine) setupSSHPortRedirection() error {
	if e.firewall == nil || e.wgInterface == nil {
		return nil
	}

	localAddr := e.wgInterface.Address().IP
	if !localAddr.IsValid() {
		return errors.New("invalid local NetBird address")
	}

	if err := e.firewall.AddInboundDNAT(localAddr, firewallManager.ProtocolTCP, 22, 22022); err != nil {
		return fmt.Errorf("add SSH port redirection: %w", err)
	}
	log.Infof("SSH port redirection enabled: %s:22 -> %s:22022", localAddr, localAddr)

	return nil
}

func (e *Engine) updateSSH(sshConf *mgmProto.SSHConfig) error {
	if e.config.BlockInbound {
		log.Info("SSH server is disabled because inbound connections are blocked")
		return e.stopSSHServer()
	}

	if !e.config.ServerSSHAllowed {
		log.Info("SSH server is disabled in config")
		return e.stopSSHServer()
	}

	if !sshConf.GetSshEnabled() {
		if e.config.ServerSSHAllowed {
			log.Info("SSH server is locally allowed but disabled by management server")
		}
		return e.stopSSHServer()
	}

	if e.sshServer != nil {
		log.Debug("SSH server is already running")
		return nil
	}

	if e.config.DisableSSHAuth != nil && *e.config.DisableSSHAuth {
		log.Info("starting SSH server without JWT authentication (authentication disabled by config)")
		return e.startSSHServer(nil)
	}

	if protoJWT := sshConf.GetJwtConfig(); protoJWT != nil {
		audiences := protoJWT.GetAudiences()
		if len(audiences) == 0 && protoJWT.GetAudience() != "" {
			audiences = []string{protoJWT.GetAudience()}
		}

		log.Debugf("starting SSH server with JWT authentication: audiences=%v", audiences)

		jwtConfig := &sshserver.JWTConfig{
			Issuer:       protoJWT.GetIssuer(),
			Audiences:    audiences,
			KeysLocation: protoJWT.GetKeysLocation(),
			MaxTokenAge:  protoJWT.GetMaxTokenAge(),
		}

		return e.startSSHServer(jwtConfig)
	}

	return errors.New("SSH server requires valid JWT configuration")
}

// updateSSHClientConfig updates the SSH client configuration with peer information
func (e *Engine) updateSSHClientConfig(remotePeers []*mgmProto.RemotePeerConfig) error {
	if netstack.IsEnabled() {
		return nil
	}

	peerInfo := e.extractPeerSSHInfo(remotePeers)
	if len(peerInfo) == 0 {
		log.Debug("no SSH-enabled peers found, skipping SSH config update")
		return nil
	}

	configMgr := sshconfig.New()
	if err := configMgr.SetupSSHClientConfig(peerInfo); err != nil {
		log.Warnf("failed to update SSH client config: %v", err)
		return nil // Don't fail engine startup on SSH config issues
	}

	log.Debugf("updated SSH client config with %d peers", len(peerInfo))

	if err := e.stateManager.UpdateState(&sshconfig.ShutdownState{
		SSHConfigDir:  configMgr.GetSSHConfigDir(),
		SSHConfigFile: configMgr.GetSSHConfigFile(),
	}); err != nil {
		log.Warnf("failed to update SSH config state: %v", err)
	}

	return nil
}

// extractPeerSSHInfo extracts SSH information from peer configurations
func (e *Engine) extractPeerSSHInfo(remotePeers []*mgmProto.RemotePeerConfig) []sshconfig.PeerSSHInfo {
	var peerInfo []sshconfig.PeerSSHInfo

	for _, peerConfig := range remotePeers {
		if peerConfig.GetSshConfig() == nil {
			continue
		}

		sshPubKeyBytes := peerConfig.GetSshConfig().GetSshPubKey()
		if len(sshPubKeyBytes) == 0 {
			continue
		}

		peerIP := e.extractPeerIP(peerConfig)
		hostname := e.extractHostname(peerConfig)

		peerInfo = append(peerInfo, sshconfig.PeerSSHInfo{
			Hostname: hostname,
			IP:       peerIP,
			FQDN:     peerConfig.GetFqdn(),
		})
	}

	return peerInfo
}

// extractPeerIP extracts IP address from peer's allowed IPs
func (e *Engine) extractPeerIP(peerConfig *mgmProto.RemotePeerConfig) string {
	if len(peerConfig.GetAllowedIps()) == 0 {
		return ""
	}

	if prefix, err := netip.ParsePrefix(peerConfig.GetAllowedIps()[0]); err == nil {
		return prefix.Addr().String()
	}
	return ""
}

// extractHostname extracts short hostname from FQDN
func (e *Engine) extractHostname(peerConfig *mgmProto.RemotePeerConfig) string {
	fqdn := peerConfig.GetFqdn()
	if fqdn == "" {
		return ""
	}

	parts := strings.Split(fqdn, ".")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

// updatePeerSSHHostKeys updates peer SSH host keys in the status recorder for daemon API access
func (e *Engine) updatePeerSSHHostKeys(remotePeers []*mgmProto.RemotePeerConfig) {
	for _, peerConfig := range remotePeers {
		if peerConfig.GetSshConfig() == nil {
			continue
		}

		sshPubKeyBytes := peerConfig.GetSshConfig().GetSshPubKey()
		if len(sshPubKeyBytes) == 0 {
			continue
		}

		if err := e.statusRecorder.UpdatePeerSSHHostKey(peerConfig.GetWgPubKey(), sshPubKeyBytes); err != nil {
			log.Warnf("failed to update SSH host key for peer %s: %v", peerConfig.GetWgPubKey(), err)
		}
	}

	log.Debugf("updated peer SSH host keys for daemon API access")
}

// GetPeerSSHKey returns the SSH host key for a specific peer by IP or FQDN
func (e *Engine) GetPeerSSHKey(peerAddress string) ([]byte, bool) {
	e.syncMsgMux.Lock()
	statusRecorder := e.statusRecorder
	e.syncMsgMux.Unlock()

	if statusRecorder == nil {
		return nil, false
	}

	fullStatus := statusRecorder.GetFullStatus()
	for _, peerState := range fullStatus.Peers {
		if peerState.IP == peerAddress || peerState.FQDN == peerAddress {
			if len(peerState.SSHHostKey) > 0 {
				return peerState.SSHHostKey, true
			}
			return nil, false
		}
	}

	return nil, false
}

// cleanupSSHConfig removes NetBird SSH client configuration on shutdown
func (e *Engine) cleanupSSHConfig() {
	if netstack.IsEnabled() {
		return
	}

	configMgr := sshconfig.New()

	if err := configMgr.RemoveSSHClientConfig(); err != nil {
		log.Warnf("failed to remove SSH client config: %v", err)
	} else {
		log.Debugf("SSH client config cleanup completed")
	}
}

// startSSHServer initializes and starts the SSH server with proper configuration.
func (e *Engine) startSSHServer(jwtConfig *sshserver.JWTConfig) error {
	if e.wgInterface == nil {
		return errors.New("wg interface not initialized")
	}

	serverConfig := &sshserver.Config{
		HostKeyPEM: e.config.SSHKey,
		JWT:        jwtConfig,
	}
	server := sshserver.New(serverConfig)

	wgAddr := e.wgInterface.Address()
	server.SetNetworkValidation(wgAddr)

	netbirdIP := wgAddr.IP
	listenAddr := netip.AddrPortFrom(netbirdIP, sshserver.InternalSSHPort)

	if netstackNet := e.wgInterface.GetNet(); netstackNet != nil {
		server.SetNetstackNet(netstackNet)
	}

	e.configureSSHServer(server)

	if err := server.Start(e.ctx, listenAddr); err != nil {
		return fmt.Errorf("start SSH server: %w", err)
	}

	e.sshServer = server

	if netstackNet := e.wgInterface.GetNet(); netstackNet != nil {
		if registrar, ok := e.firewall.(interface {
			RegisterNetstackService(protocol nftypes.Protocol, port uint16)
		}); ok {
			registrar.RegisterNetstackService(nftypes.TCP, sshserver.InternalSSHPort)
			log.Debugf("registered SSH service with netstack for TCP:%d", sshserver.InternalSSHPort)
		}
	}

	if err := e.setupSSHPortRedirection(); err != nil {
		log.Warnf("failed to setup SSH port redirection: %v", err)
	}

	return nil
}

// configureSSHServer applies SSH configuration options to the server.
func (e *Engine) configureSSHServer(server *sshserver.Server) {
	if e.config.EnableSSHRoot != nil && *e.config.EnableSSHRoot {
		server.SetAllowRootLogin(true)
		log.Info("SSH root login enabled")
	} else {
		server.SetAllowRootLogin(false)
		log.Info("SSH root login disabled (default)")
	}

	if e.config.EnableSSHSFTP != nil && *e.config.EnableSSHSFTP {
		server.SetAllowSFTP(true)
		log.Info("SSH SFTP subsystem enabled")
	} else {
		server.SetAllowSFTP(false)
		log.Info("SSH SFTP subsystem disabled (default)")
	}

	if e.config.EnableSSHLocalPortForwarding != nil && *e.config.EnableSSHLocalPortForwarding {
		server.SetAllowLocalPortForwarding(true)
		log.Info("SSH local port forwarding enabled")
	} else {
		server.SetAllowLocalPortForwarding(false)
		log.Info("SSH local port forwarding disabled (default)")
	}

	if e.config.EnableSSHRemotePortForwarding != nil && *e.config.EnableSSHRemotePortForwarding {
		server.SetAllowRemotePortForwarding(true)
		log.Info("SSH remote port forwarding enabled")
	} else {
		server.SetAllowRemotePortForwarding(false)
		log.Info("SSH remote port forwarding disabled (default)")
	}
}

func (e *Engine) cleanupSSHPortRedirection() error {
	if e.firewall == nil || e.wgInterface == nil {
		return nil
	}

	localAddr := e.wgInterface.Address().IP
	if !localAddr.IsValid() {
		return errors.New("invalid local NetBird address")
	}

	if err := e.firewall.RemoveInboundDNAT(localAddr, firewallManager.ProtocolTCP, 22, 22022); err != nil {
		return fmt.Errorf("remove SSH port redirection: %w", err)
	}
	log.Debugf("SSH port redirection removed: %s:22 -> %s:22022", localAddr, localAddr)

	return nil
}

func (e *Engine) stopSSHServer() error {
	if e.sshServer == nil {
		return nil
	}

	if err := e.cleanupSSHPortRedirection(); err != nil {
		log.Warnf("failed to cleanup SSH port redirection: %v", err)
	}

	if netstackNet := e.wgInterface.GetNet(); netstackNet != nil {
		if registrar, ok := e.firewall.(interface {
			UnregisterNetstackService(protocol nftypes.Protocol, port uint16)
		}); ok {
			registrar.UnregisterNetstackService(nftypes.TCP, sshserver.InternalSSHPort)
			log.Debugf("unregistered SSH service from netstack for TCP:%d", sshserver.InternalSSHPort)
		}
	}

	log.Info("stopping SSH server")
	err := e.sshServer.Stop()
	e.sshServer = nil
	if err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	return nil
}

// GetSSHServerStatus returns the SSH server status and active sessions
func (e *Engine) GetSSHServerStatus() (enabled bool, sessions []sshserver.SessionInfo) {
	e.syncMsgMux.Lock()
	sshServer := e.sshServer
	e.syncMsgMux.Unlock()

	if sshServer == nil {
		return false, nil
	}

	return sshServer.GetStatus()
}

// updateSSHServerAuth updates SSH fine-grained access control configuration on a running SSH server
func (e *Engine) updateSSHServerAuth(sshAuth *mgmProto.SSHAuth) {
	if sshAuth == nil {
		return
	}

	if e.sshServer == nil {
		return
	}

	protoUsers := sshAuth.GetAuthorizedUsers()
	authorizedUsers := make([]sshuserhash.UserIDHash, len(protoUsers))
	for i, hash := range protoUsers {
		if len(hash) != 16 {
			log.Warnf("invalid hash length %d, expected 16 - skipping SSH server auth update", len(hash))
			return
		}
		authorizedUsers[i] = sshuserhash.UserIDHash(hash)
	}

	machineUsers := make(map[string][]uint32)
	for osUser, indexes := range sshAuth.GetMachineUsers() {
		machineUsers[osUser] = indexes.GetIndexes()
	}

	// Update SSH server with new authorization configuration
	authConfig := &sshauth.Config{
		UserIDClaim:     sshAuth.GetUserIDClaim(),
		AuthorizedUsers: authorizedUsers,
		MachineUsers:    machineUsers,
	}

	e.sshServer.UpdateSSHAuth(authConfig)
}
