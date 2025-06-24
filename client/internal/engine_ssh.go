package internal

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strings"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"

	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	sshconfig "github.com/netbirdio/netbird/client/ssh/config"
	sshserver "github.com/netbirdio/netbird/client/ssh/server"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

type sshServer interface {
	Start(ctx context.Context, addr netip.AddrPort) error
	Stop() error
	RemoveAuthorizedKey(peer string)
	AddAuthorizedKey(peer, newKey string) error
	SetSocketFilter(ifIdx int)
	SetupSSHClientConfigWithPeers(peerKeys []sshconfig.PeerHostKey) error
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

func (e *Engine) setupSSHSocketFilter(server sshServer) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	netInterface := e.wgInterface.ToInterface()
	if netInterface == nil {
		return errors.New("failed to get WireGuard network interface")
	}

	server.SetSocketFilter(netInterface.Index)
	log.Debugf("SSH socket filter configured for interface %s (index: %d)", netInterface.Name, netInterface.Index)

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

	return e.startSSHServer()
}

// updateSSHKnownHosts updates the SSH known_hosts file with peer host keys for OpenSSH client
func (e *Engine) updateSSHKnownHosts(remotePeers []*mgmProto.RemotePeerConfig) error {
	peerKeys := e.extractPeerHostKeys(remotePeers)
	if len(peerKeys) == 0 {
		log.Debug("no SSH-enabled peers found, skipping known_hosts update")
		return nil
	}

	if err := e.updateKnownHostsFile(peerKeys); err != nil {
		return err
	}

	e.updateSSHClientConfig(peerKeys)
	log.Debugf("updated SSH known_hosts with %d peer host keys", len(peerKeys))
	return nil
}

// extractPeerHostKeys extracts SSH host keys from peer configurations
func (e *Engine) extractPeerHostKeys(remotePeers []*mgmProto.RemotePeerConfig) []sshconfig.PeerHostKey {
	var peerKeys []sshconfig.PeerHostKey

	for _, peerConfig := range remotePeers {
		peerHostKey, ok := e.parsePeerHostKey(peerConfig)
		if ok {
			peerKeys = append(peerKeys, peerHostKey)
		}
	}

	return peerKeys
}

// parsePeerHostKey parses a single peer's SSH host key configuration
func (e *Engine) parsePeerHostKey(peerConfig *mgmProto.RemotePeerConfig) (sshconfig.PeerHostKey, bool) {
	if peerConfig.GetSshConfig() == nil {
		return sshconfig.PeerHostKey{}, false
	}

	sshPubKeyBytes := peerConfig.GetSshConfig().GetSshPubKey()
	if len(sshPubKeyBytes) == 0 {
		return sshconfig.PeerHostKey{}, false
	}

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(sshPubKeyBytes)
	if err != nil {
		log.Warnf("failed to parse SSH public key for peer %s: %v", peerConfig.GetWgPubKey(), err)
		return sshconfig.PeerHostKey{}, false
	}

	peerIP := e.extractPeerIP(peerConfig)
	hostname := e.extractHostname(peerConfig)

	return sshconfig.PeerHostKey{
		Hostname: hostname,
		IP:       peerIP,
		FQDN:     peerConfig.GetFqdn(),
		HostKey:  hostKey,
	}, true
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

// updateKnownHostsFile updates the SSH known_hosts file
func (e *Engine) updateKnownHostsFile(peerKeys []sshconfig.PeerHostKey) error {
	configMgr := sshconfig.NewManager()
	if err := configMgr.UpdatePeerHostKeys(peerKeys); err != nil {
		return fmt.Errorf("update peer host keys: %w", err)
	}
	return nil
}

// updateSSHClientConfig updates SSH client configuration with peer hostnames
func (e *Engine) updateSSHClientConfig(peerKeys []sshconfig.PeerHostKey) {
	if e.sshServer == nil {
		return
	}

	if err := e.sshServer.SetupSSHClientConfigWithPeers(peerKeys); err != nil {
		log.Warnf("failed to update SSH client config with peer hostnames: %v", err)
	} else {
		log.Debugf("updated SSH client config with %d peer hostnames", len(peerKeys))
	}
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

// cleanupSSHConfig removes NetBird SSH client configuration on shutdown
func (e *Engine) cleanupSSHConfig() {
	configMgr := sshconfig.NewManager()

	if err := configMgr.RemoveSSHClientConfig(); err != nil {
		log.Warnf("failed to remove SSH client config: %v", err)
	} else {
		log.Debugf("SSH client config cleanup completed")
	}

	if err := configMgr.RemoveKnownHostsFile(); err != nil {
		log.Warnf("failed to remove SSH known_hosts: %v", err)
	} else {
		log.Debugf("SSH known_hosts cleanup completed")
	}
}

// startSSHServer initializes and starts the SSH server with proper configuration.
func (e *Engine) startSSHServer() error {
	if e.wgInterface == nil {
		return errors.New("wg interface not initialized")
	}

	server := sshserver.New(e.config.SSHKey)

	wgAddr := e.wgInterface.Address()
	server.SetNetworkValidation(wgAddr)

	netbirdIP := wgAddr.IP
	listenAddr := netip.AddrPortFrom(netbirdIP, sshserver.InternalSSHPort)

	if netstackNet := e.wgInterface.GetNet(); netstackNet != nil {
		server.SetNetstackNet(netstackNet)

		if registrar, ok := e.firewall.(interface {
			RegisterNetstackService(protocol nftypes.Protocol, port uint16)
		}); ok {
			registrar.RegisterNetstackService(nftypes.TCP, sshserver.InternalSSHPort)
			log.Debugf("registered SSH service with netstack for TCP:%d", sshserver.InternalSSHPort)
		}
	}

	e.configureSSHServer(server)
	e.sshServer = server

	if err := e.setupSSHPortRedirection(); err != nil {
		log.Warnf("failed to setup SSH port redirection: %v", err)
	}

	if err := e.setupSSHSocketFilter(server); err != nil {
		return fmt.Errorf("set socket filter: %w", err)
	}

	if err := server.Start(e.ctx, listenAddr); err != nil {
		return fmt.Errorf("start SSH server: %w", err)
	}

	if err := server.SetupSSHClientConfig(); err != nil {
		log.Warnf("failed to setup SSH client config: %v", err)
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
