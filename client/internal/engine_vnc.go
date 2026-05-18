//go:build !js && !ios && !android

package internal

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	log "github.com/sirupsen/logrus"

	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/metrics"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	sshauth "github.com/netbirdio/netbird/client/ssh/auth"
	vncserver "github.com/netbirdio/netbird/client/vnc/server"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	sshuserhash "github.com/netbirdio/netbird/shared/sshauth"
)

const (
	vncExternalPort uint16 = 5900
	vncInternalPort uint16 = 25900
)

type vncServer interface {
	Start(ctx context.Context, addr netip.AddrPort, network netip.Prefix) error
	Stop() error
	ActiveSessions() []vncserver.ActiveSessionInfo
}

func (e *Engine) setupVNCPortRedirection() error {
	if e.firewall == nil || e.wgInterface == nil {
		return nil
	}

	localAddr := e.wgInterface.Address().IP
	if !localAddr.IsValid() {
		return errors.New("invalid local NetBird address")
	}

	if err := e.firewall.AddInboundDNAT(localAddr, firewallManager.ProtocolTCP, vncExternalPort, vncInternalPort); err != nil {
		return fmt.Errorf("add VNC port redirection: %w", err)
	}
	log.Infof("VNC port redirection: %s:%d -> %s:%d", localAddr, vncExternalPort, localAddr, vncInternalPort)

	return nil
}

func (e *Engine) cleanupVNCPortRedirection() error {
	if e.firewall == nil || e.wgInterface == nil {
		return nil
	}

	localAddr := e.wgInterface.Address().IP
	if !localAddr.IsValid() {
		return errors.New("invalid local NetBird address")
	}

	if err := e.firewall.RemoveInboundDNAT(localAddr, firewallManager.ProtocolTCP, vncExternalPort, vncInternalPort); err != nil {
		return fmt.Errorf("remove VNC port redirection: %w", err)
	}

	return nil
}

// updateVNC handles starting/stopping the VNC server based on the config flag.
// sshConf provides the JWT identity provider config (shared with SSH).
func (e *Engine) updateVNC(sshConf *mgmProto.SSHConfig) error {
	if !e.config.ServerVNCAllowed {
		if e.vncSrv != nil {
			log.Info("VNC server disabled, stopping")
		}
		return e.stopVNCServer()
	}

	if e.config.BlockInbound {
		log.Info("VNC server disabled because inbound connections are blocked")
		return e.stopVNCServer()
	}

	if e.vncSrv != nil {
		// Update JWT config on existing server in case management sent new config.
		e.updateVNCServerJWT(sshConf)
		return nil
	}

	return e.startVNCServer(sshConf)
}

func (e *Engine) startVNCServer(sshConf *mgmProto.SSHConfig) error {
	if e.wgInterface == nil {
		return errors.New("wg interface not initialized")
	}

	capturer, injector, ok := newPlatformVNC()
	if !ok {
		log.Debug("VNC server not supported on this platform")
		return nil
	}

	netbirdIP := e.wgInterface.Address().IP

	srv := vncserver.New(capturer, injector)
	if e.clientMetrics != nil {
		srv.SetSessionRecorder(func(t vncserver.SessionTick) {
			e.clientMetrics.RecordVNCSessionTick(e.ctx, metrics.VNCSessionTick{
				Period:        t.Period,
				BytesOut:      t.BytesOut,
				Writes:        t.Writes,
				FBUs:          t.FBUs,
				MaxFBUBytes:   t.MaxFBUBytes,
				MaxFBURects:   t.MaxFBURects,
				MaxWriteBytes: t.MaxWriteBytes,
				WriteNanos:    t.WriteNanos,
			})
		})
	}
	if vncNeedsServiceMode() {
		log.Info("VNC: running in Session 0, enabling service mode (agent proxy)")
		srv.SetServiceMode(true)
	}

	if protoJWT := sshConf.GetJwtConfig(); protoJWT != nil {
		audiences := protoJWT.GetAudiences()
		if len(audiences) == 0 && protoJWT.GetAudience() != "" {
			audiences = []string{protoJWT.GetAudience()}
		}
		srv.SetJWTConfig(&vncserver.JWTConfig{
			Issuer:       protoJWT.GetIssuer(),
			Audiences:    audiences,
			KeysLocation: protoJWT.GetKeysLocation(),
			MaxTokenAge:  protoJWT.GetMaxTokenAge(),
		})
		log.Debugf("VNC: JWT authentication configured (issuer=%s)", protoJWT.GetIssuer())
	}

	if netstackNet := e.wgInterface.GetNet(); netstackNet != nil {
		srv.SetNetstackNet(netstackNet)
	}

	listenAddr := netip.AddrPortFrom(netbirdIP, vncInternalPort)
	network := e.wgInterface.Address().Network
	if err := srv.Start(e.ctx, listenAddr, network); err != nil {
		return fmt.Errorf("start VNC server: %w", err)
	}

	e.vncSrv = srv

	if registrar, ok := e.firewall.(interface {
		RegisterNetstackService(protocol nftypes.Protocol, port uint16)
	}); ok {
		registrar.RegisterNetstackService(nftypes.TCP, vncInternalPort)
		log.Debugf("registered VNC service for TCP:%d", vncInternalPort)
	}

	if err := e.setupVNCPortRedirection(); err != nil {
		log.Warnf("setup VNC port redirection: %v", err)
	}

	log.Info("VNC server enabled")
	return nil
}

// updateVNCServerJWT configures the JWT validation for the VNC server using
// the same JWT config as SSH (same identity provider).
func (e *Engine) updateVNCServerJWT(sshConf *mgmProto.SSHConfig) {
	if e.vncSrv == nil {
		return
	}

	vncSrv, ok := e.vncSrv.(*vncserver.Server)
	if !ok {
		return
	}

	protoJWT := sshConf.GetJwtConfig()
	if protoJWT == nil {
		return
	}

	audiences := protoJWT.GetAudiences()
	if len(audiences) == 0 && protoJWT.GetAudience() != "" {
		audiences = []string{protoJWT.GetAudience()}
	}

	vncSrv.SetJWTConfig(&vncserver.JWTConfig{
		Issuer:       protoJWT.GetIssuer(),
		Audiences:    audiences,
		KeysLocation: protoJWT.GetKeysLocation(),
		MaxTokenAge:  protoJWT.GetMaxTokenAge(),
	})
}

// updateVNCServerAuth updates VNC fine-grained access control from management.
func (e *Engine) updateVNCServerAuth(vncAuth *mgmProto.VNCAuth) {
	if vncAuth == nil || e.vncSrv == nil {
		return
	}

	vncSrv, ok := e.vncSrv.(*vncserver.Server)
	if !ok {
		return
	}

	protoUsers := vncAuth.GetAuthorizedUsers()
	authorizedUsers := make([]sshuserhash.UserIDHash, len(protoUsers))
	for i, hash := range protoUsers {
		if len(hash) != 16 {
			log.Warnf("invalid VNC auth hash length %d, expected 16", len(hash))
			return
		}
		authorizedUsers[i] = sshuserhash.UserIDHash(hash)
	}

	machineUsers := make(map[string][]uint32)
	for osUser, indexes := range vncAuth.GetMachineUsers() {
		machineUsers[osUser] = indexes.GetIndexes()
	}

	vncSrv.UpdateVNCAuth(&sshauth.Config{
		UserIDClaim:     vncAuth.GetUserIDClaim(),
		AuthorizedUsers: authorizedUsers,
		MachineUsers:    machineUsers,
	})
}

// GetVNCServerStatus returns whether the VNC server is running and the list
// of active VNC sessions.
func (e *Engine) GetVNCServerStatus() (enabled bool, sessions []vncserver.ActiveSessionInfo) {
	if e.vncSrv == nil {
		return false, nil
	}
	return true, e.vncSrv.ActiveSessions()
}

func (e *Engine) stopVNCServer() error {
	if e.vncSrv == nil {
		return nil
	}

	if err := e.cleanupVNCPortRedirection(); err != nil {
		log.Warnf("cleanup VNC port redirection: %v", err)
	}

	if registrar, ok := e.firewall.(interface {
		UnregisterNetstackService(protocol nftypes.Protocol, port uint16)
	}); ok {
		registrar.UnregisterNetstackService(nftypes.TCP, vncInternalPort)
	}

	log.Info("stopping VNC server")
	err := e.vncSrv.Stop()
	e.vncSrv = nil
	if err != nil {
		return fmt.Errorf("stop VNC server: %w", err)
	}
	return nil
}
