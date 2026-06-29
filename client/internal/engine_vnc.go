//go:build !js && !ios && !android

package internal

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	log "github.com/sirupsen/logrus"

	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/approval"
	"github.com/netbirdio/netbird/client/internal/metrics"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/vnc"
	vncserver "github.com/netbirdio/netbird/client/vnc/server"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	sshauth "github.com/netbirdio/netbird/shared/sessionauth"
	sshuserhash "github.com/netbirdio/netbird/shared/sshauth"
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

	if err := e.firewall.AddInboundDNAT(localAddr, firewallManager.ProtocolTCP, vnc.ExternalPort, vnc.InternalPort); err != nil {
		return fmt.Errorf("add VNC port redirection: %w", err)
	}
	log.Infof("VNC port redirection: %s:%d -> %s:%d", localAddr, vnc.ExternalPort, localAddr, vnc.InternalPort)

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

	if err := e.firewall.RemoveInboundDNAT(localAddr, firewallManager.ProtocolTCP, vnc.ExternalPort, vnc.InternalPort); err != nil {
		return fmt.Errorf("remove VNC port redirection: %w", err)
	}

	return nil
}

// updateVNC handles starting/stopping the VNC server based on the config flag.
func (e *Engine) updateVNC() error {
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
		return nil
	}

	return e.startVNCServer()
}

func (e *Engine) startVNCServer() error {
	if e.wgInterface == nil {
		return errors.New("wg interface not initialized")
	}

	capturer, injector, ok := newPlatformVNC()
	if !ok {
		log.Debug("VNC server not supported on this platform")
		return nil
	}

	netbirdIP := e.wgInterface.Address().IP

	var sessionRecorder func(vncserver.SessionTick)
	if e.clientMetrics != nil {
		sessionRecorder = func(t vncserver.SessionTick) {
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
		}
	}
	serviceMode := vncNeedsServiceMode()
	if serviceMode {
		log.Info("VNC: running as system service, enabling service mode (per-session agent proxy)")
	}
	requireApproval := e.config.DisableVNCApproval == nil || !*e.config.DisableVNCApproval
	srv := vncserver.New(vncserver.Config{
		Capturer:        capturer,
		Injector:        injector,
		IdentityKey:     e.config.WgPrivateKey[:],
		ServiceMode:     serviceMode,
		SessionRecorder: sessionRecorder,
		NetstackNet:     e.wgInterface.GetNet(),
		RequireApproval: requireApproval,
		Approver:        &vncApprover{broker: e.approvalBroker, statusRecorder: e.statusRecorder},
	})

	listenAddr := netip.AddrPortFrom(netbirdIP, vnc.InternalPort)
	network := e.wgInterface.Address().Network
	if err := srv.Start(e.ctx, listenAddr, network); err != nil {
		return fmt.Errorf("start VNC server: %w", err)
	}

	e.vncSrv = srv

	if netstackNet := e.wgInterface.GetNet(); netstackNet != nil {
		if registrar, ok := e.firewall.(interface {
			RegisterNetstackService(protocol nftypes.Protocol, port uint16)
		}); ok {
			registrar.RegisterNetstackService(nftypes.TCP, vnc.InternalPort)
			log.Debugf("registered VNC service with netstack for TCP:%d", vnc.InternalPort)
		}
	}

	if err := e.setupVNCPortRedirection(); err != nil {
		log.Warnf("setup VNC port redirection: %v", err)
	}

	log.Info("VNC server enabled")
	return nil
}

// updateVNCServerAuth updates VNC fine-grained access control from management.
// A nil vncAuth clears all authorized users and session pubkeys so management
// can revoke access by omitting the field on the next sync.
func (e *Engine) updateVNCServerAuth(vncAuth *mgmProto.VNCAuth) {
	if e.vncSrv == nil {
		return
	}

	vncSrv, ok := e.vncSrv.(*vncserver.Server)
	if !ok {
		return
	}

	if vncAuth == nil {
		vncSrv.UpdateVNCAuth(&sshauth.Config{})
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

	sessionPubKeys := make([]sshauth.SessionPubKey, 0, len(vncAuth.GetSessionPubKeys()))
	for _, pk := range vncAuth.GetSessionPubKeys() {
		pub := pk.GetPubKey()
		if len(pub) != 32 {
			log.Warnf("VNC session pubkey wrong length %d", len(pub))
			continue
		}
		hash := pk.GetUserIdHash()
		if len(hash) != 16 {
			log.Warnf("VNC session user id hash wrong length %d", len(hash))
			continue
		}
		sessionPubKeys = append(sessionPubKeys, sshauth.SessionPubKey{
			PubKey:      pub,
			UserIDHash:  sshuserhash.UserIDHash(hash),
			DisplayName: pk.GetDisplayName(),
		})
	}

	vncSrv.UpdateVNCAuth(&sshauth.Config{
		AuthorizedUsers: authorizedUsers,
		MachineUsers:    machineUsers,
		SessionPubKeys:  sessionPubKeys,
	})
}

// GetVNCServerStatus returns whether the VNC server is running and the list
// of active VNC sessions. The pointer is captured under syncMsgMux so a
// concurrent updateVNC/stopVNCServer cannot swap it out between the nil
// check and the ActiveSessions call.
func (e *Engine) GetVNCServerStatus() (enabled bool, sessions []vncserver.ActiveSessionInfo) {
	e.syncMsgMux.Lock()
	vncSrv := e.vncSrv
	e.syncMsgMux.Unlock()
	if vncSrv == nil {
		return false, nil
	}
	return true, vncSrv.ActiveSessions()
}

func (e *Engine) stopVNCServer() error {
	if e.vncSrv == nil {
		return nil
	}

	if err := e.cleanupVNCPortRedirection(); err != nil {
		log.Warnf("cleanup VNC port redirection: %v", err)
	}

	if e.wgInterface != nil && e.wgInterface.GetNet() != nil {
		if registrar, ok := e.firewall.(interface {
			UnregisterNetstackService(protocol nftypes.Protocol, port uint16)
		}); ok {
			registrar.UnregisterNetstackService(nftypes.TCP, vnc.InternalPort)
		}
	}

	log.Info("stopping VNC server")
	err := e.vncSrv.Stop()
	e.vncSrv = nil
	if err != nil {
		return fmt.Errorf("stop VNC server: %w", err)
	}
	return nil
}

// vncApprover adapts the generic approval.Broker for the VNC server.
type vncApprover struct {
	broker         *approval.Broker
	statusRecorder *peer.Status
}

func (a *vncApprover) Request(ctx context.Context, info vncserver.ApprovalInfo) (vncserver.ApprovalDecision, error) {
	// Resolve the source overlay IP to a peer FQDN for the prompt label.
	if info.PeerName == "" && info.SourceIP != "" && a.statusRecorder != nil {
		if fqdn, ok := a.statusRecorder.PeerByIP(info.SourceIP); ok {
			info.PeerName = fqdn
		}
	}
	subject := fmt.Sprintf("VNC connection from %s", displayPeer(info))
	meta := map[string]string{
		"peer_name":   info.PeerName,
		"peer_pubkey": info.PeerPubKey,
		"source_ip":   info.SourceIP,
		"mode":        info.Mode,
		"username":    info.Username,
		"initiator":   info.Initiator,
	}
	d, err := a.broker.Request(ctx, approval.Prompt{
		Kind:     approval.KindVNC,
		Subject:  subject,
		Metadata: meta,
	})
	if err != nil {
		return vncserver.ApprovalDecision{}, err
	}
	return vncserver.ApprovalDecision{ViewOnly: d.ViewOnly}, nil
}

func displayPeer(info vncserver.ApprovalInfo) string {
	if info.Initiator != "" {
		return info.Initiator
	}
	if info.PeerName != "" {
		return info.PeerName
	}
	if info.SourceIP != "" {
		return info.SourceIP
	}
	if info.PeerPubKey != "" {
		return info.PeerPubKey
	}
	return "unknown peer"
}
