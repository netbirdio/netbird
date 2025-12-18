package grpc

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	integrationsConfig "github.com/netbirdio/management-integrations/integrations/config"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/shared/management/proto"
	auth "github.com/netbirdio/netbird/shared/relay/auth/hmac"
	authv2 "github.com/netbirdio/netbird/shared/relay/auth/hmac/v2"
)

const defaultDuration = 12 * time.Hour

// SecretsManager used to manage TURN and relay secrets
type SecretsManager interface {
	GenerateTurnToken() (*Token, error)
	GenerateRelayToken() (*Token, error)
	SetupRefresh(ctx context.Context, accountID, peerKey string)
	CancelRefresh(peerKey string)
	GetWGKey() (wgtypes.Key, error)
}

// TimeBasedAuthSecretsManager generates credentials with TTL and using pre-shared secret known to TURN server
type TimeBasedAuthSecretsManager struct {
	mux             sync.Mutex
	turnCfg         *nbconfig.TURNConfig
	relayCfg        *nbconfig.Relay
	turnHmacToken   *auth.TimedHMAC
	relayHmacToken  *authv2.Generator
	updateManager   network_map.PeersUpdateManager
	settingsManager settings.Manager
	groupsManager   groups.Manager
	turnCancelMap   map[string]chan struct{}
	relayCancelMap  map[string]chan struct{}
	wgKey           wgtypes.Key
}

type Token auth.Token

func NewTimeBasedAuthSecretsManager(updateManager network_map.PeersUpdateManager, turnCfg *nbconfig.TURNConfig, relayCfg *nbconfig.Relay, settingsManager settings.Manager, groupsManager groups.Manager) (*TimeBasedAuthSecretsManager, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	mgr := &TimeBasedAuthSecretsManager{
		updateManager:   updateManager,
		turnCfg:         turnCfg,
		relayCfg:        relayCfg,
		turnCancelMap:   make(map[string]chan struct{}),
		relayCancelMap:  make(map[string]chan struct{}),
		settingsManager: settingsManager,
		groupsManager:   groupsManager,
		wgKey:           key,
	}

	if turnCfg != nil {
		duration := turnCfg.CredentialsTTL.Duration
		if turnCfg.CredentialsTTL.Duration <= 0 {
			log.Warnf("TURN credentials TTL is not set or invalid, using default value %s", defaultDuration)
			duration = defaultDuration
		}
		mgr.turnHmacToken = auth.NewTimedHMAC(turnCfg.Secret, duration)
	}

	if relayCfg != nil {
		duration := relayCfg.CredentialsTTL.Duration
		if relayCfg.CredentialsTTL.Duration <= 0 {
			log.Warnf("Relay credentials TTL is not set or invalid, using default value %s", defaultDuration)
			duration = defaultDuration
		}

		hashedSecret := sha256.Sum256([]byte(relayCfg.Secret))
		var err error
		if mgr.relayHmacToken, err = authv2.NewGenerator(authv2.AuthAlgoHMACSHA256, hashedSecret[:], duration); err != nil {
			log.Errorf("failed to create relay token generator: %s", err)
		}
	}

	return mgr, nil
}

// GetWGKey returns WireGuard private key used to generate peer keys
func (m *TimeBasedAuthSecretsManager) GetWGKey() (wgtypes.Key, error) {
	return m.wgKey, nil
}

// GenerateTurnToken generates new time-based secret credentials for TURN
func (m *TimeBasedAuthSecretsManager) GenerateTurnToken() (*Token, error) {
	if m.turnHmacToken == nil {
		return nil, fmt.Errorf("TURN configuration is not set")
	}
	turnToken, err := m.turnHmacToken.GenerateToken(sha1.New)
	if err != nil {
		return nil, fmt.Errorf("generate TURN token: %s", err)
	}
	return (*Token)(turnToken), nil
}

// GenerateRelayToken generates new time-based secret credentials for relay
func (m *TimeBasedAuthSecretsManager) GenerateRelayToken() (*Token, error) {
	if m.relayHmacToken == nil {
		return nil, fmt.Errorf("relay configuration is not set")
	}
	relayToken, err := m.relayHmacToken.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("generate relay token: %s", err)
	}

	return &Token{
		Payload:   string(relayToken.Payload),
		Signature: base64.StdEncoding.EncodeToString(relayToken.Signature),
	}, nil
}

func (m *TimeBasedAuthSecretsManager) cancelTURN(peerID string) {
	if channel, ok := m.turnCancelMap[peerID]; ok {
		close(channel)
		delete(m.turnCancelMap, peerID)
	}
}

func (m *TimeBasedAuthSecretsManager) cancelRelay(peerID string) {
	if channel, ok := m.relayCancelMap[peerID]; ok {
		close(channel)
		delete(m.relayCancelMap, peerID)
	}
}

// CancelRefresh cancels scheduled peer credentials refresh
func (m *TimeBasedAuthSecretsManager) CancelRefresh(peerID string) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.cancelTURN(peerID)
	m.cancelRelay(peerID)
}

// SetupRefresh starts peer credentials refresh
func (m *TimeBasedAuthSecretsManager) SetupRefresh(ctx context.Context, accountID, peerID string) {
	m.mux.Lock()
	defer m.mux.Unlock()

	m.cancelTURN(peerID)
	m.cancelRelay(peerID)

	if m.turnCfg != nil && m.turnCfg.TimeBasedCredentials {
		turnCancel := make(chan struct{}, 1)
		m.turnCancelMap[peerID] = turnCancel
		go m.refreshTURNTokens(ctx, accountID, peerID, turnCancel)
		log.WithContext(ctx).Debugf("starting TURN refresh for %s", peerID)
	}

	if m.relayCfg != nil {
		relayCancel := make(chan struct{}, 1)
		m.relayCancelMap[peerID] = relayCancel
		go m.refreshRelayTokens(ctx, accountID, peerID, relayCancel)
		log.WithContext(ctx).Tracef("starting relay refresh for %s", peerID)
	}
}

func (m *TimeBasedAuthSecretsManager) refreshTURNTokens(ctx context.Context, accountID, peerID string, cancel chan struct{}) {
	ticker := time.NewTicker(m.turnCfg.CredentialsTTL.Duration / 4 * 3)
	defer ticker.Stop()

	for {
		select {
		case <-cancel:
			log.WithContext(ctx).Tracef("stopping TURN refresh for %s", peerID)
			return
		case <-ticker.C:
			m.pushNewTURNAndRelayTokens(ctx, accountID, peerID)
		}
	}
}

func (m *TimeBasedAuthSecretsManager) refreshRelayTokens(ctx context.Context, accountID, peerID string, cancel chan struct{}) {
	ticker := time.NewTicker(m.relayCfg.CredentialsTTL.Duration / 4 * 3)
	defer ticker.Stop()

	for {
		select {
		case <-cancel:
			log.WithContext(ctx).Tracef("stopping relay refresh for %s", peerID)
			return
		case <-ticker.C:
			m.pushNewRelayTokens(ctx, accountID, peerID)
		}
	}
}

func (m *TimeBasedAuthSecretsManager) pushNewTURNAndRelayTokens(ctx context.Context, accountID, peerID string) {
	turnToken, err := m.turnHmacToken.GenerateToken(sha1.New)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to generate token for peer '%s': %s", peerID, err)
		return
	}

	var turns []*proto.ProtectedHostConfig
	for _, host := range m.turnCfg.Turns {
		turn := &proto.ProtectedHostConfig{
			HostConfig: &proto.HostConfig{
				Uri:      host.URI,
				Protocol: ToResponseProto(host.Proto),
			},
			User:     turnToken.Payload,
			Password: turnToken.Signature,
		}
		turns = append(turns, turn)
	}

	update := &proto.SyncResponse{
		NetbirdConfig: &proto.NetbirdConfig{
			Turns: turns,
		},
	}

	// workaround for the case when client is unable to handle turn and relay updates at different time
	if m.relayCfg != nil {
		token, err := m.GenerateRelayToken()
		if err == nil {
			update.NetbirdConfig.Relay = &proto.RelayConfig{
				Urls:           m.relayCfg.Addresses,
				TokenPayload:   token.Payload,
				TokenSignature: token.Signature,
			}
		}
	}

	m.extendNetbirdConfig(ctx, peerID, accountID, update)

	log.WithContext(ctx).Debugf("sending new TURN credentials to peer %s", peerID)
	m.updateManager.SendUpdate(ctx, peerID, &network_map.UpdateMessage{Update: update})
}

func (m *TimeBasedAuthSecretsManager) pushNewRelayTokens(ctx context.Context, accountID, peerID string) {
	relayToken, err := m.relayHmacToken.GenerateToken()
	if err != nil {
		log.Errorf("failed to generate relay token for peer '%s': %s", peerID, err)
		return
	}

	update := &proto.SyncResponse{
		NetbirdConfig: &proto.NetbirdConfig{
			Relay: &proto.RelayConfig{
				Urls:           m.relayCfg.Addresses,
				TokenPayload:   string(relayToken.Payload),
				TokenSignature: base64.StdEncoding.EncodeToString(relayToken.Signature),
			},
			// omit Turns to avoid updates there
		},
	}

	m.extendNetbirdConfig(ctx, peerID, accountID, update)

	log.WithContext(ctx).Debugf("sending new relay credentials to peer %s", peerID)
	m.updateManager.SendUpdate(ctx, peerID, &network_map.UpdateMessage{Update: update})
}

func (m *TimeBasedAuthSecretsManager) extendNetbirdConfig(ctx context.Context, peerID, accountID string, update *proto.SyncResponse) {
	extraSettings, err := m.settingsManager.GetExtraSettings(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get extra settings: %v", err)
	}

	peerGroups, err := m.groupsManager.GetPeerGroupIDs(ctx, accountID, peerID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get peer groups: %v", err)
	}

	extendedConfig := integrationsConfig.ExtendNetBirdConfig(peerID, peerGroups, update.NetbirdConfig, extraSettings)
	update.NetbirdConfig = extendedConfig
}
