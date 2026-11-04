package grpc

import (
	"context"
	"crypto/ed25519"
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
	"github.com/netbirdio/netbird/shared/peerauth"
	auth "github.com/netbirdio/netbird/shared/relay/auth/hmac"
	authv2 "github.com/netbirdio/netbird/shared/relay/auth/hmac/v2"
)

const defaultDuration = 12 * time.Hour

// SecretsManager used to manage TURN and relay secrets
//
//go:generate go tool mockgen -source=./token_mgr.go -destination=./token_mgr_mock.go -package=grpc
type SecretsManager interface {
	GenerateTurnToken() (*Token, error)
	GenerateRelayToken() (*Token, error)
	GenerateAuthToken(keys PeerAuthKeys) ([]byte, error)
	SetupRefresh(ctx context.Context, accountID, peerKey string, keys PeerAuthKeys)
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
	peerAuthCfg     nbconfig.PeerAuth
	peerAuth        *peerAuthIssuer
}

type Token auth.Token

// PeerAuthKeys are the peer keys, as stored on the peer, the auth token is bound to.
type PeerAuthKeys struct {
	WGPubKey   string
	AuthPubKey string
}

// SecretsManagerOption configures optional TimeBasedAuthSecretsManager behavior.
type SecretsManagerOption func(*TimeBasedAuthSecretsManager)

// WithPeerAuth sets the configuration of the tokens bound to the peer keys.
func WithPeerAuth(cfg nbconfig.PeerAuth) SecretsManagerOption {
	return func(m *TimeBasedAuthSecretsManager) { m.peerAuthCfg = cfg }
}

// peerAuthIssuer signs the tokens bound to the peer keys with Management's Ed25519 key.
type peerAuthIssuer struct {
	signingKey ed25519.PrivateKey
	ttl        time.Duration
}

func NewTimeBasedAuthSecretsManager(updateManager network_map.PeersUpdateManager, turnCfg *nbconfig.TURNConfig, relayCfg *nbconfig.Relay, settingsManager settings.Manager, groupsManager groups.Manager, opts ...SecretsManagerOption) (*TimeBasedAuthSecretsManager, error) {
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
	for _, opt := range opts {
		opt(mgr)
	}

	if mgr.peerAuth, err = newPeerAuthIssuer(mgr.peerAuthCfg, relayCfg); err != nil {
		return nil, err
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

// GenerateAuthToken returns the token bound to the peer keys, or nil when the bound token is
// disabled or the peer sent no auth key: such a peer keeps the legacy relay token.
func (m *TimeBasedAuthSecretsManager) GenerateAuthToken(keys PeerAuthKeys) ([]byte, error) {
	if m.peerAuth == nil || keys.AuthPubKey == "" {
		return nil, nil
	}
	return m.peerAuth.issue(keys)
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
func (m *TimeBasedAuthSecretsManager) SetupRefresh(ctx context.Context, accountID, peerID string, keys PeerAuthKeys) {
	m.mux.Lock()
	defer m.mux.Unlock()

	m.cancelTURN(peerID)
	m.cancelRelay(peerID)

	if m.turnCfg != nil && m.turnCfg.TimeBasedCredentials {
		turnCancel := make(chan struct{}, 1)
		m.turnCancelMap[peerID] = turnCancel
		go m.refreshTURNTokens(ctx, accountID, peerID, keys, turnCancel)
		log.WithContext(ctx).Debugf("starting TURN refresh for %s", peerID)
	} else {
		log.WithContext(ctx).Debugf("no TURN configuration, skipping TURN refresh for %s", peerID)
	}

	switch {
	case m.relayCfg != nil:
		relayCancel := make(chan struct{}, 1)
		m.relayCancelMap[peerID] = relayCancel
		go m.refreshRelayTokens(ctx, accountID, peerID, keys, relayCancel)
		log.WithContext(ctx).Tracef("starting relay refresh for %s", peerID)
	case m.peerAuth != nil && keys.AuthPubKey != "":
		authCancel := make(chan struct{}, 1)
		m.relayCancelMap[peerID] = authCancel
		go m.refreshAuthTokens(ctx, accountID, peerID, keys, authCancel)
		log.WithContext(ctx).Tracef("no relay configuration, starting auth token refresh for %s", peerID)
	default:
		log.WithContext(ctx).Tracef("no relay configuration, skipping relay refresh for %s", peerID)
	}
}

func (m *TimeBasedAuthSecretsManager) refreshTURNTokens(ctx context.Context, accountID, peerID string, keys PeerAuthKeys, cancel chan struct{}) {
	ticker := time.NewTicker(m.turnCfg.CredentialsTTL.Duration / 4 * 3)
	defer ticker.Stop()

	for {
		select {
		case <-cancel:
			log.WithContext(ctx).Tracef("stopping TURN refresh for %s", peerID)
			return
		case <-ticker.C:
			m.pushNewTURNAndRelayTokens(ctx, accountID, peerID, keys)
		}
	}
}

func (m *TimeBasedAuthSecretsManager) refreshRelayTokens(ctx context.Context, accountID, peerID string, keys PeerAuthKeys, cancel chan struct{}) {
	ticker := time.NewTicker(m.relayCfg.CredentialsTTL.Duration / 4 * 3)
	defer ticker.Stop()

	for {
		select {
		case <-cancel:
			log.WithContext(ctx).Tracef("stopping relay refresh for %s", peerID)
			return
		case <-ticker.C:
			m.pushNewRelayTokens(ctx, accountID, peerID, keys)
		}
	}
}

// refreshAuthTokens renews the auth token Signal verifies when there is no Relay config, whose
// refresh would otherwise carry it.
func (m *TimeBasedAuthSecretsManager) refreshAuthTokens(ctx context.Context, accountID, peerID string, keys PeerAuthKeys, cancel chan struct{}) {
	ticker := time.NewTicker(m.peerAuth.ttl / 4 * 3)
	defer ticker.Stop()

	for {
		select {
		case <-cancel:
			log.WithContext(ctx).Tracef("stopping auth token refresh for %s", peerID)
			return
		case <-ticker.C:
			m.pushNewAuthToken(ctx, accountID, peerID, keys)
		}
	}
}

func (m *TimeBasedAuthSecretsManager) pushNewAuthToken(ctx context.Context, accountID, peerID string, keys PeerAuthKeys) {
	authToken := m.authTokenOrLog(ctx, peerID, keys)
	if authToken == nil {
		return
	}
	update := &proto.SyncResponse{NetbirdConfig: &proto.NetbirdConfig{}}
	m.extendNetbirdConfig(ctx, peerID, accountID, update)
	setAuthToken(update.NetbirdConfig, authToken)

	log.WithContext(ctx).Debugf("sending new auth token to peer %s", peerID)
	m.updateManager.SendUpdate(ctx, peerID, &network_map.UpdateMessage{
		Update:      update,
		MessageType: network_map.MessageTypeControlConfig,
	})
}

func (m *TimeBasedAuthSecretsManager) pushNewTURNAndRelayTokens(ctx context.Context, accountID, peerID string, keys PeerAuthKeys) {
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
	authToken := m.authTokenOrLog(ctx, peerID, keys)
	if m.relayCfg != nil {
		update.NetbirdConfig.Relay = &proto.RelayConfig{Urls: m.relayCfg.Addresses}
		if authToken == nil {
			token, err := m.GenerateRelayToken()
			if err != nil {
				update.NetbirdConfig.Relay = nil
			} else {
				update.NetbirdConfig.Relay.TokenPayload = token.Payload
				update.NetbirdConfig.Relay.TokenSignature = token.Signature
			}
		}
	}

	m.extendNetbirdConfig(ctx, peerID, accountID, update)
	setAuthToken(update.NetbirdConfig, authToken)

	log.WithContext(ctx).Debugf("sending new TURN credentials to peer %s", peerID)
	m.updateManager.SendUpdate(ctx, peerID, &network_map.UpdateMessage{
		Update:      update,
		MessageType: network_map.MessageTypeControlConfig,
	})
}

func (m *TimeBasedAuthSecretsManager) pushNewRelayTokens(ctx context.Context, accountID, peerID string, keys PeerAuthKeys) {
	update := &proto.SyncResponse{
		NetbirdConfig: &proto.NetbirdConfig{
			Relay: &proto.RelayConfig{Urls: m.relayCfg.Addresses},
			// omit Turns to avoid updates there
		},
	}

	authToken := m.authTokenOrLog(ctx, peerID, keys)
	if authToken == nil {
		relayToken, err := m.relayHmacToken.GenerateToken()
		if err != nil {
			log.Errorf("failed to generate relay token for peer '%s': %s", peerID, err)
			return
		}
		update.NetbirdConfig.Relay.TokenPayload = string(relayToken.Payload)
		update.NetbirdConfig.Relay.TokenSignature = base64.StdEncoding.EncodeToString(relayToken.Signature)
	}

	m.extendNetbirdConfig(ctx, peerID, accountID, update)
	setAuthToken(update.NetbirdConfig, authToken)

	log.WithContext(ctx).Debugf("sending new relay credentials to peer %s", peerID)
	m.updateManager.SendUpdate(ctx, peerID, &network_map.UpdateMessage{
		Update:      update,
		MessageType: network_map.MessageTypeControlConfig,
	})
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

// authTokenOrLog returns the peer's auth token, or nil to fall back to the legacy relay token.
func (m *TimeBasedAuthSecretsManager) authTokenOrLog(ctx context.Context, peerID string, keys PeerAuthKeys) []byte {
	token, err := m.GenerateAuthToken(keys)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to generate auth token for peer '%s': %v", peerID, err)
		return nil
	}
	return token
}

func newPeerAuthIssuer(cfg nbconfig.PeerAuth, relayCfg *nbconfig.Relay) (*peerAuthIssuer, error) {
	if cfg.SigningKeyFile == "" {
		return nil, nil //nolint:nilnil // no signing key: peers keep the legacy relay token
	}
	signingKey, err := peerauth.LoadSigningKeyFile(cfg.SigningKeyFile)
	if err != nil {
		return nil, err
	}
	pub := signingKey.Public().(ed25519.PublicKey)
	log.Infof("peer auth signing key id %d, public key %s", peerauth.Ed25519KeyID(pub), base64.StdEncoding.EncodeToString(pub))

	ttl := defaultDuration
	if relayCfg != nil && relayCfg.CredentialsTTL.Duration > 0 {
		ttl = relayCfg.CredentialsTTL.Duration
	}
	return &peerAuthIssuer{signingKey: signingKey, ttl: ttl}, nil
}

func (i *peerAuthIssuer) issue(keys PeerAuthKeys) ([]byte, error) {
	wgPub, err := wgtypes.ParseKey(keys.WGPubKey)
	if err != nil {
		return nil, fmt.Errorf("parse WireGuard key: %w", err)
	}
	authPub, err := base64.StdEncoding.DecodeString(keys.AuthPubKey)
	if err != nil {
		return nil, fmt.Errorf("decode auth key: %w", err)
	}
	if len(authPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("auth key size %d", len(authPub))
	}
	return peerauth.IssueEd25519Token(i.signingKey, peerauth.Token{
		Expiry:  time.Now().Add(i.ttl),
		WGPub:   wgPub,
		AuthPub: authPub,
	})
}

// setAuthToken puts the auth token in the config after any extension, so it cannot be dropped.
func setAuthToken(cfg *proto.NetbirdConfig, token []byte) {
	if cfg == nil || token == nil {
		return
	}
	cfg.AuthToken = token
}
