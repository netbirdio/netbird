package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/proto"
	auth "github.com/netbirdio/netbird/relay/auth/hmac"
)

// TURNRelayTokenManager used to manage TURN credentials
type TURNRelayTokenManager interface {
	Generate() (*TURNRelayToken, error)
	SetupRefresh(ctx context.Context, peerKey string)
	CancelRefresh(peerKey string)
}

// TimeBasedAuthSecretsManager generates credentials with TTL and using pre-shared secret known to TURN server
type TimeBasedAuthSecretsManager struct {
	mux           sync.Mutex
	turnCfg       *TURNConfig
	relayAddr     string
	hmacToken     *auth.TimedHMAC
	updateManager *PeersUpdateManager
	cancelMap     map[string]chan struct{}
}

type TURNRelayToken auth.Token

func NewTimeBasedAuthSecretsManager(updateManager *PeersUpdateManager, turnCfg *TURNConfig, relayConfig *Relay) *TimeBasedAuthSecretsManager {

	var relayAddr string
	if relayConfig != nil {
		relayAddr = relayConfig.Address
	}
	return &TimeBasedAuthSecretsManager{
		mux:           sync.Mutex{},
		updateManager: updateManager,
		turnCfg:       turnCfg,
		relayAddr:     relayAddr,
		hmacToken:     auth.NewTimedHMAC(turnCfg.Secret, turnCfg.CredentialsTTL.Duration),
		cancelMap:     make(map[string]chan struct{}),
	}
}

// Generate generates new time-based secret credentials - basically username is a unix timestamp and password is a HMAC hash of a timestamp with a preshared TURN secret
func (m *TimeBasedAuthSecretsManager) Generate() (*TURNRelayToken, error) {
	token, err := m.hmacToken.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %s", err)
	}

	return (*TURNRelayToken)(token), nil
}

func (m *TimeBasedAuthSecretsManager) cancel(peerID string) {
	if channel, ok := m.cancelMap[peerID]; ok {
		close(channel)
		delete(m.cancelMap, peerID)
	}
}

// CancelRefresh cancels scheduled peer credentials refresh
func (m *TimeBasedAuthSecretsManager) CancelRefresh(peerID string) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.cancel(peerID)
}

// SetupRefresh starts peer credentials refresh. Since credentials are expiring (TTL) it is necessary to always generate them and send to the peer.
// A goroutine is created and put into TimeBasedAuthSecretsManager.cancelMap. This routine should be cancelled if peer is gone.
func (m *TimeBasedAuthSecretsManager) SetupRefresh(ctx context.Context, peerID string) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.cancel(peerID)
	cancel := make(chan struct{}, 1)
	m.cancelMap[peerID] = cancel
	log.WithContext(ctx).Debugf("starting turn refresh for %s", peerID)

	go func() {
		// we don't want to regenerate credentials right on expiration, so we do it slightly before (at 3/4 of TTL)
		ticker := time.NewTicker(m.turnCfg.CredentialsTTL.Duration / 4 * 3)
		defer ticker.Stop()

		for {
			select {
			case <-cancel:
				log.WithContext(ctx).Debugf("stopping turn refresh for %s", peerID)
				return
			case <-ticker.C:
				m.pushNewTokens(ctx, peerID)
			}
		}
	}()
}

func (m *TimeBasedAuthSecretsManager) pushNewTokens(ctx context.Context, peerID string) {
	token, err := m.hmacToken.GenerateToken()
	if err != nil {
		log.Errorf("failed to generate token for peer '%s': %s", peerID, err)
		return
	}

	var turns []*proto.ProtectedHostConfig
	for _, host := range m.turnCfg.Turns {
		turns = append(turns, &proto.ProtectedHostConfig{
			HostConfig: &proto.HostConfig{
				Uri:      host.URI,
				Protocol: ToResponseProto(host.Proto),
			},
			User:     token.Payload,
			Password: token.Signature,
		})
	}

	update := &proto.SyncResponse{
		WiretrusteeConfig: &proto.WiretrusteeConfig{
			Turns: turns,
			Relay: &proto.RelayConfig{
				Urls:           []string{m.relayAddr},
				TokenPayload:   token.Payload,
				TokenSignature: token.Signature,
			},
		},
	}
	log.WithContext(ctx).Debugf("sending new TURN credentials to peer %s", peerID)
	m.updateManager.SendUpdate(ctx, peerID, &UpdateMessage{Update: update})
}
