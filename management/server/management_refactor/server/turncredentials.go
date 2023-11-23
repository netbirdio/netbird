package server

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/proto"
)

// TURNCredentialsManager used to manage TURN credentials
type TURNCredentialsManager interface {
	GenerateCredentials() TURNCredentials
	SetupRefresh(peerKey string)
	CancelRefresh(peerKey string)
}

// TimeBasedAuthSecretsManager generates credentials with TTL and using pre-shared secret known to TURN server
type TimeBasedAuthSecretsManager struct {
	mux           sync.Mutex
	config        *TURNConfig
	updateManager *PeersUpdateManager
	cancelMap     map[string]chan struct{}
}

type TURNCredentials struct {
	Username string
	Password string
}

func NewTimeBasedAuthSecretsManager(updateManager *PeersUpdateManager, config *TURNConfig) *TimeBasedAuthSecretsManager {
	return &TimeBasedAuthSecretsManager{
		mux:           sync.Mutex{},
		config:        config,
		updateManager: updateManager,
		cancelMap:     make(map[string]chan struct{}),
	}
}

// GenerateCredentials generates new time-based secret credentials - basically username is a unix timestamp and password is a HMAC hash of a timestamp with a preshared TURN secret
func (m *TimeBasedAuthSecretsManager) GenerateCredentials() TURNCredentials {
	mac := hmac.New(sha1.New, []byte(m.config.Secret))

	timeAuth := time.Now().Add(m.config.CredentialsTTL.Duration).Unix()

	username := fmt.Sprint(timeAuth)

	_, err := mac.Write([]byte(username))
	if err != nil {
		log.Errorln("Generating turn password failed with error: ", err)
	}

	bytePassword := mac.Sum(nil)
	password := base64.StdEncoding.EncodeToString(bytePassword)

	return TURNCredentials{
		Username: username,
		Password: password,
	}

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
func (m *TimeBasedAuthSecretsManager) SetupRefresh(peerID string) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.cancel(peerID)
	cancel := make(chan struct{}, 1)
	m.cancelMap[peerID] = cancel
	log.Debugf("starting turn refresh for %s", peerID)

	go func() {
		// we don't want to regenerate credentials right on expiration, so we do it slightly before (at 3/4 of TTL)
		ticker := time.NewTicker(m.config.CredentialsTTL.Duration / 4 * 3)

		for {
			select {
			case <-cancel:
				log.Debugf("stopping turn refresh for %s", peerID)
				return
			case <-ticker.C:
				c := m.GenerateCredentials()
				var turns []*proto.ProtectedHostConfig
				for _, host := range m.config.Turns {
					turns = append(turns, &proto.ProtectedHostConfig{
						HostConfig: &proto.HostConfig{
							Uri:      host.URI,
							Protocol: ToResponseProto(host.Proto),
						},
						User:     c.Username,
						Password: c.Password,
					})
				}

				update := &proto.SyncResponse{
					WiretrusteeConfig: &proto.WiretrusteeConfig{
						Turns: turns,
					},
				}
				log.Debugf("sending new TURN credentials to peer %s", peerID)
				m.updateManager.SendUpdate(peerID, &UpdateMessage{Update: update})
			}
		}
	}()
}
