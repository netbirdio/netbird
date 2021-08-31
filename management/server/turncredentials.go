package server

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/management/proto"
	"sync"
	"time"
)

//TURNCredentialsManager used to manage TURN credentials
type TURNCredentialsManager interface {
	GenerateCredentials() TurnCredentials
	SetupRefresh(peerKey string)
	CancelRefresh(peerKey string)
}

type TurnConfig struct {
	CredentialsTTL time.Duration
	Secret         []byte
	TurnHosts      []*Host
}

//TimeBasedAuthSecretsManager generates credentials with TTL and using pre-shared secret known to TURN server
type TimeBasedAuthSecretsManager struct {
	mux           sync.Mutex
	config        *TurnConfig
	updateManager *PeersUpdateManager
	cancelMap     map[string]chan struct{}
}

type TurnCredentials struct {
	Username string
	Password string
}

func NewTimeBasedAuthSecretsManager(updateManager *PeersUpdateManager, config *TurnConfig) *TimeBasedAuthSecretsManager {
	return &TimeBasedAuthSecretsManager{
		mux:           sync.Mutex{},
		config:        config,
		updateManager: updateManager,
		cancelMap:     make(map[string]chan struct{}),
	}
}

//GenerateCredentials generates new time-based secret credentials - basically username is a unix timestamp and password is a HMAC hash of a timestamp with a preshared TURN secret
func (m *TimeBasedAuthSecretsManager) GenerateCredentials() TurnCredentials {
	mac := hmac.New(sha1.New, m.config.Secret)

	timeAuth := time.Now().Add(m.config.CredentialsTTL).Unix()

	username := fmt.Sprint(timeAuth)

	_, err := mac.Write([]byte(username))
	if err != nil {
		log.Errorln("Generating turn password failed with error: ", err)
	}

	bytePassword := mac.Sum(nil)
	password := base64.StdEncoding.EncodeToString(bytePassword)

	return TurnCredentials{
		Username: username,
		Password: password,
	}

}

func (m *TimeBasedAuthSecretsManager) cancel(peerKey string) {
	if channel, ok := m.cancelMap[peerKey]; ok {
		close(channel)
		delete(m.cancelMap, peerKey)
	}
}

//CancelRefresh cancels scheduled peer credentials refresh
func (m *TimeBasedAuthSecretsManager) CancelRefresh(peerKey string) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.cancel(peerKey)
}

//SetupRefresh starts peer credentials refresh. Since credentials are expiring (TTL) it is necessary to always generate them and send to the peer.
//A goroutine is created and put into TimeBasedAuthSecretsManager.cancelMap. This routine should be cancelled if peer is gone.
func (m *TimeBasedAuthSecretsManager) SetupRefresh(peerKey string) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.cancel(peerKey)
	cancel := make(chan struct{}, 1)
	m.cancelMap[peerKey] = cancel
	go func() {
		for {
			select {
			case <-cancel:
				return
			default:
				c := m.GenerateCredentials()
				var turns []*proto.ProtectedHostConfig
				for _, host := range m.config.TurnHosts {
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
				err := m.updateManager.SendUpdate(peerKey, &UpdateMessage{Update: update})
				if err != nil {
					log.Errorf("error while sending TURN update to peer %s %v", peerKey, err)
					// todo maybe continue trying?
				}
				//we don't want to regenerate credentials right on expiration, so we do it slightly before (at 3/4 of TTL)
				time.Sleep(m.config.CredentialsTTL / 4 * 3)
			}
		}
	}()
}
