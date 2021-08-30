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

func (m *TimeBasedAuthSecretsManager) GenerateCredentials() TurnCredentials {
	m.mux.Lock()
	defer m.mux.Unlock()
	// generate new ones
	creds := m.generateCredentials()
	return creds

}

func (m *TimeBasedAuthSecretsManager) CancelRefresh(peerKey string) {
	m.mux.Lock()
	defer m.mux.Unlock()

	if channel, ok := m.cancelMap[peerKey]; ok {
		close(channel)
		delete(m.cancelMap, peerKey)
	}
}

func (m *TimeBasedAuthSecretsManager) SetupRefresh(peerKey string) {
	m.mux.Lock()
	defer m.mux.Unlock()
	cancel := make(chan struct{}, 1)
	m.cancelMap[peerKey] = cancel
	go func() {
		for {
			select {
			case <-cancel:
				return
			default:
				c := m.generateCredentials()
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
				//todo convert credentials to TURN response
				err := m.updateManager.SendUpdate(peerKey, &UpdateMessage{Update: update})
				if err != nil {
					log.Errorf("error while sending TURN update to peer %s %v", peerKey, err)
					// todo maybe continue trying?
				}
				time.Sleep(m.config.CredentialsTTL)
			}
		}
	}()
}

func (m *TimeBasedAuthSecretsManager) generateCredentials() TurnCredentials {
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
