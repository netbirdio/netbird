package server

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"testing"
	"time"
)

var TurnTestHost = &Host{
	Proto:    UDP,
	URI:      "turn:turn.wiretrustee.com:77777",
	Username: "username",
	Password: nil,
}

func TestTimeBasedAuthSecretsManager_GenerateCredentials(t *testing.T) {
	ttl := time.Hour
	secret := []byte("some_secret")
	peersManager := NewPeersUpdateManager()

	tested := NewTimeBasedAuthSecretsManager(peersManager, &TurnConfig{
		CredentialsTTL: ttl,
		Secret:         secret,
		TurnHosts:      []*Host{TurnTestHost},
	})

	credentials := tested.GenerateCredentials()

	if credentials.Username == "" {
		t.Errorf("expected generated TURN username not to be empty, got empty")
	}
	if credentials.Password == "" {
		t.Errorf("expected generated TURN password not to be empty, got empty")
	}

	validateMAC(credentials.Username, credentials.Password, secret, t)

}

func TestTimeBasedAuthSecretsManager_SetupRefresh(t *testing.T) {
	ttl := time.Second
	secret := []byte("some_secret")
	peersManager := NewPeersUpdateManager()
	peer := "some_peer"
	updateChannel := peersManager.CreateChannel(peer)

	tested := NewTimeBasedAuthSecretsManager(peersManager, &TurnConfig{
		CredentialsTTL: ttl,
		Secret:         secret,
		TurnHosts:      []*Host{TurnTestHost},
	})

	tested.SetupRefresh(peer)

	if _, ok := tested.cancelMap[peer]; !ok {
		t.Errorf("expecting peer to be present in a cancel map, got not present")
	}

	var updates []*UpdateMessage

loop:
	for timeout := time.After(3 * time.Second); ; {

		select {
		case update := <-updateChannel:
			updates = append(updates, update)
		case <-timeout:
			break loop
		}

		if len(updates) >= 2 {
			break loop
		}
	}

	if len(updates) < 2 {
		t.Errorf("expecting 2 peer credentials updates, got %v", len(updates))
	}

	firstUpdate := updates[0].Update.GetWiretrusteeConfig().Turns[0]
	secondUpdate := updates[1].Update.GetWiretrusteeConfig().Turns[0]

	if firstUpdate.User == secondUpdate.User {
		t.Errorf("expecting first credential update username %v to be diffeerent from second, got equal", firstUpdate.User)
	}
	if firstUpdate.Password == secondUpdate.Password {
		t.Errorf("expecting first credential update password %v to be diffeerent from second, got equal", firstUpdate.Password)
	}

}

func validateMAC(username string, actualMAC string, key []byte, t *testing.T) {
	mac := hmac.New(sha1.New, key)

	_, err := mac.Write([]byte(username))
	if err != nil {
		t.Fatal(err)
	}

	expectedMAC := mac.Sum(nil)
	decodedMAC, err := base64.StdEncoding.DecodeString(actualMAC)
	if err != nil {
		t.Fatal(err)
	}
	equal := hmac.Equal(decodedMAC, expectedMAC)

	if !equal {
		t.Errorf("expected password MAC to be %s. got %s", expectedMAC, decodedMAC)
	}
}
