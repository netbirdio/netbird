package server

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"testing"
	"time"

	"github.com/netbirdio/netbird/util"
)

var TurnTestHost = &Host{
	Proto:    UDP,
	URI:      "turn:turn.wiretrustee.com:77777",
	Username: "username",
	Password: "",
}

func TestTimeBasedAuthSecretsManager_GenerateCredentials(t *testing.T) {
	ttl := util.Duration{Duration: time.Hour}
	secret := "some_secret"
	peersManager := NewPeersUpdateManager(nil)

	tested := NewTimeBasedAuthSecretsManager(peersManager, &TURNConfig{
		CredentialsTTL: ttl,
		Secret:         secret,
		Turns:          []*Host{TurnTestHost},
	})

	credentials := tested.GenerateCredentials()

	if credentials.Username == "" {
		t.Errorf("expected generated TURN username not to be empty, got empty")
	}
	if credentials.Password == "" {
		t.Errorf("expected generated TURN password not to be empty, got empty")
	}

	validateMAC(t, credentials.Username, credentials.Password, []byte(secret))

}

func TestTimeBasedAuthSecretsManager_SetupRefresh(t *testing.T) {
	ttl := util.Duration{Duration: 2 * time.Second}
	secret := "some_secret"
	peersManager := NewPeersUpdateManager(nil)
	peer := "some_peer"
	updateChannel := peersManager.CreateChannel(peer)

	tested := NewTimeBasedAuthSecretsManager(peersManager, &TURNConfig{
		CredentialsTTL: ttl,
		Secret:         secret,
		Turns:          []*Host{TurnTestHost},
	})

	tested.SetupRefresh(peer)

	if _, ok := tested.cancelMap[peer]; !ok {
		t.Errorf("expecting peer to be present in a cancel map, got not present")
	}

	var updates []*UpdateMessage

loop:
	for timeout := time.After(5 * time.Second); ; {

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

	if firstUpdate.Password == secondUpdate.Password {
		t.Errorf("expecting first credential update password %v to be diffeerent from second, got equal", firstUpdate.Password)
	}

}

func TestTimeBasedAuthSecretsManager_CancelRefresh(t *testing.T) {
	ttl := util.Duration{Duration: time.Hour}
	secret := "some_secret"
	peersManager := NewPeersUpdateManager(nil)
	peer := "some_peer"

	tested := NewTimeBasedAuthSecretsManager(peersManager, &TURNConfig{
		CredentialsTTL: ttl,
		Secret:         secret,
		Turns:          []*Host{TurnTestHost},
	})

	tested.SetupRefresh(peer)
	if _, ok := tested.cancelMap[peer]; !ok {
		t.Errorf("expecting peer to be present in a cancel map, got not present")
	}

	tested.CancelRefresh(peer)
	if _, ok := tested.cancelMap[peer]; ok {
		t.Errorf("expecting peer to be not present in a cancel map, got present")
	}
}

func validateMAC(t *testing.T, username string, actualMAC string, key []byte) {
	t.Helper()
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
