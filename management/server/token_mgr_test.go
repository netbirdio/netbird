package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
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

	rc := &Relay{
		Address: "localhost:0",
	}
	tested := NewTimeBasedAuthSecretsManager(peersManager, &TURNConfig{
		CredentialsTTL: ttl,
		Secret:         secret,
		Turns:          []*Host{TurnTestHost},
	}, rc)

	credentials, _ := tested.Generate()

	if credentials.Payload == "" {
		t.Errorf("expected generated TURN username not to be empty, got empty")
	}
	if credentials.Signature == "" {
		t.Errorf("expected generated TURN password not to be empty, got empty")
	}

	validateMAC(t, credentials.Payload, credentials.Signature, []byte(secret))

}

func TestTimeBasedAuthSecretsManager_SetupRefresh(t *testing.T) {
	ttl := util.Duration{Duration: 2 * time.Second}
	secret := "some_secret"
	peersManager := NewPeersUpdateManager(nil)
	peer := "some_peer"
	updateChannel := peersManager.CreateChannel(context.Background(), peer)

	rc := &Relay{
		Address: "localhost:0",
	}
	tested := NewTimeBasedAuthSecretsManager(peersManager, &TURNConfig{
		CredentialsTTL: ttl,
		Secret:         secret,
		Turns:          []*Host{TurnTestHost},
	}, rc)

	tested.SetupRefresh(context.Background(), peer)

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

	rc := &Relay{
		Address: "localhost:0",
	}
	tested := NewTimeBasedAuthSecretsManager(peersManager, &TURNConfig{
		CredentialsTTL: ttl,
		Secret:         secret,
		Turns:          []*Host{TurnTestHost},
	}, rc)

	tested.SetupRefresh(context.Background(), peer)
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
	mac := hmac.New(sha256.New, key)

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
