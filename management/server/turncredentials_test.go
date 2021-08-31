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
