package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/proto"
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
		Addresses:      []string{"localhost:0"},
		CredentialsTTL: ttl,
		Secret:         secret,
	}

	tested := NewTimeBasedAuthSecretsManager(peersManager, &TURNConfig{
		CredentialsTTL:       ttl,
		Secret:               secret,
		Turns:                []*Host{TurnTestHost},
		TimeBasedCredentials: true,
	}, rc)

	turnCredentials, err := tested.GenerateTurnToken()
	require.NoError(t, err)

	if turnCredentials.Payload == "" {
		t.Errorf("expected generated TURN username not to be empty, got empty")
	}
	if turnCredentials.Signature == "" {
		t.Errorf("expected generated TURN password not to be empty, got empty")
	}

	validateMAC(t, sha1.New, turnCredentials.Payload, turnCredentials.Signature, []byte(secret))

	relayCredentials, err := tested.GenerateRelayToken()
	require.NoError(t, err)

	if relayCredentials.Payload == "" {
		t.Errorf("expected generated relay payload not to be empty, got empty")
	}
	if relayCredentials.Signature == "" {
		t.Errorf("expected generated relay signature not to be empty, got empty")
	}

	hashedSecret := sha256.Sum256([]byte(secret))
	validateMAC(t, sha256.New, relayCredentials.Payload, relayCredentials.Signature, hashedSecret[:])
}

func TestTimeBasedAuthSecretsManager_SetupRefresh(t *testing.T) {
	ttl := util.Duration{Duration: 2 * time.Second}
	secret := "some_secret"
	peersManager := NewPeersUpdateManager(nil)
	peer := "some_peer"
	updateChannel := peersManager.CreateChannel(context.Background(), peer)

	rc := &Relay{
		Addresses:      []string{"localhost:0"},
		CredentialsTTL: ttl,
		Secret:         secret,
	}
	tested := NewTimeBasedAuthSecretsManager(peersManager, &TURNConfig{
		CredentialsTTL:       ttl,
		Secret:               secret,
		Turns:                []*Host{TurnTestHost},
		TimeBasedCredentials: true,
	}, rc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tested.SetupRefresh(ctx, peer)

	if _, ok := tested.turnCancelMap[peer]; !ok {
		t.Errorf("expecting peer to be present in the turn cancel map, got not present")
	}

	if _, ok := tested.relayCancelMap[peer]; !ok {
		t.Errorf("expecting peer to be present in the relay cancel map, got not present")
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
		t.Errorf("expecting at least 2 peer credentials updates, got %v", len(updates))
	}

	var turnUpdates, relayUpdates int
	var firstTurnUpdate, secondTurnUpdate *proto.ProtectedHostConfig
	var firstRelayUpdate, secondRelayUpdate *proto.RelayConfig

	for _, update := range updates {
		if turns := update.Update.GetWiretrusteeConfig().GetTurns(); len(turns) > 0 {
			turnUpdates++
			if turnUpdates == 1 {
				firstTurnUpdate = turns[0]
			} else {
				secondTurnUpdate = turns[0]
			}
		}
		if relay := update.Update.GetWiretrusteeConfig().GetRelay(); relay != nil {
			// avoid updating on turn updates since they also send relay credentials
			if update.Update.GetWiretrusteeConfig().GetTurns() == nil {
				relayUpdates++
				if relayUpdates == 1 {
					firstRelayUpdate = relay
				} else {
					secondRelayUpdate = relay
				}
			}
		}
	}

	if turnUpdates < 1 {
		t.Errorf("expecting at least 1 TURN credential update, got %v", turnUpdates)
	}
	if relayUpdates < 1 {
		t.Errorf("expecting at least 1 relay credential update, got %v", relayUpdates)
	}

	if firstTurnUpdate != nil && secondTurnUpdate != nil {
		if firstTurnUpdate.Password == secondTurnUpdate.Password {
			t.Errorf("expecting first TURN credential update password %v to be different from second, got equal", firstTurnUpdate.Password)
		}
	}

	if firstRelayUpdate != nil && secondRelayUpdate != nil {
		if firstRelayUpdate.TokenSignature == secondRelayUpdate.TokenSignature {
			t.Errorf("expecting first relay credential update signature %v to be different from second, got equal", firstRelayUpdate.TokenSignature)
		}
	}
}

func TestTimeBasedAuthSecretsManager_CancelRefresh(t *testing.T) {
	ttl := util.Duration{Duration: time.Hour}
	secret := "some_secret"
	peersManager := NewPeersUpdateManager(nil)
	peer := "some_peer"

	rc := &Relay{
		Addresses:      []string{"localhost:0"},
		CredentialsTTL: ttl,
		Secret:         secret,
	}
	tested := NewTimeBasedAuthSecretsManager(peersManager, &TURNConfig{
		CredentialsTTL:       ttl,
		Secret:               secret,
		Turns:                []*Host{TurnTestHost},
		TimeBasedCredentials: true,
	}, rc)

	tested.SetupRefresh(context.Background(), peer)
	if _, ok := tested.turnCancelMap[peer]; !ok {
		t.Errorf("expecting peer to be present in turn cancel map, got not present")
	}
	if _, ok := tested.relayCancelMap[peer]; !ok {
		t.Errorf("expecting peer to be present in relay cancel map, got not present")
	}

	tested.CancelRefresh(peer)
	if _, ok := tested.turnCancelMap[peer]; ok {
		t.Errorf("expecting peer to be not present in turn cancel map, got present")
	}
	if _, ok := tested.relayCancelMap[peer]; ok {
		t.Errorf("expecting peer to be not present in relay cancel map, got present")
	}
}

func validateMAC(t *testing.T, algo func() hash.Hash, username string, actualMAC string, key []byte) {
	t.Helper()
	mac := hmac.New(algo, key)

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
