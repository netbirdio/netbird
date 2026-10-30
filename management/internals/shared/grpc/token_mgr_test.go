package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/peerauth"
	"github.com/netbirdio/netbird/util"
)

var TurnTestHost = &config.Host{
	Proto:    config.UDP,
	URI:      "turn:turn.netbird.io:77777",
	Username: "username",
	Password: "",
}

func TestTimeBasedAuthSecretsManager_GenerateCredentials(t *testing.T) {
	ttl := util.Duration{Duration: time.Hour}
	secret := "some_secret"
	peersManager := update_channel.NewPeersUpdateManager(nil)

	rc := &config.Relay{
		Addresses:      []string{"localhost:0"},
		CredentialsTTL: ttl,
		Secret:         secret,
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMockManager := settings.NewMockManager(ctrl)
	groupsManager := groups.NewManagerMock()

	tested, err := NewTimeBasedAuthSecretsManager(peersManager, &config.TURNConfig{
		CredentialsTTL:       ttl,
		Secret:               secret,
		Turns:                []*config.Host{TurnTestHost},
		TimeBasedCredentials: true,
	}, rc, settingsMockManager, groupsManager)
	require.NoError(t, err)

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
	peersManager := update_channel.NewPeersUpdateManager(nil)
	peer := "some_peer"
	updateChannel := peersManager.CreateChannel(context.Background(), peer)

	rc := &config.Relay{
		Addresses:      []string{"localhost:0"},
		CredentialsTTL: ttl,
		Secret:         secret,
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMockManager := settings.NewMockManager(ctrl)
	settingsMockManager.EXPECT().GetExtraSettings(gomock.Any(), "someAccountID").Return(&types.ExtraSettings{}, nil).AnyTimes()
	groupsManager := groups.NewManagerMock()

	tested, err := NewTimeBasedAuthSecretsManager(peersManager, &config.TURNConfig{
		CredentialsTTL:       ttl,
		Secret:               secret,
		Turns:                []*config.Host{TurnTestHost},
		TimeBasedCredentials: true,
	}, rc, settingsMockManager, groupsManager)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tested.SetupRefresh(ctx, "someAccountID", peer, PeerAuthKeys{})

	if _, ok := tested.turnCancelMap[peer]; !ok {
		t.Errorf("expecting peer to be present in the turn cancel map, got not present")
	}

	if _, ok := tested.relayCancelMap[peer]; !ok {
		t.Errorf("expecting peer to be present in the relay cancel map, got not present")
	}

	var updates []*network_map.UpdateMessage

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
		if turns := update.Update.GetNetbirdConfig().GetTurns(); len(turns) > 0 {
			turnUpdates++
			if turnUpdates == 1 {
				firstTurnUpdate = turns[0]
			} else {
				secondTurnUpdate = turns[0]
			}
		}
		if relay := update.Update.GetNetbirdConfig().GetRelay(); relay != nil {
			// avoid updating on turn updates since they also send relay credentials
			if update.Update.GetNetbirdConfig().GetTurns() == nil {
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
	peersManager := update_channel.NewPeersUpdateManager(nil)
	peer := "some_peer"

	rc := &config.Relay{
		Addresses:      []string{"localhost:0"},
		CredentialsTTL: ttl,
		Secret:         secret,
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMockManager := settings.NewMockManager(ctrl)
	groupsManager := groups.NewManagerMock()

	tested, err := NewTimeBasedAuthSecretsManager(peersManager, &config.TURNConfig{
		CredentialsTTL:       ttl,
		Secret:               secret,
		Turns:                []*config.Host{TurnTestHost},
		TimeBasedCredentials: true,
	}, rc, settingsMockManager, groupsManager)
	require.NoError(t, err)

	tested.SetupRefresh(context.Background(), "someAccountID", peer, PeerAuthKeys{})
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

const peerAuthTestSecret = "some_relay_secret"

func newPeerAuthTestManager(t *testing.T, peerAuth config.PeerAuth) (*TimeBasedAuthSecretsManager, *update_channel.PeersUpdateManager) {
	t.Helper()
	ctrl := gomock.NewController(t)
	settingsMockManager := settings.NewMockManager(ctrl)
	settingsMockManager.EXPECT().GetExtraSettings(gomock.Any(), gomock.Any()).Return(&types.ExtraSettings{}, nil).AnyTimes()
	peersManager := update_channel.NewPeersUpdateManager(nil)

	tested, err := NewTimeBasedAuthSecretsManager(peersManager, &config.TURNConfig{
		CredentialsTTL:       util.Duration{Duration: time.Hour},
		Secret:               "turn_secret",
		Turns:                []*config.Host{TurnTestHost},
		TimeBasedCredentials: true,
	}, &config.Relay{
		Addresses:      []string{"rels://relay.netbird.io:443"},
		CredentialsTTL: util.Duration{Duration: time.Hour},
		Secret:         peerAuthTestSecret,
	}, settingsMockManager, groups.NewManagerMock(), WithPeerAuth(peerAuth))
	require.NoError(t, err)
	return tested, peersManager
}

func newPeerAuthTestKeys(t *testing.T) (PeerAuthKeys, wgtypes.Key, ed25519.PublicKey) {
	t.Helper()
	wgKey, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	authPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keys := PeerAuthKeys{WGPubKey: wgKey.PublicKey().String(), AuthPubKey: base64.StdEncoding.EncodeToString(authPub)}
	return keys, wgKey.PublicKey(), authPub
}

// verifyPeerAuthToken checks the token the way a Signal or Relay verifier holding the relay
// secret does.
func verifyPeerAuthToken(t *testing.T, token []byte) *peerauth.Token {
	t.Helper()
	secret := sha256.Sum256([]byte(peerAuthTestSecret))
	verified, err := peerauth.VerifyToken(token, peerauth.TokenKeys{HMAC: secret[:]}, time.Now())
	require.NoError(t, err, "a verifier holding the relay secret must accept the token")
	return verified
}

func TestTimeBasedAuthSecretsManager_GenerateAuthToken(t *testing.T) {
	keys, wgPub, authPub := newPeerAuthTestKeys(t)

	t.Run("disabled", func(t *testing.T) {
		tested, _ := newPeerAuthTestManager(t, config.PeerAuth{})
		token, err := tested.GenerateAuthToken(keys)
		require.NoError(t, err)
		assert.Nil(t, token, "with peer auth disabled every peer keeps the legacy relay token")
	})

	tested, _ := newPeerAuthTestManager(t, config.PeerAuth{Enabled: true})

	t.Run("peer without auth key", func(t *testing.T) {
		token, err := tested.GenerateAuthToken(PeerAuthKeys{WGPubKey: keys.WGPubKey})
		require.NoError(t, err)
		assert.Nil(t, token, "a peer that sent no auth key keeps the legacy relay token")
	})

	t.Run("peer with auth key", func(t *testing.T) {
		token, err := tested.GenerateAuthToken(keys)
		require.NoError(t, err)
		verified := verifyPeerAuthToken(t, token)
		assert.Equal(t, wgPub, verified.WGPub, "the token must be bound to the peer WireGuard key")
		assert.Equal(t, authPub, verified.AuthPub, "the token must be bound to the peer auth key")
		assert.WithinDuration(t, time.Now().Add(time.Hour), verified.Expiry, time.Minute, "the token must live as long as the relay credentials")
	})

	t.Run("malformed auth key", func(t *testing.T) {
		_, err := tested.GenerateAuthToken(PeerAuthKeys{WGPubKey: keys.WGPubKey, AuthPubKey: "bm90LWEta2V5"})
		assert.Error(t, err, "a stored auth key of the wrong size must not be signed")
	})
}

func TestNewTimeBasedAuthSecretsManager_PeerAuthNeedsRelaySecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	_, err := NewTimeBasedAuthSecretsManager(update_channel.NewPeersUpdateManager(nil), nil, &config.Relay{Addresses: []string{"rels://relay.netbird.io:443"}},
		settings.NewMockManager(ctrl), groups.NewManagerMock(), WithPeerAuth(config.PeerAuth{Enabled: true}))
	assert.Error(t, err, "peer auth cannot be enabled without the secret that signs the tokens")
}

// While peer auth is on, every credentials refresh must carry the auth token and no legacy relay
// token: a NetbirdConfig without it makes the client fall back to legacy credentials.
func TestTimeBasedAuthSecretsManager_RefreshCarriesAuthToken(t *testing.T) {
	keys, _, _ := newPeerAuthTestKeys(t)
	tested, peersManager := newPeerAuthTestManager(t, config.PeerAuth{Enabled: true})
	ctx := context.Background()

	for name, keys := range map[string]PeerAuthKeys{"with auth key": keys, "without auth key": {WGPubKey: keys.WGPubKey}} {
		t.Run(name, func(t *testing.T) {
			updates := peersManager.CreateChannel(ctx, "peer")
			t.Cleanup(func() { peersManager.CloseChannel(ctx, "peer") })

			tested.pushNewRelayTokens(ctx, "account", "peer", keys)
			tested.pushNewTURNAndRelayTokens(ctx, "account", "peer", keys)

			for _, kind := range []string{"relay refresh", "TURN refresh"} {
				var update *network_map.UpdateMessage
				select {
				case update = <-updates:
				case <-time.After(5 * time.Second):
					t.Fatalf("no %s sent", kind)
				}
				cfg := update.Update.GetNetbirdConfig()
				require.NotNil(t, cfg.GetRelay(), "%s must carry the relay config", kind)
				if keys.AuthPubKey == "" {
					assert.Nil(t, cfg.GetAuthToken(), "%s must not carry an auth token for a legacy peer", kind)
					assert.NotEmpty(t, cfg.GetRelay().GetTokenPayload(), "%s must carry the legacy relay token", kind)
					continue
				}
				verifyPeerAuthToken(t, cfg.GetAuthToken())
				assert.Empty(t, cfg.GetRelay().GetTokenPayload(), "%s must not carry the legacy relay token too", kind)
				assert.Empty(t, cfg.GetRelay().GetTokenSignature(), "%s must not carry the legacy relay token too", kind)
			}
		})
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
