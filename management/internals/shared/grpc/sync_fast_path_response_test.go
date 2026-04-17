package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/groups"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/util"
)

func fastPathTestPeer() *nbpeer.Peer {
	return &nbpeer.Peer{
		ID:        "peer-id",
		AccountID: "account-id",
		Key:       "pubkey",
	}
}

func fastPathTestSecrets(t *testing.T, turn *config.TURNConfig, relay *config.Relay) *TimeBasedAuthSecretsManager {
	t.Helper()
	peersManager := update_channel.NewPeersUpdateManager(nil)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMock := settings.NewMockManager(ctrl)
	secrets, err := NewTimeBasedAuthSecretsManager(peersManager, turn, relay, settingsMock, groups.NewManagerMock())
	require.NoError(t, err, "secrets manager initialisation must succeed")
	return secrets
}

func noGroupsFetcher(context.Context, string, string) ([]string, error) {
	return nil, nil
}

func TestBuildFastPathResponse_TimeBasedTURNAndRelay_FreshTokens(t *testing.T) {
	ttl := util.Duration{Duration: time.Hour}
	turnCfg := &config.TURNConfig{
		CredentialsTTL:       ttl,
		Secret:               "turn-secret",
		Turns:                []*config.Host{TurnTestHost},
		TimeBasedCredentials: true,
	}
	relayCfg := &config.Relay{
		Addresses:      []string{"rel.example:443"},
		CredentialsTTL: ttl,
		Secret:         "relay-secret",
	}
	cfg := &config.Config{
		TURNConfig: turnCfg,
		Relay:      relayCfg,
		Signal:     &config.Host{URI: "signal.example:443", Proto: config.HTTPS},
		Stuns:      []*config.Host{{URI: "stun.example:3478", Proto: config.UDP}},
	}

	secrets := fastPathTestSecrets(t, turnCfg, relayCfg)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMock := settings.NewMockManager(ctrl)
	settingsMock.EXPECT().GetExtraSettings(gomock.Any(), "account-id").Return(&types.ExtraSettings{}, nil).AnyTimes()

	resp := buildFastPathResponse(context.Background(), cfg, secrets, settingsMock, noGroupsFetcher, fastPathTestPeer())

	require.NotNil(t, resp, "response must not be nil")
	assert.Nil(t, resp.NetworkMap, "fast path must omit NetworkMap")
	assert.Nil(t, resp.PeerConfig, "fast path must omit PeerConfig")
	assert.Empty(t, resp.Checks, "fast path must omit posture checks")
	assert.Empty(t, resp.RemotePeers, "fast path must omit remote peers")

	require.NotNil(t, resp.NetbirdConfig, "NetbirdConfig must be present on fast path")
	require.Len(t, resp.NetbirdConfig.Turns, 1, "time-based TURN credentials must be present")
	assert.NotEmpty(t, resp.NetbirdConfig.Turns[0].User, "TURN user must be populated")
	assert.NotEmpty(t, resp.NetbirdConfig.Turns[0].Password, "TURN password must be populated")

	require.NotNil(t, resp.NetbirdConfig.Relay, "Relay config must be present when configured")
	assert.NotEmpty(t, resp.NetbirdConfig.Relay.TokenPayload, "relay token payload must be populated")
	assert.NotEmpty(t, resp.NetbirdConfig.Relay.TokenSignature, "relay token signature must be populated")
	assert.Equal(t, []string{"rel.example:443"}, resp.NetbirdConfig.Relay.Urls, "relay URLs passthrough")

	require.NotNil(t, resp.NetbirdConfig.Signal, "Signal config must be present when configured")
	assert.Equal(t, "signal.example:443", resp.NetbirdConfig.Signal.Uri, "signal URI passthrough")
	require.Len(t, resp.NetbirdConfig.Stuns, 1, "STUNs must be passed through")
	assert.Equal(t, "stun.example:3478", resp.NetbirdConfig.Stuns[0].Uri, "STUN URI passthrough")
}

func TestBuildFastPathResponse_StaticTURNCredentials(t *testing.T) {
	ttl := util.Duration{Duration: time.Hour}
	staticHost := &config.Host{
		URI:      "turn:static.example:3478",
		Proto:    config.UDP,
		Username: "preset-user",
		Password: "preset-pass",
	}
	turnCfg := &config.TURNConfig{
		CredentialsTTL:       ttl,
		Secret:               "turn-secret",
		Turns:                []*config.Host{staticHost},
		TimeBasedCredentials: false,
	}
	cfg := &config.Config{TURNConfig: turnCfg}

	// Use a relay-free secrets manager; static TURN path does not consult it.
	secrets := fastPathTestSecrets(t, turnCfg, nil)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMock := settings.NewMockManager(ctrl)
	settingsMock.EXPECT().GetExtraSettings(gomock.Any(), gomock.Any()).Return(&types.ExtraSettings{}, nil).AnyTimes()

	resp := buildFastPathResponse(context.Background(), cfg, secrets, settingsMock, noGroupsFetcher, fastPathTestPeer())

	require.NotNil(t, resp.NetbirdConfig)
	require.Len(t, resp.NetbirdConfig.Turns, 1, "static TURN must appear in response")
	assert.Equal(t, "preset-user", resp.NetbirdConfig.Turns[0].User, "static user passthrough")
	assert.Equal(t, "preset-pass", resp.NetbirdConfig.Turns[0].Password, "static password passthrough")
	assert.Nil(t, resp.NetbirdConfig.Relay, "no Relay when Relay config is nil")
}

func TestBuildFastPathResponse_NoRelayConfigured_NoRelaySection(t *testing.T) {
	cfg := &config.Config{}
	secrets := fastPathTestSecrets(t, nil, nil)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMock := settings.NewMockManager(ctrl)
	settingsMock.EXPECT().GetExtraSettings(gomock.Any(), gomock.Any()).Return(&types.ExtraSettings{}, nil).AnyTimes()

	resp := buildFastPathResponse(context.Background(), cfg, secrets, settingsMock, noGroupsFetcher, fastPathTestPeer())
	require.NotNil(t, resp.NetbirdConfig, "NetbirdConfig must be non-nil even without relay/turn")
	assert.Nil(t, resp.NetbirdConfig.Relay, "Relay must be absent when not configured")
	assert.Empty(t, resp.NetbirdConfig.Turns, "Turns must be empty when not configured")
}

func TestBuildFastPathResponse_ExtraSettingsErrorStillReturnsResponse(t *testing.T) {
	cfg := &config.Config{}
	secrets := fastPathTestSecrets(t, nil, nil)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMock := settings.NewMockManager(ctrl)
	settingsMock.EXPECT().GetExtraSettings(gomock.Any(), gomock.Any()).Return(nil, assertAnError).AnyTimes()

	resp := buildFastPathResponse(context.Background(), cfg, secrets, settingsMock, noGroupsFetcher, fastPathTestPeer())
	require.NotNil(t, resp, "extra settings failure must degrade gracefully into an empty fast-path response")
	assert.Nil(t, resp.NetworkMap, "NetworkMap still omitted on degraded path")
}

// assertAnError is a sentinel used by fast-path tests that need to simulate a
// dependency failure without caring about the error value.
var assertAnError = errForTests("simulated")

type errForTests string

func (e errForTests) Error() string { return string(e) }
