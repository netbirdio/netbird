package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// The seeded profile of setupServerWithProfile is created with this management
// URL, so a request carrying it restates what the profile already holds.
const storedManagementURL = "https://api.netbird.io:443"

// A client configured by environment re-sends its whole configuration on every
// `netbird up`: the CLI fills the request from its flags and env regardless of
// what changed. With the update-settings kill switch on, such a request must
// pass — nothing about the configuration moves.
func TestSetConfig_RestatingTheStoredConfigPassesTheGate(t *testing.T) {
	s, ctx, profName, username, _ := setupServerWithProfile(t)
	s.updateSettingsDisabled = true

	_, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:   profName,
		Username:      username,
		ManagementUrl: storedManagementURL,
	})
	require.NoError(t, err, "restating the stored management URL is not a settings change")
}

// The same endpoint written without its default port is the same endpoint. A
// gate that compared raw strings refused NB_MANAGEMENT_URL=https://host, which
// is how the URL is normally spelled.
func TestSetConfig_EquivalentManagementURLPassesTheGate(t *testing.T) {
	s, ctx, profName, username, _ := setupServerWithProfile(t)
	s.updateSettingsDisabled = true

	_, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:   profName,
		Username:      username,
		ManagementUrl: "https://api.netbird.io",
	})
	require.NoError(t, err, "an implicit :443 is the same management URL")
}

// The kill switch still has to do its job: a request that moves a setting is
// refused, and the profile keeps the value it had.
func TestSetConfig_ChangingASettingIsRefused(t *testing.T) {
	s, ctx, profName, username, cfgPath := setupServerWithProfile(t)
	s.updateSettingsDisabled = true

	_, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:   profName,
		Username:      username,
		ManagementUrl: "https://mgmt.elsewhere.example:443",
	})
	require.Error(t, err, "moving the management URL is a settings change")
	require.Equal(t, codes.Unavailable, gstatus.Code(err), "want the update-settings refusal, got %v", err)

	cfg, err := profilemanager.GetConfig(cfgPath)
	require.NoError(t, err)
	require.Equal(t, storedManagementURL, cfg.ManagementURL.String(), "the refused request changed the config anyway")
}

// A field whose requested value differs from the stored one is a change even
// when the rest of the request restates the configuration.
func TestSetConfig_SingleDivergingFieldIsRefused(t *testing.T) {
	s, ctx, profName, username, _ := setupServerWithProfile(t)
	s.updateSettingsDisabled = true

	rosenpass := true
	_, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:      profName,
		Username:         username,
		ManagementUrl:    storedManagementURL,
		RosenpassEnabled: &rosenpass,
	})
	require.Error(t, err, "enabling Rosenpass is a settings change")
	require.Equal(t, codes.Unavailable, gstatus.Code(err), "want the update-settings refusal, got %v", err)
}

// With the switch off, the same diverging request goes through: the gate must
// not leak into a daemon that never enabled it.
func TestSetConfig_ChangeAllowedWhenTheSwitchIsOff(t *testing.T) {
	s, ctx, profName, username, cfgPath := setupServerWithProfile(t)

	_, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:   profName,
		Username:      username,
		ManagementUrl: "https://mgmt.elsewhere.example:443",
	})
	require.NoError(t, err)

	cfg, err := profilemanager.GetConfig(cfgPath)
	require.NoError(t, err)
	require.Equal(t, "https://mgmt.elsewhere.example:443", cfg.ManagementURL.String())
}

// Login carries the same config surface as SetConfig, so it is gated the same
// way: a login that would move a protected setting is refused before it can
// touch daemon state.
func TestLogin_ChangingTheManagementURLIsRefused(t *testing.T) {
	s, _, _, username, _ := setupServerWithProfile(t)
	s.updateSettingsDisabled = true
	s.rootCtx = internal.CtxInitState(context.Background())

	_, err := s.Login(userCtx(), &proto.LoginRequest{
		Username:      &username,
		ManagementUrl: "https://mgmt.elsewhere.example:443",
	})
	require.Error(t, err, "moving the management URL through Login is a settings change")
	require.Equal(t, codes.Unavailable, gstatus.Code(err), "want the update-settings refusal, got %v", err)
}

// seedProfileConfig writes a profile config carrying the given management URL
// and pre-shared key into a temp dir, and returns its path.
func seedProfileConfig(t *testing.T, managementURL, preSharedKey string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "seeded.json")
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    path,
		ManagementURL: managementURL,
		PreSharedKey:  &preSharedKey,
	})
	require.NoError(t, err, "seed profile config")
	return path
}

// The decision procedure itself, over the fields a login actually persists.
// A login that restates the stored values must not be refused: that is what
// keeps a re-login, or a container restart carrying NB_MANAGEMENT_URL, working
// with the kill switch on.
func TestLoginGateDecision(t *testing.T) {
	stored, err := profilemanager.GetConfig(seedProfileConfig(t, storedManagementURL, "stored-key"))
	require.NoError(t, err)

	redacted := preSharedKeyRedactedSentinel
	empty := ""
	sameKey := "stored-key"
	otherKey := "other-key"

	tests := []struct {
		name        string
		msg         *proto.LoginRequest
		wantChanged bool
	}{
		{
			name:        "pure auth carries no config",
			msg:         &proto.LoginRequest{SetupKey: "ABC"},
			wantChanged: false,
		},
		{
			name:        "stored management URL restated",
			msg:         &proto.LoginRequest{ManagementUrl: storedManagementURL},
			wantChanged: false,
		},
		{
			name:        "stored management URL without its default port",
			msg:         &proto.LoginRequest{ManagementUrl: "https://api.netbird.io"},
			wantChanged: false,
		},
		{
			name:        "different management URL",
			msg:         &proto.LoginRequest{ManagementUrl: "https://mgmt.elsewhere.example:443"},
			wantChanged: true,
		},
		{
			name:        "stored pre-shared key restated",
			msg:         &proto.LoginRequest{OptionalPreSharedKey: &sameKey},
			wantChanged: false,
		},
		{
			name:        "redacted pre-shared key echoed back",
			msg:         &proto.LoginRequest{OptionalPreSharedKey: &redacted},
			wantChanged: false,
		},
		{
			name:        "empty pre-shared key is not a request to clear it",
			msg:         &proto.LoginRequest{OptionalPreSharedKey: &empty},
			wantChanged: false,
		},
		{
			name:        "different pre-shared key",
			msg:         &proto.LoginRequest{OptionalPreSharedKey: &otherKey},
			wantChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantChanged, configChangeRequested(stored, loginOverridesInput(tt.msg)))
		})
	}
}

// A profile with no config on disk yet is judged against the config the daemon
// would create for it, so a first login that asks for the defaults is not a
// change while one that asks for a different management URL is.
func TestGateDecisionWithoutStoredConfig(t *testing.T) {
	require.False(t, configChangeRequested(nil, profilemanager.ConfigInput{}),
		"a request carrying nothing cannot change anything")
	require.False(t, configChangeRequested(nil, profilemanager.ConfigInput{ManagementURL: profilemanager.DefaultManagementURL}),
		"asking for the default management URL is what the daemon would write anyway")
	require.True(t, configChangeRequested(nil, profilemanager.ConfigInput{ManagementURL: "https://mgmt.elsewhere.example:443"}),
		"asking for a non-default management URL is a change")
}

// A dry run that cannot be evaluated must fail closed, or a malformed field
// would open the gate.
func TestGateDecisionFailsClosedOnAnInvalidRequest(t *testing.T) {
	require.True(t, configChangeRequested(nil, profilemanager.ConfigInput{ManagementURL: "not-a-url"}),
		"an unevaluable request must count as a change")
}

// The gate reads the stored config to decide, and reading it must not write it:
// a refused request has to leave the profile file byte-for-byte as it was.
// A config file missing a field the config layer fills in (MTU, here) is what
// makes the normalization write fire.
func TestSetConfig_RefusedRequestLeavesTheConfigFileUntouched(t *testing.T) {
	s, ctx, profName, username, cfgPath := setupServerWithProfile(t)
	s.updateSettingsDisabled = true

	require.NoError(t, os.WriteFile(cfgPath, []byte(`{"WgIface":"wt0"}`), 0o600))
	before, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	_, err = s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:   profName,
		Username:      username,
		ManagementUrl: "https://mgmt.elsewhere.example:443",
	})
	require.Error(t, err)
	require.Equal(t, codes.Unavailable, gstatus.Code(err), "want the update-settings refusal, got %v", err)

	after, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	require.Equal(t, string(before), string(after), "the refused request rewrote the profile config")
}
