package server

import (
	"context"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
)

// fakeMDMFetcher implements mdm.PolicyFetcher returning a pre-set
// policy map. Tests build one per Server instance to inject a
// scripted MDM overlay via a Loader rather than via package-level state.
type fakeMDMFetcher struct{ values map[string]any }

func (f *fakeMDMFetcher) Fetch() map[string]any { return f.values }

// withMDMPolicy installs an mdm.Loader on the given Server whose
// loadPlatform returns the supplied Policy's underlying values. Use
// after setupServerWithProfile to inject the scripted policy the
// SetConfig / Login MDM gates will observe.
func withMDMPolicy(t *testing.T, s *Server, policy *mdm.Policy) {
	t.Helper()
	values := map[string]any{}
	if policy != nil {
		for _, k := range policy.ManagedKeys() {
			if v, ok := policy.GetString(k); ok {
				values[k] = v
				continue
			}
			if v, ok := policy.GetBool(k); ok {
				values[k] = v
				continue
			}
			if v, ok := policy.GetInt(k); ok {
				values[k] = v
				continue
			}
			if v, ok := policy.GetStringSlice(k); ok {
				values[k] = v
			}
		}
	}
	s.mdmLoader = mdm.NewLoader(&fakeMDMFetcher{values: values})
}

// setupServerWithProfile mirrors the boilerplate of TestSetConfig_AllFieldsSaved:
// overrides profilemanager paths to a temp dir, seeds a profile, sets it
// active, and constructs a Server instance. Returns the constructed server
// plus context + profile name + username + cfgPath for the seeded profile.
func setupServerWithProfile(t *testing.T) (s *Server, ctx context.Context, profName, username, cfgPath string) {
	t.Helper()
	tempDir := t.TempDir()

	origDefaultProfileDir := profilemanager.DefaultConfigPathDir
	origDefaultConfigPath := profilemanager.DefaultConfigPath
	origActiveProfileStatePath := profilemanager.ActiveProfileStatePath
	profilemanager.ConfigDirOverride = tempDir
	profilemanager.DefaultConfigPathDir = tempDir
	profilemanager.ActiveProfileStatePath = tempDir + "/active_profile.json"
	profilemanager.DefaultConfigPath = filepath.Join(tempDir, "default.json")
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDefaultProfileDir
		profilemanager.ActiveProfileStatePath = origActiveProfileStatePath
		profilemanager.DefaultConfigPath = origDefaultConfigPath
		profilemanager.ConfigDirOverride = ""
	})

	currUser, err := user.Current()
	require.NoError(t, err)

	profName = "test-profile-mdm"
	cfgPath = filepath.Join(tempDir, profName+".json")

	_, err = profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    cfgPath,
		ManagementURL: "https://api.netbird.io:443",
	})
	require.NoError(t, err)

	pm := profilemanager.ServiceManager{}
	require.NoError(t, pm.SetActiveProfileState(&profilemanager.ActiveProfileState{
		ID:       profilemanager.ID(profName),
		Username: currUser.Username,
	}))

	// The privileged-change gate reads the caller's kernel identity from the
	// context, which a real caller gets from the daemon's transport credentials.
	// This test drives the handler directly, so it stands in for a root caller;
	// without an identity the gate would (correctly) refuse the SSH fields.
	ctx = privilegedTestCtx()
	s = New(ctx, "console", "", false, false, false, false)
	return s, ctx, profName, currUser.Username, cfgPath
}

// extractViolation pulls the MDMManagedFieldsViolation detail from a
// FailedPrecondition error. Fails the test if absent or malformed.
func extractViolation(t *testing.T, err error) *proto.MDMManagedFieldsViolation {
	t.Helper()
	require.Error(t, err)
	st, ok := gstatus.FromError(err)
	require.True(t, ok, "error must be a gRPC status: %v", err)
	require.Equal(t, codes.FailedPrecondition, st.Code(), "expected FailedPrecondition, got %s", st.Code())
	for _, d := range st.Details() {
		if v, ok := d.(*proto.MDMManagedFieldsViolation); ok {
			return v
		}
	}
	t.Fatalf("MDMManagedFieldsViolation detail not found on status; details: %v", st.Details())
	return nil
}

func TestSetConfig_MDMReject_SingleField(t *testing.T) {
	s, ctx, profName, username, _ := setupServerWithProfile(t)
	withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL: "https://mdm.example.com:443",
	}))

	_, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:   profName,
		Username:      username,
		ManagementUrl: "https://user.tried.this.com:443",
	})

	v := extractViolation(t, err)
	assert.Equal(t, []string{mdm.KeyManagementURL}, v.GetFields())
}

func TestSetConfig_MDMReject_MultipleFields(t *testing.T) {
	s, ctx, profName, username, _ := setupServerWithProfile(t)
	withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL:    "https://mdm.example.com:443",
		mdm.KeyBlockInbound:     true,
		mdm.KeyRosenpassEnabled: true,
	}))

	blockInbound := false
	rosenpassEnabled := false
	_, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:      profName,
		Username:         username,
		ManagementUrl:    "https://user.tried.this.com:443",
		BlockInbound:     &blockInbound,
		RosenpassEnabled: &rosenpassEnabled,
	})

	v := extractViolation(t, err)
	assert.ElementsMatch(t, []string{
		mdm.KeyManagementURL,
		mdm.KeyBlockInbound,
		mdm.KeyRosenpassEnabled,
	}, v.GetFields())
}

func TestSetConfig_MDMReject_AllOrNothing(t *testing.T) {
	// MDM enforces ManagementURL only; user request touches both the
	// enforced field AND a non-enforced field (RosenpassEnabled).
	// The whole request must be rejected — non-conflicting fields are not
	// applied either.
	s, ctx, profName, username, cfgPath := setupServerWithProfile(t)
	withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL: "https://mdm.example.com:443",
	}))

	rosenpassEnabled := true
	_, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:      profName,
		Username:         username,
		ManagementUrl:    "https://user.tried.this.com:443",
		RosenpassEnabled: &rosenpassEnabled,
	})

	v := extractViolation(t, err)
	assert.Equal(t, []string{mdm.KeyManagementURL}, v.GetFields())

	// Confirm RosenpassEnabled was NOT applied even though it was not
	// in the conflict list: the request was rejected as a whole.
	reloaded, err := profilemanager.GetConfig(cfgPath)
	require.NoError(t, err)
	assert.False(t, reloaded.RosenpassEnabled, "non-conflicting field must not be applied when request is rejected")
}

func TestSetConfig_MDMAllow_NonManagedFields(t *testing.T) {
	// MDM enforces ManagementURL but the user only writes RosenpassEnabled.
	// Request must succeed.
	s, ctx, profName, username, _ := setupServerWithProfile(t)
	withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL: "https://mdm.example.com:443",
	}))

	rosenpassEnabled := true
	resp, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:      profName,
		Username:         username,
		RosenpassEnabled: &rosenpassEnabled,
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
}

// TestSetConfig_MDMAllow_ManagementURLPortNormalized covers the
// regression from discussion #6483: MDM URL without explicit port vs
// UI echo with the parseURL-appended default port must be treated as
// a no-op echo, not a conflict.
func TestSetConfig_MDMAllow_ManagementURLPortNormalized(t *testing.T) {
	tests := []struct {
		name      string
		mdmURL    string
		submitURL string
	}{
		{"policy_no_port_submit_with_443", "https://netbird.corp.example", "https://netbird.corp.example:443"},
		{"policy_with_443_submit_no_port", "https://netbird.corp.example:443", "https://netbird.corp.example"},
		{"http_policy_no_port_submit_with_80", "http://netbird.corp.example", "http://netbird.corp.example:80"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, ctx, profName, username, _ := setupServerWithProfile(t)
			withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{
				mdm.KeyManagementURL: tc.mdmURL,
			}))

			rosenpassEnabled := true
			resp, err := s.SetConfig(ctx, &proto.SetConfigRequest{
				ProfileName:      profName,
				Username:         username,
				ManagementUrl:    tc.submitURL,
				RosenpassEnabled: &rosenpassEnabled,
			})

			require.NoError(t, err, "port-normalized URL echo must not trip MDM conflict gate")
			require.NotNil(t, resp)
		})
	}
}

func TestSetConfig_MDMEmpty_NoEnforcement(t *testing.T) {
	// No MDM policy active: any field can be written.
	s, ctx, profName, username, _ := setupServerWithProfile(t)
	withMDMPolicy(t, s, mdm.NewPolicy(nil))

	resp, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:   profName,
		Username:      username,
		ManagementUrl: "https://user.changed.url.com:443",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
}
