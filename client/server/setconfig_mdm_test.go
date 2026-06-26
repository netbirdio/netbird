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

// withMDMPolicy temporarily overrides the server-package loadMDMPolicy hook
// so SetConfig observes the supplied Policy. Restores the original loader
// at test cleanup.
func withMDMPolicy(t *testing.T, policy *mdm.Policy) {
	t.Helper()
	prev := loadMDMPolicy
	loadMDMPolicy = func() *mdm.Policy { return policy }
	t.Cleanup(func() { loadMDMPolicy = prev })
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

	ctx = context.Background()
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
	withMDMPolicy(t, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL: "https://mdm.example.com:443",
	}))

	s, ctx, profName, username, _ := setupServerWithProfile(t)

	_, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:   profName,
		Username:      username,
		ManagementUrl: "https://user.tried.this.com:443",
	})

	v := extractViolation(t, err)
	assert.Equal(t, []string{mdm.KeyManagementURL}, v.GetFields())
}

func TestSetConfig_MDMReject_MultipleFields(t *testing.T) {
	withMDMPolicy(t, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL:    "https://mdm.example.com:443",
		mdm.KeyBlockInbound:     true,
		mdm.KeyRosenpassEnabled: true,
	}))

	s, ctx, profName, username, _ := setupServerWithProfile(t)

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
	withMDMPolicy(t, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL: "https://mdm.example.com:443",
	}))

	s, ctx, profName, username, cfgPath := setupServerWithProfile(t)

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
	withMDMPolicy(t, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL: "https://mdm.example.com:443",
	}))

	s, ctx, profName, username, _ := setupServerWithProfile(t)

	rosenpassEnabled := true
	resp, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:      profName,
		Username:         username,
		RosenpassEnabled: &rosenpassEnabled,
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestSetConfig_MDMEmpty_NoEnforcement(t *testing.T) {
	// No MDM policy active: any field can be written.
	withMDMPolicy(t, mdm.NewPolicy(nil))

	s, ctx, profName, username, _ := setupServerWithProfile(t)

	resp, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:   profName,
		Username:      username,
		ManagementUrl: "https://user.changed.url.com:443",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
}
