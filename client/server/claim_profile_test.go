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
	"github.com/netbirdio/netbird/client/proto"
)

// claimTestServer points the profile manager at a temp dir holding one default
// profile, which is the profile a claim exists to settle.
func claimTestServer(t *testing.T) *Server {
	t.Helper()

	origDir, origPath, origActive := profilemanager.DefaultConfigPathDir, profilemanager.DefaultConfigPath, profilemanager.ActiveProfileStatePath
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDir
		profilemanager.DefaultConfigPath = origPath
		profilemanager.ActiveProfileStatePath = origActive
	})

	dir := t.TempDir()
	profilemanager.DefaultConfigPathDir = dir
	profilemanager.DefaultConfigPath = filepath.Join(dir, "default.json")
	profilemanager.ActiveProfileStatePath = filepath.Join(dir, "active_profile.json")

	sm := profilemanager.NewServiceManager("")
	require.NoError(t, sm.CreateDefaultProfile())

	srv := newTestServer()
	srv.profileManager = sm
	return srv
}

func TestClaimProfile_RecordsTheOwner(t *testing.T) {
	srv := claimTestServer(t)

	resp, err := srv.ClaimProfile(rootCtx(), &proto.ClaimProfileRequest{
		Handle: "default",
		Owner:  "uid:4242",
	})
	require.NoError(t, err)
	assert.Equal(t, "default", resp.GetId())
	assert.Equal(t, "uid:4242", resp.GetOwner())

	list, err := srv.ListProfiles(rootCtx(), &proto.ListProfilesRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetProfiles(), 1)
	assert.Equal(t, []string{"uid:4242"}, list.GetProfiles()[0].GetOwners(),
		"the listing has to show the owner, it is the only way to confirm a claim")
}

// The owner is not looked up, so a claim lands on a machine whose accounts do
// not exist yet. Only its shape is checked.
func TestClaimProfile_RejectsWhatWouldMatchNobody(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner string
	}{
		{"unparseable uid", "uid:abc"},
		{"unknown kind", "bogus:1000"},
		{"malformed sid", "sid:hello"},
		{"bare number", "1000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := claimTestServer(t)

			_, err := srv.ClaimProfile(rootCtx(), &proto.ClaimProfileRequest{
				Handle: "default",
				Owner:  tc.owner,
			})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, gstatus.Convert(err).Code())

			list, err := srv.ListProfiles(rootCtx(), &proto.ListProfilesRequest{})
			require.NoError(t, err)
			assert.Empty(t, list.GetProfiles()[0].GetOwners(),
				"a refused claim must leave the profile as it was")
		})
	}
}

func TestClaimProfile_RequiresBothArguments(t *testing.T) {
	srv := claimTestServer(t)

	_, err := srv.ClaimProfile(rootCtx(), &proto.ClaimProfileRequest{Owner: "uid:4242"})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, gstatus.Convert(err).Code())

	_, err = srv.ClaimProfile(rootCtx(), &proto.ClaimProfileRequest{Handle: "default"})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, gstatus.Convert(err).Code())
}

func TestClaimProfile_RefusesAnUnknownProfile(t *testing.T) {
	srv := claimTestServer(t)

	_, err := srv.ClaimProfile(rootCtx(), &proto.ClaimProfileRequest{
		Handle: "no-such-profile",
		Owner:  "uid:4242",
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, gstatus.Convert(err).Code())
}

func TestClaimProfile_NeedsAnIdentifiedCaller(t *testing.T) {
	srv := claimTestServer(t)

	_, err := srv.ClaimProfile(context.Background(), &proto.ClaimProfileRequest{
		Handle: "default",
		Owner:  "uid:4242",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, gstatus.Convert(err).Code())
}

// A principal is taken as given. The account deliberately does not exist, which
// is the provisioning case: a machine-wide profile is configured before the
// account that will own it.
func TestClaimProfile_TakesAPrincipalWithoutResolvingIt(t *testing.T) {
	for _, owner := range []string{"uid:4242", "uid:999999"} {
		t.Run(owner, func(t *testing.T) {
			srv := claimTestServer(t)

			resp, err := srv.ClaimProfile(rootCtx(), &proto.ClaimProfileRequest{
				Handle: "default",
				Owner:  owner,
			})
			require.NoError(t, err, "a principal must never need an account lookup")
			assert.Equal(t, owner, resp.GetOwner())
		})
	}
}

func TestClaimProfile_ResolvesAnAccountName(t *testing.T) {
	srv := claimTestServer(t)

	u, err := user.Current()
	require.NoError(t, err)
	want, ok := profilemanager.PrincipalForUser(u)
	require.True(t, ok)

	resp, err := srv.ClaimProfile(rootCtx(), &proto.ClaimProfileRequest{
		Handle: "default",
		Owner:  u.Username,
	})
	require.NoError(t, err)
	assert.Equal(t, want, resp.GetOwner(),
		"a name has no shortcut, only a lookup turns it into a principal")
}

func TestClaimProfile_RefusesAnUnknownAccountName(t *testing.T) {
	srv := claimTestServer(t)

	_, err := srv.ClaimProfile(rootCtx(), &proto.ClaimProfileRequest{
		Handle: "default",
		Owner:  "no-such-account-here",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, gstatus.Convert(err).Code())
}
