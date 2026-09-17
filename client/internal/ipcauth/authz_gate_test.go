package ipcauth

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

// gateFor builds a gate over a stub daemon, with this process pinned to root so
// the unprivileged fixture caller is not mistaken for the daemon's own identity.
func gateFor(t *testing.T, st DaemonState) *AuthzGate {
	t.Helper()
	asDaemon(t, root)

	g := NewAuthzGate()
	g.SetState(st)
	return g
}

func switchTo(handle string) *proto.SwitchProfileRequest {
	if handle == "" {
		return &proto.SwitchProfileRequest{}
	}
	return &proto.SwitchProfileRequest{ProfileName: &handle}
}

// A handle that names no profile the caller can address is answered with what
// is wrong with the handle. The refusal about ownership would claim the profile
// exists and belongs to somebody, which a mistyped handle does not.
func TestAuthorizeSurfacesWhatIsWrongWithTheHandle(t *testing.T) {
	notFound := gstatus.Errorf(codes.NotFound, "profile %q not found", "asdfasdfasdf")
	g := gateFor(t, stubState{ownsErr: notFound})

	err := g.authorize(transportCtx(unprivUser, nil), servicePath+"SwitchProfile", switchTo("asdfasdfasdf"))
	require.Error(t, err)

	st := gstatus.Convert(err)
	assert.Equal(t, codes.NotFound, st.Code(), "a handle that resolves to nothing is not a permission problem")
	assert.Contains(t, st.Message(), `profile "asdfasdfasdf" not found`)

	_, isDenial := DenialFrom(err)
	assert.False(t, isDenial, "the ownership refusal took over an error about the handle")
}

// The candidate list an ambiguous handle produces is the whole value of that
// error, and the CLI reformats it into a hint. It has to reach the CLI.
func TestAuthorizeSurfacesAnAmbiguousHandle(t *testing.T) {
	ambiguous := gstatus.Errorf(codes.InvalidArgument, "handle %q matches 2 profiles", "ab")
	g := gateFor(t, stubState{ownsErr: ambiguous})

	err := g.authorize(transportCtx(unprivUser, nil), servicePath+"SwitchProfile", switchTo("ab"))
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, gstatus.Convert(err).Code())
}

// A method that names no profile acts on the active one, which the caller never
// typed. Reporting it as not found would quote back an ID they never gave, so
// the refusal stays about who the profile belongs to.
func TestAuthorizeBlamesOwnershipForTheActiveProfile(t *testing.T) {
	notFound := gstatus.Errorf(codes.NotFound, "profile %q not found", "active-profile-id")
	g := gateFor(t, stubState{ownsErr: notFound})

	err := g.authorize(transportCtx(unprivUser, nil), servicePath+"SwitchProfile", switchTo(""))
	require.Error(t, err)

	denial, ok := DenialFrom(err)
	require.True(t, ok, "an unnamed profile is refused on ownership, not on the handle")
	assert.Equal(t, ErrorReasonNotProfileOwner, denial.Reason)
	assert.NotContains(t, denial.Summary, "active-profile-id", "the caller never named a profile")
}

// A daemon-side failure is not something the caller can correct, and putting it
// on the wire would describe the daemon rather than the request.
func TestAuthorizeKeepsADaemonFailureOffTheWire(t *testing.T) {
	g := gateFor(t, stubState{ownsErr: errors.New("read profile directory: permission denied")})

	err := g.authorize(transportCtx(unprivUser, nil), servicePath+"SwitchProfile", switchTo("some-profile"))
	require.Error(t, err)

	denial, ok := DenialFrom(err)
	require.True(t, ok, "a daemon-side failure must still refuse in the gate's own words")
	assert.Equal(t, ErrorReasonNotProfileOwner, denial.Reason)
	assert.NotContains(t, denial.Summary, "permission denied")
}

// Resolving the active profile happens on every call, including the ones any
// identified caller may make. A failure there must not take those down.
func TestAuthorizeAllowsIdentifiedMethodsDespiteAResolveFailure(t *testing.T) {
	notFound := gstatus.Errorf(codes.NotFound, "profile %q not found", "active-profile-id")
	g := gateFor(t, stubState{ownsErr: notFound})

	for _, method := range []string{"ListProfiles", "AddProfile", "GetActiveProfile", "GetFeatures"} {
		t.Run(method, func(t *testing.T) {
			require.Equal(t, AuthzLevelIdentified, methodPolicies[servicePath+method].Level,
				"fixture is wrong: %s is no longer open to any identified caller", method)

			assert.NoError(t, g.authorize(transportCtx(unprivUser, nil), servicePath+method, nil))
		})
	}
}

// Ownership is the gate's answer, never the error's: a resolution that failed is
// a no whatever it returned alongside.
func TestAuthorizeRefusesWhenResolutionFails(t *testing.T) {
	g := gateFor(t, stubState{owns: true, ownsErr: gstatus.Error(codes.NotFound, "profile not found")})

	err := g.authorize(transportCtx(unprivUser, nil), servicePath+"SwitchProfile", switchTo("some-profile"))
	assert.Error(t, err, "an error from the resolution cannot be read as ownership")
}
