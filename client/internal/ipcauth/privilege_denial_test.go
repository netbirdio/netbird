package ipcauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
)

// Every method names what it does, so a refusal can say what was refused rather
// than quoting a level at the user.
func TestPoliciesDeclareAnAction(t *testing.T) {
	for method, policy := range methodPolicies {
		assert.NotEmpty(t, policy.Action, "%s declares no Action, its refusals cannot name the operation", method)
	}
}

// A privileged method must also say how to satisfy it, since that is the one
// refusal the caller can act on.
func TestPrivilegedPoliciesDeclareGuidance(t *testing.T) {
	for method, policy := range methodPolicies {
		if policy.Level != AuthzLevelPrivileged {
			continue
		}
		assert.NotEmpty(t, policy.Command, "%s requires privilege but declares no Command", method)
	}
}

// Only privilege is something the caller can run their way out of. The other
// refusals explain and stop there.
func TestOnlyPrivilegedPoliciesDeclareACommand(t *testing.T) {
	for method, policy := range methodPolicies {
		if policy.Level == AuthzLevelPrivileged {
			continue
		}
		assert.Empty(t, policy.Command, "%s is not privileged but offers a command", method)
	}
}

func TestDenyPolicyLevelCarriesPrivilegeGuidance(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelIdentified,
		Method:   servicePath + "ClaimProfile",
	}

	err := denyPolicyLevel(req, methodPolicies[servicePath+"ClaimProfile"])
	require.Error(t, err)

	st := gstatus.Convert(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())

	var info *errdetails.ErrorInfo
	for _, d := range st.Details() {
		if got, ok := d.(*errdetails.ErrorInfo); ok {
			info = got
		}
	}
	require.NotNil(t, info, "a privilege refusal must be machine readable")
	assert.Equal(t, ErrorReasonPrivilegeRequired, info.GetReason())
	assert.Equal(t, ErrorDomain, info.GetDomain())
	assert.NotEmpty(t, info.GetMetadata()[ErrorMetaSummary])
	assert.NotEmpty(t, info.GetMetadata()[ErrorMetaCommand])
}

// A profile that belongs to somebody else is explained, not answered with sudo.
func TestDenyPolicyLevelExplainsAProfileOwnedByAnother(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelIdentified,
		Method:   servicePath + "SetConfig",
		State:    stubState{},
	}

	info := denialDetail(t, denyPolicyLevel(req, methodPolicies[servicePath+"SetConfig"]))
	assert.Equal(t, ErrorReasonNotProfileOwner, info.GetReason())
	assert.Contains(t, info.GetMetadata()[ErrorMetaSummary], "belongs to another user")

	_, hasCommand := info.GetMetadata()[ErrorMetaCommand]
	assert.False(t, hasCommand, "privilege is not what the method asked for")
}

// A privileged method that declares nothing still refuses, it just cannot say
// how to satisfy it. This is the methodPolicyFor fallback for an unknown RPC.
func TestDenyPolicyLevelWithoutGuidanceStaysBare(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelIdentified,
		Method:   servicePath + "NotARealMethod",
	}

	err := denyPolicyLevel(req, methodPolicyFor(req.Method))
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, gstatus.Convert(err).Code())
	assert.Empty(t, gstatus.Convert(err).Details())
}

// stubState stands in for the daemon so a denial can be built without a server.
type stubState struct {
	holder  Principal
	running bool
}

func (s stubState) SessionHolder() (Principal, bool)  { return s.holder, s.running }
func (s stubState) OwnsProfile(Identity, string) bool { return true }

// A refusal caused by somebody else's connection explains itself and offers no
// command, since the caller cannot end a session that is not theirs.
func TestDenyPolicyLevelExplainsAHeldSession(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelProfileOwner,
		Method:   servicePath + "Up",
		State:    stubState{holder: Principal{Kind: KindUID, Value: "4242"}, running: true},
	}

	err := denyPolicyLevel(req, methodPolicies[servicePath+"Up"])
	require.Error(t, err)

	st := gstatus.Convert(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())

	var info *errdetails.ErrorInfo
	for _, d := range st.Details() {
		if got, ok := d.(*errdetails.ErrorInfo); ok {
			info = got
		}
	}
	require.NotNil(t, info)
	assert.Equal(t, ErrorReasonSessionHeld, info.GetReason())
	assert.Equal(t, ErrorDomain, info.GetDomain())

	summary := info.GetMetadata()[ErrorMetaSummary]
	assert.Contains(t, summary, "Connecting", "the summary names what was refused")
	assert.Contains(t, summary, "another user")
	assert.NotContains(t, summary, "4242", "who holds it is not the caller's business")

	_, hasCommand := info.GetMetadata()[ErrorMetaCommand]
	assert.False(t, hasCommand, "there is no command that ends somebody else's session")
	assert.NotContains(t, st.Message(), "sudo")
}

// With no session running, a caller short of session holder fell short on
// ownership instead, and the refusal says so rather than blaming a session.
func TestDenyPolicyLevelWithNoSessionBlamesOwnership(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelIdentified,
		Method:   servicePath + "Up",
		State:    stubState{},
	}

	info := denialDetail(t, denyPolicyLevel(req, methodPolicies[servicePath+"Up"]))
	assert.Equal(t, ErrorReasonNotProfileOwner, info.GetReason())
	assert.NotContains(t, info.GetMetadata()[ErrorMetaSummary], "connected")
}

// A method with no Action still refuses, it just cannot name the operation.
func TestSessionHeldSummaryWithoutAnAction(t *testing.T) {
	assert.Contains(t, sessionHeldSummary(""), "This command is refused")
	assert.Contains(t, sessionHeldSummary("connecting"), "Connecting is refused")
}

// denialDetail pulls the machine readable half out of a refusal.
func denialDetail(t *testing.T, err error) *errdetails.ErrorInfo {
	t.Helper()
	require.Error(t, err)

	st := gstatus.Convert(err)
	require.Equal(t, codes.PermissionDenied, st.Code())

	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			require.Equal(t, ErrorDomain, info.GetDomain())
			return info
		}
	}
	t.Fatal("refusal carries no ErrorInfo detail")
	return nil
}
