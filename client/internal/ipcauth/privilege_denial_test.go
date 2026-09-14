package ipcauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
)

// A privileged method must declare how to satisfy it. Without that the caller
// gets a bare refusal and no way to know they should run it elevated.
func TestPrivilegedPoliciesDeclareGuidance(t *testing.T) {
	for method, policy := range methodPolicies {
		if policy.Level != AuthzLevelPrivileged {
			continue
		}
		assert.NotEmpty(t, policy.Action, "%s requires privilege but declares no Action", method)
		assert.NotEmpty(t, policy.Command, "%s requires privilege but declares no Command", method)
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

// Every other level denies as before. Only privilege is something the caller can
// act on, so only privilege carries a command.
func TestDenyPolicyLevelLeavesOtherLevelsBare(t *testing.T) {
	req := Request{
		Identity: KnownForTest(Identity{UID: 1000}),
		Level:    AuthzLevelIdentified,
		Method:   servicePath + "SetConfig",
	}

	err := denyPolicyLevel(req, methodPolicies[servicePath+"SetConfig"])
	require.Error(t, err)

	st := gstatus.Convert(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Empty(t, st.Details(), "a level the caller cannot elevate into needs no guidance")
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
