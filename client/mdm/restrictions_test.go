package mdm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every key the UI can be told about has to be mapped here. A field left out
// reports the key as unmanaged, so the desktop and mobile UIs offer a control
// the policy actually enforces, and the user's change is silently overridden.
func TestBuildRestrictions_MapsRemoteAccessKeys(t *testing.T) {
	policy := NewPolicy(map[string]any{
		KeyAllowServerSSH:     true,
		KeyAllowServerVNC:     true,
		KeyDisableVNCApproval: true,
		KeyRemoteJobsAllowed:  true,
	})

	r := BuildRestrictions(policy)

	require.NotNil(t, r.MDM.AllowServerSSH, "allowServerSSH must be reported as managed")
	assert.True(t, *r.MDM.AllowServerSSH)
	require.NotNil(t, r.MDM.AllowServerVNC, "allowServerVNC must be reported as managed")
	assert.True(t, *r.MDM.AllowServerVNC)
	assert.True(t, r.MDM.DisableVNCApproval, "disableVNCApproval must be reported as managed")
	assert.True(t, r.MDM.RemoteJobsAllowed)
}

// An unmanaged key stays nil/false so the UI leaves the control editable.
func TestBuildRestrictions_UnmanagedVNCKeys(t *testing.T) {
	r := BuildRestrictions(NewPolicy(map[string]any{KeyAllowServerSSH: false}))

	assert.Nil(t, r.MDM.AllowServerVNC, "an unset allowServerVNC must not read as managed")
	assert.False(t, r.MDM.DisableVNCApproval)
}
