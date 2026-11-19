package mdm

import (
	"encoding/json"
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

func TestBuildRestrictions_NetworkKeys(t *testing.T) {
	// A key counts as managed whatever its value: the UI must lock the toggle
	// even when the policy enforces false.
	raw, err := BuildRestrictions(NewPolicy(map[string]any{
		KeyInterfaceName:        "utun100",
		KeyMTU:                  int64(1280),
		KeyDisableDNS:           false,
		KeyDisableIPv6:          true,
		KeyDisableFirewall:      true,
		KeyBlockLANAccess:       true,
		KeyDisableNotifications: true,
		KeyNetworkMonitor:       false,
	})).JSON()
	require.NoError(t, err)

	var got struct {
		MDM map[string]any `json:"mdm"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &got))
	for _, key := range []string{
		KeyInterfaceName, KeyMTU, KeyDisableDNS, KeyDisableIPv6, KeyDisableFirewall,
		KeyBlockLANAccess, KeyDisableNotifications, KeyNetworkMonitor,
	} {
		assert.Equal(t, true, got.MDM[key], "%s must be reported as managed under its policy key name", key)
	}
}

func TestBuildRestrictions_NetworkKeysUnmanaged(t *testing.T) {
	r := BuildRestrictions(NewPolicy(map[string]any{KeyBlockInbound: true}))

	assert.False(t, r.MDM.DisableDNS, "an unmanaged key must leave its toggle editable")
	assert.False(t, r.MDM.MTU, "an unmanaged key must leave its field editable")
}

func TestBuildRestrictions_SSHKeys(t *testing.T) {
	r := BuildRestrictions(NewPolicy(map[string]any{
		KeyEnableSSHRoot:                 false,
		KeyEnableSSHSFTP:                 true,
		KeyEnableSSHLocalPortForwarding:  true,
		KeyEnableSSHRemotePortForwarding: false,
		KeyDisableSSHAuth:                false,
		KeySSHJWTCacheTTL:                int64(0),
	}))

	assert.True(t, r.MDM.EnableSSHRoot, "managed whatever its value")
	assert.True(t, r.MDM.EnableSSHSFTP, "enableSSHSFTP")
	assert.True(t, r.MDM.EnableSSHLocalPortForwarding, "enableSSHLocalPortForwarding")
	assert.True(t, r.MDM.EnableSSHRemotePortForwarding, "enableSSHRemotePortForwarding")
	assert.True(t, r.MDM.DisableSSHAuth, "disableSSHAuth")
	assert.True(t, r.MDM.SSHJWTCacheTTL, "sshJWTCacheTTL")
}

func TestBuildRestrictions_KeepConnectedOnQuit(t *testing.T) {
	r := BuildRestrictions(NewPolicy(map[string]any{KeyKeepConnectedOnQuit: false}))
	assert.True(t, r.MDM.KeepConnectedOnQuit, "managed whatever its value")
	assert.False(t, BuildRestrictions(NewPolicy(map[string]any{KeyMTU: int64(1300)})).MDM.KeepConnectedOnQuit, "not managed when absent")
}

func TestBuildRestrictions_ForceRelay(t *testing.T) {
	assert.True(t, BuildRestrictions(NewPolicy(map[string]any{KeyForceRelay: false})).MDM.ForceRelay, "managed whatever its value")
	assert.False(t, BuildRestrictions(NewPolicy(map[string]any{KeyMTU: int64(1300)})).MDM.ForceRelay, "not managed when absent")
}
