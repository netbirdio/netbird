package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
)

const otherManagementURL = "https://other-management.example.com:443"

// MDM overrides live in memory only, so the profile file can say the SSH server
// is off while the policy runs it. Repointing management hands SSH
// authorization to whoever controls the new server, so the gate must see the
// state the daemon actually runs with.
func TestSetConfig_ManagementURLChangeWhileMDMRunsSSHNeedsPrivilege(t *testing.T) {
	s, _, profName, username, cfgPath := setupServerWithProfile(t)
	withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{mdm.KeyAllowServerSSH: true}))
	require.Equal(t, false, readProfileFile(t, cfgPath)["ServerSSHAllowed"], "precondition: the file says SSH off")

	_, err := s.SetConfig(withTarget(userCtx(), cfgPath), &proto.SetConfigRequest{
		ProfileName:   profName,
		Username:      username,
		ManagementUrl: otherManagementURL,
	})
	require.Error(t, err, "repointing management while the SSH server runs needs privilege")

	assert.Equal(t, "https://api.netbird.io:443", managementURLOnDisk(t, cfgPath), "a refused URL must not be persisted")
}

func TestLoginGate_ManagementURLChangeWhileMDMRunsSSHNeedsPrivilege(t *testing.T) {
	s, _, profName, username, cfgPath := setupServerWithProfile(t)
	policy := mdm.NewPolicy(map[string]any{mdm.KeyAllowServerSSH: true})
	withMDMPolicy(t, s, policy)

	ctx := withTarget(userCtx(), cfgPath)
	msg := &proto.LoginRequest{ManagementUrl: otherManagementURL}
	activeProf := &profilemanager.ActiveProfileState{ID: profilemanager.ID(profName), Username: username}
	stored, err := s.storedLoginConfig(ctx, activeProf, msg)
	require.NoError(t, err)

	assert.Error(t, requirePrivilegeForConfigChange(ctx, stored, policy, privilegedChangeFromLogin(msg)),
		"a login repointing management while the SSH server runs needs privilege")
}

// Turning metrics on is harmless on the loopback address in the file, but not
// on the address the policy enforces.
func TestSetConfig_MetricsEnabledOnMDMAddressNeedsPrivilege(t *testing.T) {
	s, _, profName, username, cfgPath := setupServerWithProfile(t)
	withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{mdm.KeyLocalMetricsAddress: "0.0.0.0:9090"}))

	_, err := s.SetConfig(withTarget(userCtx(), cfgPath), &proto.SetConfigRequest{
		ProfileName:        profName,
		Username:           username,
		EnableLocalMetrics: boolPtr(true),
	})
	require.Error(t, err, "exposing metrics on the enforced address needs privilege")

	assert.Equal(t, false, readProfileFile(t, cfgPath)["LocalMetricsEnabled"], "a refused value must not be persisted")
}

// The state seen by the gate is the file and the policy together: a policy
// turning the SSH server off does not lift the guard while the file runs it,
// since the guard would be gone for good once the policy is removed.
func TestSetConfig_ManagementURLChangeWhileFileRunsSSHNeedsPrivilege(t *testing.T) {
	s, adminCtx, profName, username, cfgPath := setupServerWithProfile(t)
	_, err := s.SetConfig(adminCtx, &proto.SetConfigRequest{
		ProfileName: profName, Username: username, ServerSSHAllowed: boolPtr(true),
	})
	require.NoError(t, err, "admin setup must succeed")
	withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{mdm.KeyAllowServerSSH: false}))

	_, err = s.SetConfig(withTarget(userCtx(), cfgPath), &proto.SetConfigRequest{
		ProfileName:   profName,
		Username:      username,
		ManagementUrl: otherManagementURL,
	})
	require.Error(t, err, "the file still runs the SSH server once the policy goes away")
}

func managementURLOnDisk(t *testing.T, path string) string {
	t.Helper()
	u, ok := readProfileFile(t, path)["ManagementURL"].(map[string]any)
	require.True(t, ok, "ManagementURL must be stored as a URL object")
	return u["Scheme"].(string) + "://" + u["Host"].(string)
}

// A profile with no config yet takes a new profile's defaults with the policy
// on top: when the policy runs the SSH server, the first login must not be free
// to pick the management that will decide who opens a shell here.
func TestRequirePrivilege_NewProfileWithMDMSSH(t *testing.T) {
	sshPolicy := mdm.NewPolicy(map[string]any{mdm.KeyAllowServerSSH: true})
	tests := []struct {
		name     string
		policy   *mdm.Policy
		ctx      func() context.Context
		url      string
		wantDeny bool
	}{
		{name: "a management URL while the policy runs SSH is refused", policy: sshPolicy, ctx: userCtx, url: otherManagementURL, wantDeny: true},
		{name: "root may pick the management URL", policy: sshPolicy, ctx: rootCtx, url: otherManagementURL},
		{name: "no management URL leaves nothing to guard", policy: sshPolicy, ctx: userCtx},
		{name: "without the policy SSH is off on a new profile", policy: nil, ctx: userCtx, url: otherManagementURL},
		{name: "a policy turning SSH off guards nothing", policy: mdm.NewPolicy(map[string]any{mdm.KeyAllowServerSSH: false}), ctx: userCtx, url: otherManagementURL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requirePrivilegeForConfigChange(tt.ctx(), nil, tt.policy, privilegedConfigChange{managementURL: tt.url})
			if tt.wantDeny {
				assertDenied(t, err)
				return
			}
			assertAllowed(t, err)
		})
	}
}
