package server

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
)

// readProfileFile returns the profile as written on disk, without the MDM
// overlay that every config loader applies on read.
func readProfileFile(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// A request value that matches the MDM-enforced one is handled as if no policy
// were in place: it passes the MDM gate, goes through the usual gates, and is
// persisted the way it would be without MDM.
func TestSetConfig_ValueMatchingMDMIsHandledAsWithoutMDM(t *testing.T) {
	s, ctx, profName, username, cfgPath := setupServerWithProfile(t)
	withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{mdm.KeyMTU: int64(1300)}))

	mtu := int64(1300)
	_, err := s.SetConfig(ctx, &proto.SetConfigRequest{ProfileName: profName, Username: username, Mtu: &mtu})
	require.NoError(t, err, "a value matching the policy must pass the MDM gate")

	assert.Equal(t, float64(1300), readProfileFile(t, cfgPath)["MTU"], "it is persisted as it would be without MDM")
}

func TestSetConfig_ValueDifferingFromMDMIsRefused(t *testing.T) {
	s, ctx, profName, username, cfgPath := setupServerWithProfile(t)
	withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{mdm.KeyMTU: int64(1300)}))
	before := readProfileFile(t, cfgPath)["MTU"]

	mtu := int64(1240)
	_, err := s.SetConfig(ctx, &proto.SetConfigRequest{ProfileName: profName, Username: username, Mtu: &mtu})
	require.Error(t, err, "a value differing from the policy must be refused")

	assert.Equal(t, before, readProfileFile(t, cfgPath)["MTU"], "a refused value must not be persisted")
}

// The usual gates still apply to a matching value: an unprivileged caller
// cannot turn on the SSH server, whatever the policy enforces.
func TestSetConfig_ValueMatchingMDMStillNeedsPrivilege(t *testing.T) {
	s, _, profName, username, cfgPath := setupServerWithProfile(t)
	withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{mdm.KeyAllowServerSSH: true}))

	_, err := s.SetConfig(withTarget(userCtx(), cfgPath), &proto.SetConfigRequest{
		ProfileName:      profName,
		Username:         username,
		ServerSSHAllowed: boolPtr(true),
	})
	assertDenied(t, err)

	assert.Equal(t, false, readProfileFile(t, cfgPath)["ServerSSHAllowed"], "a refused value must not be persisted")
}

// Root login and unauthenticated SSH stay privileged changes when the policy
// enforces them: matching the policy does not make an unprivileged caller
// entitled to persist them.
func TestSetConfig_PrivilegedSSHValueMatchingMDMStillNeedsPrivilege(t *testing.T) {
	for _, tc := range []struct {
		key string
		set func(*proto.SetConfigRequest)
	}{
		{mdm.KeyEnableSSHRoot, func(r *proto.SetConfigRequest) { r.EnableSSHRoot = boolPtr(true) }},
		{mdm.KeyDisableSSHAuth, func(r *proto.SetConfigRequest) { r.DisableSSHAuth = boolPtr(true) }},
	} {
		t.Run(tc.key, func(t *testing.T) {
			s, _, profName, username, cfgPath := setupServerWithProfile(t)
			withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{tc.key: true}))

			req := &proto.SetConfigRequest{ProfileName: profName, Username: username}
			tc.set(req)
			_, err := s.SetConfig(withTarget(userCtx(), cfgPath), req)
			assertDenied(t, err)
		})
	}
}
