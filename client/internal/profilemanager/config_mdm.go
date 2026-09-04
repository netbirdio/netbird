package profilemanager

import (
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/client/mdm"
)

// ErrMDMManagedFields marks a config change rejected because it diverges from
// MDM-enforced values.
var ErrMDMManagedFields = errors.New("fields managed by MDM cannot be modified")

// MDMConflicts returns the names of MDM-managed keys whose requested value in
// the ConfigInput differs from the policy-enforced value; a field set to the
// enforced value is a no-op echo, not a conflict.
func MDMConflicts(input ConfigInput, policy *mdm.Policy) []string {
	pskGot := input.PreSharedKey
	if isPreSharedKeyHidden(pskGot) {
		pskGot = nil
	}
	var port *int64
	if input.WireguardPort != nil {
		v := int64(*input.WireguardPort)
		port = &v
	}
	return mdm.ResolveConflicts(policy, []mdm.ConflictCheck{
		mdm.ConflictURL(mdm.KeyManagementURL, input.ManagementURL),
		mdm.ConflictStringPtr(mdm.KeyPreSharedKey, pskGot),
		mdm.ConflictBool(mdm.KeyRosenpassEnabled, input.RosenpassEnabled),
		mdm.ConflictBool(mdm.KeyRosenpassPermissive, input.RosenpassPermissive),
		mdm.ConflictBool(mdm.KeyDisableAutoConnect, input.DisableAutoConnect),
		mdm.ConflictBool(mdm.KeyAllowServerSSH, input.ServerSSHAllowed),
		mdm.ConflictBool(mdm.KeyDisableClientRoutes, input.DisableClientRoutes),
		mdm.ConflictBool(mdm.KeyDisableServerRoutes, input.DisableServerRoutes),
		mdm.ConflictBool(mdm.KeyBlockInbound, input.BlockInbound),
		mdm.ConflictInt64(mdm.KeyWireguardPort, port),
	})
}

// CheckMDMConflicts returns an ErrMDMManagedFields-wrapped error naming the
// conflicting keys, or nil when the input does not fight the policy.
func CheckMDMConflicts(input ConfigInput, policy *mdm.Policy) error {
	conflicts := MDMConflicts(input, policy)
	if len(conflicts) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrMDMManagedFields, conflicts)
}
