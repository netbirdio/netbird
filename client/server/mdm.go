package server

import (
	"fmt"

	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
)

// loadMDMPolicy is the indirection used by server handlers to read the
// active MDM policy. Tests override this to inject a fake policy.
var loadMDMPolicy = mdm.LoadPolicy

// requestedMDMManagedKeys returns the names of MDM-managed keys whose
// corresponding field is set in the SetConfigRequest. Only keys with an
// MDM mapping are considered; other fields are ignored.
func requestedMDMManagedKeys(msg *proto.SetConfigRequest) []string {
	if msg == nil {
		return nil
	}
	var keys []string
	if msg.ManagementUrl != "" {
		keys = append(keys, mdm.KeyManagementURL)
	}
	if msg.OptionalPreSharedKey != nil {
		keys = append(keys, mdm.KeyPreSharedKey)
	}
	if msg.RosenpassEnabled != nil {
		keys = append(keys, mdm.KeyRosenpassEnabled)
	}
	if msg.RosenpassPermissive != nil {
		keys = append(keys, mdm.KeyRosenpassPermissive)
	}
	if msg.DisableAutoConnect != nil {
		keys = append(keys, mdm.KeyDisableAutoConnect)
	}
	if msg.ServerSSHAllowed != nil {
		keys = append(keys, mdm.KeyAllowServerSSH)
	}
	if msg.DisableClientRoutes != nil {
		keys = append(keys, mdm.KeyDisableClientRoutes)
	}
	if msg.DisableServerRoutes != nil {
		keys = append(keys, mdm.KeyDisableServerRoutes)
	}
	if msg.BlockInbound != nil {
		keys = append(keys, mdm.KeyBlockInbound)
	}
	if msg.WireguardPort != nil {
		keys = append(keys, mdm.KeyWireguardPort)
	}
	return keys
}

// rejectMDMManagedFieldConflicts returns a FailedPrecondition gRPC error
// with an MDMManagedFieldsViolation detail when any of the requested keys
// is MDM-enforced, and nil otherwise. The whole request is rejected on
// any conflict; non-conflicting fields in the same request are not
// applied either (no partial apply).
func rejectMDMManagedFieldConflicts(policy *mdm.Policy, requested []string) error {
	if policy.IsEmpty() || len(requested) == 0 {
		return nil
	}
	var conflicts []string
	for _, k := range requested {
		if policy.HasKey(k) {
			conflicts = append(conflicts, k)
		}
	}
	if len(conflicts) == 0 {
		return nil
	}
	st := gstatus.New(
		codes.FailedPrecondition,
		fmt.Sprintf("fields managed by MDM cannot be modified: %v", conflicts),
	)
	detailed, err := st.WithDetails(&proto.MDMManagedFieldsViolation{Fields: conflicts})
	if err != nil {
		// Detail attachment is best-effort; fall back to the plain status
		// so the caller still gets a usable FailedPrecondition.
		return st.Err()
	}
	return detailed.Err()
}
