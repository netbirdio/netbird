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
	var mtu *int64
	if input.MTU != nil {
		v := int64(*input.MTU)
		mtu = &v
	}
	var sshJWTCacheTTL *int64
	if input.SSHJWTCacheTTL != nil {
		v := int64(*input.SSHJWTCacheTTL)
		sshJWTCacheTTL = &v
	}
	return mdm.ResolveConflicts(policy, []mdm.ConflictCheck{
		mdm.ConflictURL(mdm.KeyManagementURL, input.ManagementURL),
		mdm.ConflictStringPtr(mdm.KeyPreSharedKey, pskGot),
		mdm.ConflictBool(mdm.KeyRosenpassEnabled, input.RosenpassEnabled),
		mdm.ConflictBool(mdm.KeyRosenpassPermissive, input.RosenpassPermissive),
		mdm.ConflictBool(mdm.KeyDisableAutoConnect, input.DisableAutoConnect),
		mdm.ConflictBool(mdm.KeyAllowServerSSH, input.ServerSSHAllowed),
		mdm.ConflictBool(mdm.KeyRemoteJobsAllowed, input.RemoteJobsAllowed),
		mdm.ConflictBool(mdm.KeyDisableClientRoutes, input.DisableClientRoutes),
		mdm.ConflictBool(mdm.KeyDisableServerRoutes, input.DisableServerRoutes),
		mdm.ConflictBool(mdm.KeyBlockInbound, input.BlockInbound),
		mdm.ConflictInt64(mdm.KeyWireguardPort, port),
		mdm.ConflictBool(mdm.KeyEnableLocalMetrics, input.LocalMetricsEnabled),
		mdm.ConflictStringPtr(mdm.KeyLocalMetricsAddress, input.LocalMetricsAddress),
		mdm.ConflictBool(mdm.KeyDisableDNS, input.DisableDNS),
		mdm.ConflictBool(mdm.KeyDisableIPv6, input.DisableIPv6),
		mdm.ConflictBool(mdm.KeyForceRelay, input.ForceRelay),
		mdm.ConflictBool(mdm.KeyDisableFirewall, input.DisableFirewall),
		mdm.ConflictBool(mdm.KeyBlockLANAccess, input.BlockLANAccess),
		mdm.ConflictBool(mdm.KeyDisableNotifications, input.DisableNotifications),
		mdm.ConflictBool(mdm.KeyNetworkMonitor, input.NetworkMonitor),
		mdm.ConflictStringPtr(mdm.KeyInterfaceName, input.InterfaceName),
		mdm.ConflictInt64(mdm.KeyMTU, mtu),
		mdm.ConflictDuration(mdm.KeyDNSRouteInterval, input.DNSRouteInterval),
		mdm.ConflictStringSlice(mdm.KeyNATExternalIPs, input.NATExternalIPs),
		mdm.ConflictBool(mdm.KeyEnableSSHRoot, input.EnableSSHRoot),
		mdm.ConflictBool(mdm.KeyEnableSSHSFTP, input.EnableSSHSFTP),
		mdm.ConflictBool(mdm.KeyEnableSSHLocalPortForwarding, input.EnableSSHLocalPortForwarding),
		mdm.ConflictBool(mdm.KeyEnableSSHRemotePortForwarding, input.EnableSSHRemotePortForwarding),
		mdm.ConflictBool(mdm.KeyDisableSSHAuth, input.DisableSSHAuth),
		mdm.ConflictInt64(mdm.KeySSHJWTCacheTTL, sshJWTCacheTTL),
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
