package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

func TestRunningConfigFromProfileMatchesConfigResponse(t *testing.T) {
	enabled := true
	cfg := &profilemanager.Config{
		WgIface:                      "wt7",
		WgPort:                       51830,
		MTU:                          1380,
		NetworkMonitor:               &enabled,
		DisableDNS:                   true,
		DisableClientRoutes:          true,
		DisableIPv6:                  true,
		BlockLANAccess:               true,
		RosenpassEnabled:             true,
		EnableSSHSFTP:                &enabled,
		EnableSSHLocalPortForwarding: &enabled,
		ServerVNCAllowed:             &enabled,
	}

	running := runningConfigFromProfile(cfg)
	stored := configResponseFromProfile(cfg)

	require.NotNil(t, running)
	assert.Equal(t, &proto.RunningConfig{
		InterfaceName:                 stored.GetInterfaceName(),
		WireguardPort:                 stored.GetWireguardPort(),
		Mtu:                           stored.GetMtu(),
		NetworkMonitor:                stored.GetNetworkMonitor(),
		DisableDns:                    stored.GetDisableDns(),
		DisableClientRoutes:           stored.GetDisableClientRoutes(),
		DisableServerRoutes:           stored.GetDisableServerRoutes(),
		DisableIpv6:                   stored.GetDisableIpv6(),
		BlockInbound:                  stored.GetBlockInbound(),
		BlockLanAccess:                stored.GetBlockLanAccess(),
		RosenpassEnabled:              stored.GetRosenpassEnabled(),
		RosenpassPermissive:           stored.GetRosenpassPermissive(),
		ServerSSHAllowed:              stored.GetServerSSHAllowed(),
		EnableSSHRoot:                 stored.GetEnableSSHRoot(),
		EnableSSHSFTP:                 stored.GetEnableSSHSFTP(),
		EnableSSHLocalPortForwarding:  stored.GetEnableSSHLocalPortForwarding(),
		EnableSSHRemotePortForwarding: stored.GetEnableSSHRemotePortForwarding(),
		DisableSSHAuth:                stored.GetDisableSSHAuth(),
		ServerVNCAllowed:              stored.GetServerVNCAllowed(),
		DisableVNCApproval:            stored.GetDisableVNCApproval(),
	}, running, "running config should mirror the stored config response field by field")

	assert.Equal(t, "wt7", running.GetInterfaceName(), "interface name should come from the profile")
	assert.Equal(t, int64(51830), running.GetWireguardPort(), "configured port should be reported, not the bound one")
	assert.Equal(t, int64(1380), running.GetMtu(), "configured MTU should be reported")
	assert.True(t, running.GetDisableClientRoutes(), "disabled client routes should be reported")
	assert.True(t, running.GetServerSSHAllowed(), "unset SSH server flag should default to allowed")
}

func TestRunningEngineConfigWithoutEngine(t *testing.T) {
	s := &Server{}

	clientRoutesDisabled, running := s.runningEngineConfig()

	assert.Nil(t, clientRoutesDisabled, "client routes state should be unset without a running engine")
	assert.Nil(t, running, "running config should be unset without a running engine")
}
