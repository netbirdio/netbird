package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

func TestRunningConfigFromProfileCarriesProfileValues(t *testing.T) {
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

	require.NotNil(t, running)
	assert.Equal(t, &proto.RunningConfig{
		InterfaceName:                "wt7",
		WireguardPort:                51830,
		Mtu:                          1380,
		NetworkMonitor:               true,
		DisableDns:                   true,
		DisableClientRoutes:          true,
		DisableIpv6:                  true,
		BlockLanAccess:               true,
		RosenpassEnabled:             true,
		ServerSSHAllowed:             true,
		EnableSSHSFTP:                true,
		EnableSSHLocalPortForwarding: true,
		ServerVNCAllowed:             true,
	}, running, "running config should carry the profile values")

	stored := configResponseFromProfile(cfg)
	assert.Equal(t, stored.GetDisableClientRoutes(), running.GetDisableClientRoutes(), "running and stored mapping should agree")
	assert.Equal(t, stored.GetServerSSHAllowed(), running.GetServerSSHAllowed(), "running and stored mapping should agree on defaults")

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
