package internal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/client/netevents"
)

// The desktop client gets a netevents manager only when the network change
// handling will use it. Otherwise every component must see nil and keep the
// behavior it had before, such as the relay's fixed reconnect delay, so the
// environment switch really restores the old client.
func TestNetEventsFor(t *testing.T) {
	mgr := netevents.NewManager(peer.NewRecorder(""))
	on, off := true, false
	used := nbnet.AdvancedRouting()

	tests := []struct {
		name    string
		monitor *bool
		envOff  string
		want    bool
	}{
		{name: "monitor on", monitor: &on, want: used},
		{name: "monitor off", monitor: &off, want: false},
		{name: "monitor unset", monitor: nil, want: false},
		{name: "monitor on, redial disabled by env", monitor: &on, envOff: "true", want: false},
		{name: "monitor on, env set to false", monitor: &on, envOff: "false", want: used},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvDisableNetworkChangeRedial, tt.envOff)
			if tt.envOff == "" {
				os.Unsetenv(EnvDisableNetworkChangeRedial)
			}
			got := NetEventsFor(&profilemanager.Config{NetworkMonitor: tt.monitor}, mgr)
			if tt.want {
				assert.Same(t, mgr, got, "the manager must be handed over")
			} else {
				assert.Nil(t, got, "no manager: components keep their behavior without network events")
			}
		})
	}
}
