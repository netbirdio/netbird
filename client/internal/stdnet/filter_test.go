package stdnet

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestInterfaceFilterBridgeNames checks that only the bridge names Docker generates
// are excluded from ICE candidate gathering, and that OpenWrt's br-lan, br-wan and
// br-guest stay available, including when an older client persisted a bare "br-"
// entry into its disallow list.
func TestInterfaceFilterBridgeNames(t *testing.T) {
	if runtime.GOOS == "ios" {
		t.Skip("the disallow list is not applied on iOS")
	}

	plainDetector, _ := newCountingDetector(t, time.Minute, false)

	// DefaultInterfaceBlacklist no longer carries a bare "br-", but a client installed
	// before that change has it persisted in its config, so the filter still sees it.
	filter := InterfaceFilter([]string{"br-", "docker", "veth"}, plainDetector)

	for _, tc := range []struct {
		iFace   string
		allowed bool
		why     string
	}{
		{"br-lan", true, "OpenWrt names its LAN bridge br-lan"},
		{"br-wan", true, "OpenWrt names its WAN bridge br-wan"},
		{"br-guest", true, "OpenWrt names its guest bridge br-guest"},
		{"br-1a2b3c4d5e6f", false, "docker derives this name from a network id"},
		{"br-0123456789ab", false, "docker derives this name from a network id"},
		{"br-1a2b3c", true, "too short to be a docker network id"},
		{"br-1a2b3c4d5e6g", true, "not hex, so not a docker network id"},
		{"docker0", false, "the docker entry still applies"},
		{"veth7f3a", false, "the veth entry still applies"},
	} {
		assert.Equal(t, tc.allowed, filter(tc.iFace), "%s: %s", tc.iFace, tc.why)
	}
}
