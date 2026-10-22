//go:build !ios && !android

package networkmonitor

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func TestDefaultInterfaceAddrs(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no loopback interface named lo on this host")
	}
	// Loopback addresses are not underlay addresses and must be dropped.
	assert.Empty(t, defaultInterfaceAddrs(systemops.Nexthop{Intf: lo}), "loopback addresses are skipped")
	assert.Empty(t, defaultInterfaceAddrs(systemops.Nexthop{}), "a family without a default contributes nothing")
}
