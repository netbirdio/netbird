package nftables

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall"
)

func TestNftablesManager(t *testing.T) {
	// just check on the local interface
	manager, err := Create("lo")
	require.NoError(t, err)

	ip := net.ParseIP("100.96.0.1")

	rule, err := manager.AddFiltering(
		ip,
		fw.ProtocolTCP,
		&fw.Port{Values: []int{53}},
		fw.DirectionSrc,
		fw.ActionDrop,
		"",
	)
	require.NoError(t, err, "failed to add rule")

	err = manager.DeleteRule(rule)
	require.NoError(t, err, "failed to delete rule")

	err = manager.Reset()
	require.NoError(t, err, "failed to reset")
}
