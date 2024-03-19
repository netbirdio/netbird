package routemanager

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/iface"
)

type dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func createWGInterface(t *testing.T, interfaceName, ipAddressCIDR string, listenPort int) *iface.WGIface {
	t.Helper()

	peerPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	newNet, err := stdnet.NewNet(nil)
	require.NoError(t, err)

	wgInterface, err := iface.NewWGIFace(interfaceName, ipAddressCIDR, listenPort, peerPrivateKey.String(), iface.DefaultMTU, newNet, nil)
	require.NoError(t, err, "should create testing WireGuard interface")

	err = wgInterface.Create()
	require.NoError(t, err, "should create testing WireGuard interface")

	t.Cleanup(func() {
		wgInterface.Close()
	})

	return wgInterface
}

func setupTestEnv(t *testing.T) {
	t.Helper()

	setupDummyInterfacesAndRoutes(t)

	wgIface := createWGInterface(t, "wgtest0", "100.64.0.1/24", 51820)
	t.Cleanup(func() {
		assert.NoError(t, wgIface.Close())
	})

	_, _, err := setupRouting(nil, wgIface)
	require.NoError(t, err, "setupRouting should not return err")
	t.Cleanup(func() {
		assert.NoError(t, cleanupRouting())
	})

	// default route exists in main table and vpn table
	err = addToRouteTableIfNoExists(netip.MustParsePrefix("0.0.0.0/0"), wgIface.Address().IP.String(), wgIface.Name())
	require.NoError(t, err, "addToRouteTableIfNoExists should not return err")

	// 10.0.0.0/8 route exists in main table and vpn table
	err = addToRouteTableIfNoExists(netip.MustParsePrefix("10.0.0.0/8"), wgIface.Address().IP.String(), wgIface.Name())
	require.NoError(t, err, "addToRouteTableIfNoExists should not return err")

	// 10.10.0.0/24 more specific route exists in vpn table
	err = addToRouteTableIfNoExists(netip.MustParsePrefix("10.10.0.0/24"), wgIface.Address().IP.String(), wgIface.Name())
	require.NoError(t, err, "addToRouteTableIfNoExists should not return err")

	// 127.0.10.0/24 more specific route exists in vpn table
	err = addToRouteTableIfNoExists(netip.MustParsePrefix("127.0.10.0/24"), wgIface.Address().IP.String(), wgIface.Name())
	require.NoError(t, err, "addToRouteTableIfNoExists should not return err")

	// unique route in vpn table
	err = addToRouteTableIfNoExists(netip.MustParsePrefix("172.16.0.0/12"), wgIface.Address().IP.String(), wgIface.Name())
	require.NoError(t, err, "addToRouteTableIfNoExists should not return err")
}
