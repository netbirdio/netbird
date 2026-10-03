package device

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

func TestNewNetstackDevice(t *testing.T) {
	privateKey, _ := wgtypes.GeneratePrivateKey()
	wgAddress, _ := wgaddr.ParseWGAddress("1.2.3.4/24")

	relayBind := bind.NewRelayBindJS()
	nsTun := NewNetstackDevice("wtx", wgAddress, 1234, privateKey.String(), 1500, relayBind, netstack.ListenAddr())

	cfgr, err := nsTun.Create()
	if err != nil {
		t.Fatalf("failed to create netstack device: %v", err)
	}
	if cfgr == nil {
		t.Fatal("expected non-nil configurer")
	}
}

// TestNetstackDevice_UpWithRelayBind brings a netstack device up on a
// RelayBindJS, the bind the WASM client uses, and closes it again. The bind
// embeds a StdNetBind it never opens, so every method the Device calls on it
// through that embedding, before and after Open, has to run on a live receiver.
func TestNetstackDevice_UpWithRelayBind(t *testing.T) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	wgAddress, err := wgaddr.ParseWGAddress("1.2.3.4/24")
	require.NoError(t, err)

	nsTun := NewNetstackDevice("wtx", wgAddress, 1234, privateKey.String(), 1500, bind.NewRelayBindJS(), netstack.ListenAddr())
	_, err = nsTun.Create()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, nsTun.Close()) })

	_, err = nsTun.Up()
	require.NoError(t, err)
}
