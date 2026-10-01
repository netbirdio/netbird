package device

import (
	"testing"

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
