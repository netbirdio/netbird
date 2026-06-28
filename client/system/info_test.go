package system

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func Test_LocalWTVersion(t *testing.T) {
	got := GetInfo(context.TODO())
	want := "development"
	assert.Equal(t, want, got.NetbirdVersion)
}

func Test_UIVersion(t *testing.T) {
	ctx := context.Background()
	want := "netbird-desktop-ui/development"
	ctx = metadata.NewOutgoingContext(ctx, map[string][]string{
		"user-agent": {want},
	})

	got := GetInfo(ctx)
	assert.Equal(t, want, got.UIVersion)
}

func Test_CustomHostname(t *testing.T) {
	// nolint
	ctx := context.WithValue(context.Background(), DeviceNameCtxKey, "custom-host")
	want := "custom-host"

	got := GetInfo(ctx)
	assert.Equal(t, want, got.Hostname)
}

func Test_NetAddresses(t *testing.T) {
	addr, err := networkAddresses()
	if err != nil {
		t.Errorf("failed to discover network addresses: %s", err)
	}
	if len(addr) == 0 {
		t.Errorf("no network addresses found")
	}
}

func TestInfo_RemoveAddresses(t *testing.T) {
	addr := func(cidr string) NetworkAddress {
		return NetworkAddress{NetIP: netip.MustParsePrefix(cidr)}
	}

	info := &Info{
		NetworkAddresses: []NetworkAddress{
			addr("192.168.1.7/24"),
			addr("100.76.70.97/32"),                          // overlay v4 (host mask /32)
			addr("2001:818:c51b:4800:845:a65d:ae6f:623f/64"), // real global v6
			addr("fd00:1234::1/64"),                          // overlay v6
		},
	}

	// Overlay addresses as the engine knows them, with a different mask (/16, /64).
	info.removeAddresses(
		netip.MustParseAddr("100.76.70.97"),
		netip.MustParseAddr("fd00:1234::1"),
	)

	want := []string{"192.168.1.7/24", "2001:818:c51b:4800:845:a65d:ae6f:623f/64"}
	if len(info.NetworkAddresses) != len(want) {
		t.Fatalf("got %d addresses, want %d: %v", len(info.NetworkAddresses), len(want), info.NetworkAddresses)
	}
	for i, w := range want {
		if got := info.NetworkAddresses[i].NetIP.String(); got != w {
			t.Errorf("address[%d] = %s, want %s", i, got, w)
		}
	}
}

func TestInfo_RemoveAddresses_NoOp(t *testing.T) {
	info := &Info{NetworkAddresses: []NetworkAddress{{NetIP: netip.MustParsePrefix("10.0.0.1/24")}}}
	info.removeAddresses()
	if len(info.NetworkAddresses) != 1 {
		t.Errorf("expected no change with empty input, got %v", info.NetworkAddresses)
	}
}
