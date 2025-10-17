package system

import (
    "context"
    "testing"

    "github.com/stretchr/testify/assert"
    "google.golang.org/grpc/metadata"
)

func TestInfo_CopyFlagsFrom(t *testing.T) {
	origin := &Info{}
	serverSSHAllowed := true
	origin.SetFlags(
		true,   // RosenpassEnabled
		false,  // RosenpassPermissive
		&serverSSHAllowed,
		true,  // DisableClientRoutes
		false, // DisableServerRoutes
		true,  // DisableDNS
		false, // DisableFirewall
		true,  // BlockLANAccess
		false, // BlockInbound
		true,  // LazyConnectionEnabled
	)

	got := &Info{}
	got.CopyFlagsFrom(origin)

	if got.RosenpassEnabled != true {
		t.Fatalf("RosenpassEnabled not copied: got %v", got.RosenpassEnabled)
	}
	if got.RosenpassPermissive != false {
		t.Fatalf("RosenpassPermissive not copied: got %v", got.RosenpassPermissive)
	}
	if got.ServerSSHAllowed != true {
		t.Fatalf("ServerSSHAllowed not copied: got %v", got.ServerSSHAllowed)
	}
	if got.DisableClientRoutes != true {
		t.Fatalf("DisableClientRoutes not copied: got %v", got.DisableClientRoutes)
	}
	if got.DisableServerRoutes != false {
		t.Fatalf("DisableServerRoutes not copied: got %v", got.DisableServerRoutes)
	}
	if got.DisableDNS != true {
		t.Fatalf("DisableDNS not copied: got %v", got.DisableDNS)
	}
	if got.DisableFirewall != false {
		t.Fatalf("DisableFirewall not copied: got %v", got.DisableFirewall)
	}
	if got.BlockLANAccess != true {
		t.Fatalf("BlockLANAccess not copied: got %v", got.BlockLANAccess)
	}
	if got.BlockInbound != false {
		t.Fatalf("BlockInbound not copied: got %v", got.BlockInbound)
	}
	if got.LazyConnectionEnabled != true {
		t.Fatalf("LazyConnectionEnabled not copied: got %v", got.LazyConnectionEnabled)
	}

	// ensure CopyFlagsFrom does not touch unrelated fields
	origin.Hostname = "host-a"
	got.Hostname = "host-b"
	got.CopyFlagsFrom(origin)
	if got.Hostname != "host-b" {
		t.Fatalf("CopyFlagsFrom should not overwrite non-flag fields, got Hostname=%q", got.Hostname)
	}
}

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
