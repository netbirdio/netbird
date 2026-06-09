package system

import (
	"context"
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
	addr, err := networkAddresses(context.Background())
	if err != nil {
		t.Errorf("failed to discover network addresses: %s", err)
	}
	if len(addr) == 0 {
		t.Errorf("no network addresses found")
	}
}

func Test_networkAddresses(t *testing.T) {
	addrs, err := networkAddresses(context.Background())
	assert.NoError(t, err)
	assert.NotEmpty(t, addrs, "should discover at least one network address")

	for _, addr := range addrs {
		assert.True(t, addr.NetIP.IsValid(), "address should be valid: %s", addr.NetIP)
		assert.False(t, addr.NetIP.Addr().IsLoopback(), "should not include loopback addresses")
	}
}

func Test_networkAddresses_noDuplicates(t *testing.T) {
	addrs, err := networkAddresses(context.Background())
	assert.NoError(t, err)

	seen := make(map[string]struct{})
	for _, addr := range addrs {
		key := addr.NetIP.String()
		_, exists := seen[key]
		assert.False(t, exists, "duplicate address found: %s", key)
		seen[key] = struct{}{}
	}
}
