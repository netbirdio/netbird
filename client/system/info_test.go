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
	assert.Equal(t, want, got.WiretrusteeVersion)
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
