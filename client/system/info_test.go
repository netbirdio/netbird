package system

import (
	"context"
	"testing"
	"time"

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

func TestGetInfoWithChecksTimeout_Success(t *testing.T) {
	info, ok := GetInfoWithChecksTimeout(context.Background(), 30*time.Second, nil)
	assert.True(t, ok, "expected gathering to complete within the timeout")
	assert.NotNil(t, info)
}

func TestGetInfoWithChecksTimeout_Timeout(t *testing.T) {
	// A 1ns budget expires before the (real) system-info gathering can finish, so the
	// caller must get (nil, false) instead of blocking on the in-flight goroutine.
	info, ok := GetInfoWithChecksTimeout(context.Background(), time.Nanosecond, nil)
	assert.False(t, ok, "expected timeout to be reported")
	assert.Nil(t, info)
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
