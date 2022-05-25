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
	want := "development"
	ctx = metadata.NewIncomingContext(ctx, map[string][]string{
		"netbird-desktop-ui/": {want},
	})

	got := GetInfo(ctx)
	assert.Equal(t, want, got.UIVersion)
}
