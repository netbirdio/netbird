package system

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_LocalVersion(t *testing.T) {
	got := GetInfo(context.TODO())
	want := "development"
	assert.Equal(t, want, got.WiretrusteeVersion)
}
