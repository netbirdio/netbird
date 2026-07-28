package types

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestServiceMode_IsL4(t *testing.T) {
	tests := []struct {
		mode ServiceMode
		want bool
	}{
		{ServiceModeHTTP, false},
		{ServiceModeTCP, true},
		{ServiceModeUDP, true},
		{ServiceModeTLS, true},
		{ServiceMode("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			assert.Equal(t, tt.want, tt.mode.IsL4())
		})
	}
}

func TestDialTimeoutContext(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		ctx := WithDialTimeout(context.Background(), 5*time.Second)
		d, ok := DialTimeoutFromContext(ctx)
		assert.True(t, ok)
		assert.Equal(t, 5*time.Second, d)
	})

	t.Run("missing", func(t *testing.T) {
		_, ok := DialTimeoutFromContext(context.Background())
		assert.False(t, ok)
	})

	t.Run("zero returns false", func(t *testing.T) {
		ctx := WithDialTimeout(context.Background(), 0)
		_, ok := DialTimeoutFromContext(ctx)
		assert.False(t, ok, "zero duration should return ok=false")
	})

	t.Run("negative returns false", func(t *testing.T) {
		ctx := WithDialTimeout(context.Background(), -1*time.Second)
		_, ok := DialTimeoutFromContext(ctx)
		assert.False(t, ok, "negative duration should return ok=false")
	})
}
