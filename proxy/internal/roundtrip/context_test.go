package roundtrip

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

func TestAccountIDContext(t *testing.T) {
	t.Run("returns empty when missing", func(t *testing.T) {
		assert.Equal(t, types.AccountID(""), AccountIDFromContext(context.Background()))
	})

	t.Run("round-trips value", func(t *testing.T) {
		ctx := WithAccountID(context.Background(), "acc-123")
		assert.Equal(t, types.AccountID("acc-123"), AccountIDFromContext(ctx))
	})
}

func TestSkipTLSVerifyContext(t *testing.T) {
	t.Run("false by default", func(t *testing.T) {
		assert.False(t, skipTLSVerifyFromContext(context.Background()))
	})

	t.Run("true when set", func(t *testing.T) {
		ctx := WithSkipTLSVerify(context.Background())
		assert.True(t, skipTLSVerifyFromContext(ctx))
	})
}
