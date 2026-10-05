package server

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
)

func TestInnermostStatus(t *testing.T) {
	t.Run("wrapped gRPC status", func(t *testing.T) {
		inner := gstatus.Error(codes.PermissionDenied, "peer is already registered by a different User or a Setup Key")
		// Mirror the daemon wrap chain: engine wraps with %w, mgm error is the inner status.
		wrapped := fmt.Errorf("extend auth session on management: %w", inner)

		st := innermostStatus(wrapped)
		require.NotNil(t, st)
		require.Equal(t, codes.PermissionDenied, st.Code())
		require.Equal(t, "peer is already registered by a different User or a Setup Key", st.Message())
	})

	t.Run("deepest status wins over an outer one", func(t *testing.T) {
		inner := gstatus.Error(codes.PermissionDenied, "deepest")
		chain := fmt.Errorf("outer: %w", fmt.Errorf("mid: %w", inner))

		st := innermostStatus(chain)
		require.NotNil(t, st)
		require.Equal(t, codes.PermissionDenied, st.Code())
		require.Equal(t, "deepest", st.Message())
	})

	t.Run("no status in chain", func(t *testing.T) {
		require.Nil(t, innermostStatus(errors.New("plain error")))
	})

	t.Run("nil error", func(t *testing.T) {
		require.Nil(t, innermostStatus(nil))
	})
}
