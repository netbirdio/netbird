//go:build !android && !ios && !freebsd && !js

package services

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	gcodes "google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
)

func TestErrorClassifier_Classify(t *testing.T) {
	c := errorClassifier{} // nil translator → Short is the bare "error.<code>" key

	t.Run("permission denied by gRPC code with a clean desc", func(t *testing.T) {
		// The daemon now forwards the innermost status: code + clean desc that
		// no longer carries the English "permission denied" marker.
		err := gstatus.Error(gcodes.PermissionDenied, "peer is already registered by a different User or a Setup Key")

		ce := c.classify(err)
		require.NotNil(t, ce)
		require.Equal(t, "permission_denied", ce.Code)
		require.Equal(t, "error.permission_denied", ce.Short)
		require.Equal(t, "peer is already registered by a different User or a Setup Key", ce.Long)
	})

	t.Run("substring match still wins for unclassified codes", func(t *testing.T) {
		err := gstatus.Error(gcodes.Unknown, "peer login has expired")

		ce := c.classify(err)
		require.NotNil(t, ce)
		require.Equal(t, "session_expired", ce.Code)
	})

	t.Run("unavailable code maps to daemon_unreachable", func(t *testing.T) {
		ce := c.classify(gstatus.Error(gcodes.Unavailable, "transport closing"))
		require.Equal(t, "daemon_unreachable", ce.Code)
	})

	t.Run("unmatched stays unknown", func(t *testing.T) {
		ce := c.classify(errors.New("something odd"))
		require.Equal(t, "unknown", ce.Code)
	})

	t.Run("nil error", func(t *testing.T) {
		require.Nil(t, c.classify(nil))
	})
}
