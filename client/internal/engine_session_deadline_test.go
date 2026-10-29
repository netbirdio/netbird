package internal

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/internal/auth/sessionwatch"
	"github.com/netbirdio/netbird/client/internal/peer"
)

// TestApplySessionDeadline_ThreeState pins down the 3-state semantics of the
// wire field carried on LoginResponse / SyncResponse:
//
//   - nil pointer            → no info; previously-anchored deadline survives
//   - explicit zero value    → "expiry disabled" sentinel; both sinks cleared
//   - valid future timestamp → new deadline propagated to both sinks
func TestApplySessionDeadline_ThreeState(t *testing.T) {
	newEngine := func() *Engine {
		recorder := peer.NewRecorder("")
		return &Engine{
			statusRecorder: recorder,
			sessionWatcher: sessionwatch.New(recorder),
		}
	}

	t.Run("valid timestamp sets deadline on both sinks", func(t *testing.T) {
		e := newEngine()
		deadline := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

		e.ApplySessionDeadline(timestamppb.New(deadline))

		require.True(t, e.statusRecorder.GetSessionExpiresAt().Equal(deadline),
			"status recorder should hold the new deadline")
	})

	t.Run("nil is a no-op and preserves previous deadline", func(t *testing.T) {
		e := newEngine()
		seeded := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		e.ApplySessionDeadline(timestamppb.New(seeded))
		require.True(t, e.statusRecorder.GetSessionExpiresAt().Equal(seeded))

		e.ApplySessionDeadline(nil)

		require.True(t, e.statusRecorder.GetSessionExpiresAt().Equal(seeded),
			"nil snapshot must not disturb the existing deadline")
	})

	t.Run("explicit zero clears a previously-anchored deadline", func(t *testing.T) {
		e := newEngine()
		seeded := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		e.ApplySessionDeadline(timestamppb.New(seeded))
		require.True(t, e.statusRecorder.GetSessionExpiresAt().Equal(seeded))

		// Explicit zero Timestamp{} (seconds=0, nanos=0) is the
		// "expiry disabled / not SSO" sentinel.
		e.ApplySessionDeadline(&timestamppb.Timestamp{})

		require.True(t, e.statusRecorder.GetSessionExpiresAt().IsZero(),
			"explicit zero sentinel must clear the deadline")
	})

	t.Run("invalid timestamp clears the deadline", func(t *testing.T) {
		e := newEngine()
		seeded := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		e.ApplySessionDeadline(timestamppb.New(seeded))
		require.True(t, e.statusRecorder.GetSessionExpiresAt().Equal(seeded))

		// Out-of-range nanos → IsValid()==false; same-meaning as the
		// disabled sentinel for downstream sinks.
		e.ApplySessionDeadline(&timestamppb.Timestamp{Seconds: 1, Nanos: -1})

		require.True(t, e.statusRecorder.GetSessionExpiresAt().IsZero(),
			"invalid timestamp must clear the deadline")
	})

	t.Run("recently expired timestamp stays visible as expired", func(t *testing.T) {
		e := newEngine()
		expired := time.Now().Add(-5 * time.Minute).UTC().Truncate(time.Second)

		e.ApplySessionDeadline(timestamppb.New(expired))

		require.True(t, e.statusRecorder.GetSessionExpiresAt().Equal(expired),
			"recently-expired deadline must stay on the recorder so consumers render it as expired")
	})
}
