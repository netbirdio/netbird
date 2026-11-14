package alignedhb

import "time"

// CorrectionWindow is how far a phase correction from the client may move the
// tick away from the phase Management signed, in either direction. It covers
// path delay and proxy holds, and keeps a client from steering its streams to a
// moment it picks.
const CorrectionWindow = 5 * time.Second

// ClampPhase returns phase limited to CorrectionWindow around signed, on the
// circle of period. clamped is true when phase was outside the window and the
// result is the nearest edge of it. phase and signed must be valid phases of
// period.
func ClampPhase(phase, signed, period time.Duration) (_ time.Duration, clamped bool) {
	delta := (phase - signed) % period
	if delta < 0 {
		delta += period
	}
	// Take the shorter way round the circle, so delta is in (-period/2, period/2].
	if delta > period/2 {
		delta -= period
	}
	switch {
	case delta > CorrectionWindow:
		delta = CorrectionWindow
	case delta < -CorrectionWindow:
		delta = -CorrectionWindow
	default:
		return phase, false
	}
	return ((signed+delta)%period + period) % period, true
}
