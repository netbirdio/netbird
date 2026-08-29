//go:build windows

package server

// ShutdownState exists on Windows only so the shared server Config can name it.
// Virtual sessions are an X11 feature: the Windows path proxies to an agent the
// service control manager owns, so there are no residual processes of ours to
// reap after a crash.
type ShutdownState struct{}

// Name returns the state name for the state manager.
func (s *ShutdownState) Name() string {
	return "vnc_sessions_state"
}

// Cleanup has nothing to do on Windows.
func (s *ShutdownState) Cleanup() error {
	return nil
}
