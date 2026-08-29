//go:build !linux || android

package server

// Crash recovery for virtual-session processes is implemented on Linux only,
// where /proc gives a process identity stable enough to signal safely: a PID
// alone can have been reused by the time the daemon restarts, and Cleanup
// signals a whole process group.
//
// The type exists everywhere so the shared server Config can name it, and so
// the state manager can be handed one uniformly.
//
// What that leaves uncovered, per platform:
//
//   - FreeBSD runs virtual sessions but mounts no procfs by default, so there
//     is no start time to pin an identity to. Reaping on a PID alone could
//     signal an unrelated process group, which is worse than leaving an X
//     server behind, so nothing is reaped.
//   - Windows has no virtual sessions. Its console agent is tied to the daemon
//     by a Job Object with kill-on-close, which reaps it when the service dies.
//     Assignment to that job can fail (the log says so at the time), and an
//     agent that was never assigned does outlive a service crash; recovering
//     from that would need a Windows process identity this does not implement.
//   - macOS spawns a per-connection agent that exits with its connection.
type ShutdownState struct {
	// Processes is never acted on here; the field exists so the virtual-session
	// plumbing, which FreeBSD shares with Linux, compiles unchanged.
	Processes map[string]sessionProcess `json:"processes,omitempty"`
}

// Name returns the state name for the state manager.
func (s *ShutdownState) Name() string {
	return "vnc_sessions_state"
}

// Cleanup has nothing it can safely reap on these platforms.
func (s *ShutdownState) Cleanup() error {
	return nil
}

// sessionProcess is the placeholder identity these platforms record, which is
// to say none.
type sessionProcess struct{}

// describeProcess records nothing: without a way to tell a reused PID from the
// original, a record would only invite an unsafe kill later.
func describeProcess(_ int) sessionProcess {
	return sessionProcess{}
}
