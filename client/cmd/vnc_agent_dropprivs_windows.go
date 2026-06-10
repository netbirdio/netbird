//go:build windows

package cmd

// dropAgentPrivileges is a no-op on Windows: the agent and the daemon
// both run as SYSTEM (the daemon spawns the agent into the interactive
// session via CreateProcessAsUser with an impersonation token, but the
// resulting process still runs under SYSTEM, not under the user's
// account). The Windows path relies on the DACL-restricted socket
// directory, the unpredictable per-spawn socket name, the listen-readiness
// gate, and the per-spawn token for integrity instead.
func dropAgentPrivileges(_ uint32) error {
	return nil
}
