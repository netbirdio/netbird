//go:build windows

package cmd

// dropAgentPrivileges is a no-op on Windows: the agent and the daemon
// both run as SYSTEM (the daemon spawns the agent into the interactive
// session via CreateProcessAsUser with an impersonation token, but the
// resulting process still runs under SYSTEM, not under the user's
// account). The Windows path relies on the C:\Windows\Temp socket
// location (admin/SYSTEM-write-only) and the per-spawn token for
// integrity instead.
func dropAgentPrivileges(_ uint32) error {
	return nil
}
