//go:build darwin && !ios

package cmd

import (
	"strings"
	"testing"
)

// TestDropAgentPrivileges_RefusesRootTarget locks in the contract that
// dropAgentPrivileges must never be a no-op when asked to keep the
// agent as root (target uid 0). A future caller that passes 0 by
// mistake would otherwise leave the post-auth attack surface running
// with full root privileges.
func TestDropAgentPrivileges_RefusesRootTarget(t *testing.T) {
	err := dropAgentPrivileges(0)
	if err == nil {
		t.Fatal("expected refusal for target uid 0, got nil")
	}
	if !strings.Contains(err.Error(), "root") {
		t.Fatalf("error should mention root, got: %v", err)
	}
}

// TestDropAgentPrivileges_NoOpWhenAlreadyTarget covers the dev path
// where the agent is launched by hand as the target user (no root
// available, no setuid needed). The helper must succeed silently
// instead of trying (and failing) a setuid to its current uid.
func TestDropAgentPrivileges_NoOpWhenAlreadyTarget(t *testing.T) {
	// Skip when running as root: the early-return path we want to
	// cover only fires when current uid == target uid.
	uid := currentUIDForTest()
	if uid == 0 {
		t.Skip("test must not run as root; cannot exercise the no-op early-return")
	}
	if err := dropAgentPrivileges(uid); err != nil {
		t.Fatalf("expected no-op when current uid == target, got: %v", err)
	}
}

// TestDropAgentPrivileges_RefusesMismatchedNonRoot guards the "non-root
// caller tries to setuid to a different uid" path: setuid would fail
// with EPERM anyway, but the helper should surface a clear error
// before issuing the syscall so a misconfigured spawn (wrong --target-uid
// flag) is debuggable.
func TestDropAgentPrivileges_RefusesMismatchedNonRoot(t *testing.T) {
	uid := currentUIDForTest()
	if uid == 0 {
		t.Skip("test must not run as root; covered case requires non-root caller")
	}
	err := dropAgentPrivileges(uid + 1)
	if err == nil {
		t.Fatal("expected refusal when non-root caller asks to setuid elsewhere")
	}
}
