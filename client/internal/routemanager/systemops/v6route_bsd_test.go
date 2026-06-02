//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package systemops

import (
	"bytes"
	"os/exec"
	"testing"
)

// ensureIPv6DefaultRoute installs an IPv6 default route via the loopback
// interface so route lookups for global IPv6 prefixes resolve in environments
// without v6 connectivity. If a default already exists it is left alone.
func ensureIPv6DefaultRoute(t *testing.T) {
	t.Helper()

	out, err := exec.Command("route", "-6", "add", "default", "-iface", "lo0").CombinedOutput()
	if err != nil {
		// Existing default; nothing to install or clean up.
		if bytes.Contains(out, []byte("route already in table")) {
			return
		}
		t.Skipf("install IPv6 fallback default route: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("route", "-6", "delete", "default").CombinedOutput(); err != nil {
			t.Logf("delete IPv6 fallback default route: %v: %s", err, out)
		}
	})
}
