//go:build windows

package systemops

import (
	"bytes"
	"os/exec"
	"testing"
)

const loopbackIfaceWindows = "Loopback Pseudo-Interface 1"

// ensureIPv6DefaultRoute installs an IPv6 default route via the loopback
// interface so route lookups for global IPv6 prefixes resolve in environments
// without v6 connectivity. If a default already exists it is left alone.
func ensureIPv6DefaultRoute(t *testing.T) {
	t.Helper()

	script := `New-NetRoute -DestinationPrefix "::/0" -InterfaceAlias "` + loopbackIfaceWindows + `" -RouteMetric 9999 -PolicyStore ActiveStore -ErrorAction Stop`
	out, err := exec.Command("powershell", "-Command", script).CombinedOutput()
	if err != nil {
		// Existing default; nothing to install or clean up.
		if bytes.Contains(out, []byte("already exists")) {
			return
		}
		t.Skipf("install IPv6 fallback default route: %v: %s", err, out)
	}
	t.Cleanup(func() {
		script := `Remove-NetRoute -DestinationPrefix "::/0" -InterfaceAlias "` + loopbackIfaceWindows + `" -Confirm:$false -ErrorAction Stop`
		if out, err := exec.Command("powershell", "-Command", script).CombinedOutput(); err != nil {
			t.Logf("delete IPv6 fallback default route: %v: %s", err, out)
		}
	})
}
