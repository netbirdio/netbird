//go:build linux && !386

package main

import (
	"os"
	"strings"
)

// init runs before Wails' own init(), so the env vars are set in time.
func init() {
	disableDMABUFRenderer()
	disableWebKitSandboxIfNeeded()
}

func disableDMABUFRenderer() {
	if os.Getenv("WEBKIT_DISABLE_DMABUF_RENDERER") != "" {
		return
	}

	// WebKitGTK's DMA-BUF renderer fails on many setups (VMs, containers,
	// minimal WMs without proper GPU access) and leaves the window blank
	// white. Wails only disables it for NVIDIA+Wayland, but the issue is
	// broader. Always disable it — software rendering works fine for a
	// small UI like this.
	_ = os.Setenv("WEBKIT_DISABLE_DMABUF_RENDERER", "1")
}

// disableWebKitSandboxIfNeeded works around WebKitGTK crashing at startup when
// its bubblewrap (bwrap) sandbox can't create an unprivileged user namespace —
// "bwrap: setting up uid map: Permission denied" followed by "Failed to fully
// launch dbus-proxy" and a panic in webkit_web_view_load_uri. This happens in
// containers/VMs and on Ubuntu 24.04+ where AppArmor restricts unprivileged
// user namespaces (kernel.apparmor_restrict_unprivileged_userns=1). Software
// can't grant the namespace from here, so when we detect that userns are
// blocked we disable the WebKit sandbox to keep the UI usable. The user can
// override either way by setting WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS.
func disableWebKitSandboxIfNeeded() {
	if _, set := os.LookupEnv("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS"); set {
		return
	}
	if unprivilegedUsernsAllowed() {
		return
	}
	_ = os.Setenv("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS", "1")
}

// unprivilegedUsernsAllowed reports whether the kernel currently permits
// unprivileged user namespaces, which WebKit's bwrap sandbox needs. It reads
// the relevant procfs knobs; on a kernel that doesn't expose them (older or
// hardened), it conservatively assumes namespaces are available so we don't
// needlessly weaken the sandbox.
func unprivilegedUsernsAllowed() bool {
	// Debian/Ubuntu legacy switch: 0 disables unprivileged user namespaces.
	if v, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(v)) == "0" {
			return false
		}
	}
	// Ubuntu 24.04+ AppArmor restriction: non-zero restricts/blocks them.
	if v, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil {
		if strings.TrimSpace(string(v)) != "0" {
			return false
		}
	}
	return true
}

// On Linux, the system tray provider may require the menu to be recreated
// rather than updated in place. The rebuildExitNodeMenu method in tray.go
// already handles this by removing and re-adding items; no additional
// Linux-specific workaround is needed for Wails v3.
