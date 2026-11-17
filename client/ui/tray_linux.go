//go:build linux && !386

package main

import (
	"os"
	"strings"
)

// init runs before Wails' own init(), so the env vars are set in time.
func init() {
	disableDMABUFRenderer()
	disableCompositingMode()
	disableWebKitSandboxIfNeeded()
}

func disableDMABUFRenderer() {
	if os.Getenv("WEBKIT_DISABLE_DMABUF_RENDERER") != "" {
		return
	}

	// WebKitGTK's DMA-BUF renderer leaves a blank-white window on many setups
	// (VMs, containers, minimal WMs). Wails only disables it for NVIDIA+Wayland,
	// but the issue is broader; software rendering is fine for a small UI.
	_ = os.Setenv("WEBKIT_DISABLE_DMABUF_RENDERER", "1")
}

func disableCompositingMode() {
	if os.Getenv("WEBKIT_DISABLE_COMPOSITING_MODE") != "" {
		return
	}
	// Disabling the DMA-BUF renderer alone isn't enough on some Intel setups: the
	// GL compositor still hits Mesa's unimplemented DRM-format-modifier paths and
	// SIGSEGVs inside g_application_run before the first frame.
	_ = os.Setenv("WEBKIT_DISABLE_COMPOSITING_MODE", "1")
}

// disableWebKitSandboxIfNeeded works around WebKitGTK crashing at startup when
// its bwrap sandbox can't create an unprivileged user namespace (containers/VMs,
// or Ubuntu 24.04+ AppArmor restrictions).
func disableWebKitSandboxIfNeeded() {
	if _, set := os.LookupEnv("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS"); set {
		return
	}
	if unprivilegedUsernsAllowed() {
		return
	}
	_ = os.Setenv("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS", "1")
}

// unprivilegedUsernsAllowed reports whether the kernel permits unprivileged
// user namespaces (needed by WebKit's bwrap sandbox). Absent knobs are treated
// as allowed, to avoid needlessly weakening the sandbox.
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

// Linux's tray provider needs the menu recreated rather than updated in place;
// tray.go's rebuildExitNodeMenu already does this, so no extra workaround here.
