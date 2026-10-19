//go:build dragonfly || freebsd || netbsd || openbsd

package networkmonitor

func monitorScopedFlag() int { return 0 }
