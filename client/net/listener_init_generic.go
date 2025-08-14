//go:build !linux && !windows

package net

func (l *ListenerConfig) init() {
	// implemented on Linux, Android, and Windows only
}
