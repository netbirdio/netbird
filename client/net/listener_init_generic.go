//go:build !linux && !windows && !darwin

package net

func (l *ListenerConfig) init() {
	// implemented on Linux, Android, and Windows only
}
