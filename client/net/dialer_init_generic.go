//go:build !linux && !windows

package net

func (d *Dialer) init() {
	// implemented on Linux, Android, and Windows only
}
