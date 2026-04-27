//go:build !linux && !windows && !darwin

package net

func (d *Dialer) init() {
	// implemented on Linux, Android, and Windows only
}
