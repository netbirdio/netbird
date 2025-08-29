//go:build !linux

package net

func (d *Dialer) init() {
	// implemented on Linux and Android only
}
