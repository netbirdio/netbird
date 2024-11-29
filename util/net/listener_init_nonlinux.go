//go:build !linux

package net

func (l *ListenerConfig) init() {
	// implemented on Linux and Android only
}
