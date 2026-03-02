//go:build !linux || (linux && 386)

package main

import (
	"errors"

	"github.com/godbus/dbus/v5"
)

type xembedHost struct{}

func newXembedHost(_ *dbus.Conn, _ string, _ dbus.ObjectPath) (*xembedHost, error) {
	return nil, errors.New("XEmbed tray not supported on this platform")
}

func (h *xembedHost) run()  {}
func (h *xembedHost) stop() {}
