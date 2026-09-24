//go:build freebsd

package server

import (
	"fmt"
	"image"
)

func (c *X11Capturer) initSHM() error {
	return fmt.Errorf("SysV SHM not available on this platform")
}

func (c *X11Capturer) captureSHM() (*image.RGBA, error) {
	return nil, fmt.Errorf("SHM capture not available on this platform")
}

func (c *X11Capturer) captureSHMInto(_ *image.RGBA) error {
	return fmt.Errorf("SHM capture not available on this platform")
}

func (c *X11Capturer) closeSHM() {
	// no SHM to close on this platform
}
