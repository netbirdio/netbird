//go:build freebsd || openbsd || netbsd || dragonfly

package main

import (
	"os"
	"runtime"

	log "github.com/sirupsen/logrus"
)

func (s *serviceClient) setDefaultFonts() {
	paths := []string{
		"/usr/local/share/fonts/TTF/DejaVuSans.ttf",
		"/usr/local/share/fonts/dejavu/DejaVuSans.ttf",
		"/usr/local/share/noto/NotoSans-Regular.ttf",
		"/usr/local/share/fonts/noto/NotoSans-Regular.ttf",
		"/usr/local/share/fonts/liberation-fonts-ttf/LiberationSans-Regular.ttf",
	}

	for _, fontPath := range paths {
		if _, err := os.Stat(fontPath); err == nil {
			os.Setenv("FYNE_FONT", fontPath)
			log.Debugf("Using font: %s", fontPath)
			return
		}
	}

	log.Errorf("Failed to find any suitable font files for %s", runtime.GOOS)
}
