package main

import (
	"os"

	log "github.com/sirupsen/logrus"
)

const defaultFontPath = "/Library/Fonts/Arial Unicode.ttf"

func (s *serviceClient) setDefaultFonts() {
	if _, err := os.Stat(defaultFontPath); err != nil {
		log.Errorf("Failed to find default font file: %v", err)
		return
	}

	os.Setenv("FYNE_FONT", defaultFontPath)
}
