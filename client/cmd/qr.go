package cmd

import (
	"io"

	"github.com/mdp/qrterminal/v3"
)

// printQRCode prints a QR code for the given URL to the writer.
// Called only when the user explicitly requests QR output via --qr.
func printQRCode(w io.Writer, url string) {
	if url == "" {
		return
	}
	qrterminal.GenerateWithConfig(url, qrterminal.Config{
		Level:          qrterminal.M,
		Writer:         w,
		HalfBlocks:     true,
		BlackChar:      qrterminal.BLACK_BLACK,
		WhiteChar:      qrterminal.WHITE_WHITE,
		BlackWhiteChar: qrterminal.BLACK_WHITE,
		WhiteBlackChar: qrterminal.WHITE_BLACK,
		QuietZone:      qrterminal.QUIET_ZONE,
	})
}
