package cmd

import (
	"io"
	"os"

	"github.com/mdp/qrterminal/v3"
	"golang.org/x/term"
)

// printQRCode prints a QR code for the given URL to the writer.
// When output is piped or redirected, the QR code is suppressed.
func printQRCode(w io.Writer, url string) {
	if url == "" {
		return
	}
	f, ok := w.(*os.File)
	if !ok {
		return
	}
	if !term.IsTerminal(int(f.Fd())) {
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
