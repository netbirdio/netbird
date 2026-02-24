package cmd

import (
	"bytes"
	"os"
	"testing"

	"github.com/mdp/qrterminal/v3"
)

func TestPrintQRCode_NonTerminalWriter(t *testing.T) {
	var buf bytes.Buffer

	printQRCode(&buf, "https://example.com/auth")

	if buf.Len() != 0 {
		t.Error("expected no output when writer is not a terminal file")
	}
}

func TestPrintQRCode_EmptyURL(t *testing.T) {
	var buf bytes.Buffer

	printQRCode(&buf, "")

	if buf.Len() != 0 {
		t.Error("expected no output for empty URL")
	}
}

func TestPrintQRCode_NonTerminalFile(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Skipf("cannot open %s: %v", os.DevNull, err)
	}
	defer f.Close()

	// /dev/null is a valid *os.File but not a terminal, so printQRCode should
	// suppress output. We cannot capture output from a non-terminal *os.File,
	// so this test serves as a no-panic guard. Non-terminal suppression is
	// fully asserted in TestPrintQRCode_NonTerminalWriter.
	printQRCode(f, "https://example.com/auth")
}

func TestQRTerminalLibrary_GeneratesOutput(t *testing.T) {
	var buf bytes.Buffer

	qrterminal.GenerateWithConfig("https://example.com/auth", qrterminal.Config{
		Level:     qrterminal.L,
		Writer:    &buf,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
	})

	if buf.Len() == 0 {
		t.Error("expected qrterminal library to produce output")
	}
}
