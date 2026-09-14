package cmd

import (
	"bytes"
	"testing"
)

func TestPrintQRCode_EmptyURL(t *testing.T) {
	var buf bytes.Buffer

	printQRCode(&buf, "")

	if buf.Len() != 0 {
		t.Error("expected no output for empty URL")
	}
}

func TestPrintQRCode_WritesOutput(t *testing.T) {
	var buf bytes.Buffer

	printQRCode(&buf, "https://example.com/auth")

	if buf.Len() == 0 {
		t.Error("expected QR code output for non-empty URL")
	}
}
