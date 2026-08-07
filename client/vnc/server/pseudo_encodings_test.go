//go:build !js && !ios && !android

package server

import "testing"

func TestEncodeDesktopSizeBody(t *testing.T) {
	got := encodeDesktopSizeBody(1920, 1080)
	if len(got) != 12 {
		t.Fatalf("DesktopSize body length: want 12, got %d", len(got))
	}
	if got[0] != 0 || got[1] != 0 || got[2] != 0 || got[3] != 0 {
		t.Fatalf("DesktopSize: x and y must be zero; got % x", got[0:4])
	}
	if got[4] != 0x07 || got[5] != 0x80 {
		t.Fatalf("DesktopSize: width should be 1920 (0x0780); got % x", got[4:6])
	}
	if got[6] != 0x04 || got[7] != 0x38 {
		t.Fatalf("DesktopSize: height should be 1080 (0x0438); got % x", got[6:8])
	}
	// Encoding = -223 → 0xFFFFFF21 in two's complement big-endian.
	if got[8] != 0xFF || got[9] != 0xFF || got[10] != 0xFF || got[11] != 0x21 {
		t.Fatalf("DesktopSize: encoding bytes wrong: % x", got[8:12])
	}
}

func TestEncodeDesktopNameBody(t *testing.T) {
	name := "vma@debian3"
	got := encodeDesktopNameBody(name)
	if len(got) != 12+4+len(name) {
		t.Fatalf("DesktopName body length: want %d, got %d", 12+4+len(name), len(got))
	}
	// Encoding = -307 → 0xFFFFFECD.
	if got[8] != 0xFF || got[9] != 0xFF || got[10] != 0xFE || got[11] != 0xCD {
		t.Fatalf("DesktopName: encoding bytes wrong: % x", got[8:12])
	}
	if got[12] != 0 || got[13] != 0 || got[14] != 0 || got[15] != byte(len(name)) {
		t.Fatalf("DesktopName: name length prefix wrong: % x", got[12:16])
	}
	if string(got[16:]) != name {
		t.Fatalf("DesktopName: name body wrong: %q", got[16:])
	}
}

func TestEncodeLastRectBody(t *testing.T) {
	got := encodeLastRectBody()
	if len(got) != 12 {
		t.Fatalf("LastRect body length: want 12, got %d", len(got))
	}
	for i := 0; i < 8; i++ {
		if got[i] != 0 {
			t.Fatalf("LastRect: header bytes 0..7 must be zero; got byte %d = 0x%02x", i, got[i])
		}
	}
	// Encoding = -224 → 0xFFFFFF20.
	if got[8] != 0xFF || got[9] != 0xFF || got[10] != 0xFF || got[11] != 0x20 {
		t.Fatalf("LastRect: encoding bytes wrong: % x", got[8:12])
	}
}
