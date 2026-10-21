//go:build !js && !ios && !android

package server

import "testing"

func TestQemuScancodeToLinuxKey_KnownLetters(t *testing.T) {
	// Spot-check a few familiar letter keys against the Linux KEY_*
	// values they're supposed to land on.
	tests := []struct {
		name     string
		scancode uint32
		want     int
	}{
		{"A", 0x1E, keyA},
		{"S", 0x1F, keyS},
		{"D", 0x20, keyD},
		{"Q", 0x10, keyQ},
		{"Z", 0x2C, keyZ},
		{"1", 0x02, key1},
		{"Esc", 0x01, keyEsc},
		{"Tab", 0x0F, keyTab},
		{"Space", 0x39, keySpace},
		{"LeftShift", 0x2A, keyLeftShift},
	}
	for _, tc := range tests {
		got := qemuScancodeToLinuxKey(tc.scancode)
		if got != tc.want {
			t.Errorf("%s: scancode 0x%X => %d, want %d", tc.name, tc.scancode, got, tc.want)
		}
	}
}

func TestQemuScancodeToLinuxKey_Extended(t *testing.T) {
	// Extended (0xE0-prefixed) scancodes for arrow + navigation cluster.
	tests := []struct {
		name     string
		scancode uint32
		want     int
	}{
		{"Up", 0xE048, keyUp},
		{"Down", 0xE050, keyDown},
		{"Left", 0xE04B, keyLeft},
		{"Right", 0xE04D, keyRight},
		{"Home", 0xE047, keyHome},
		{"End", 0xE04F, keyEnd},
		{"PageUp", 0xE049, keyPageUp},
		{"PageDown", 0xE051, keyPageDown},
		{"Insert", 0xE052, keyInsert},
		{"Delete", 0xE053, keyDelete},
		{"RightCtrl", 0xE01D, keyRightCtrl},
		{"RightAlt", 0xE038, keyRightAlt},
		{"KPEnter", 0xE01C, keyKPEnter},
		{"KPSlash", 0xE035, keyKPSlash},
	}
	for _, tc := range tests {
		got := qemuScancodeToLinuxKey(tc.scancode)
		if got != tc.want {
			t.Errorf("%s: scancode 0x%X => %d, want %d", tc.name, tc.scancode, got, tc.want)
		}
	}
}

func TestQemuScancodeToLinuxKey_Miss(t *testing.T) {
	// 0xE0FF is in the extended range but not a real key. Must return 0
	// so the caller can fall back to the keysym path.
	if got := qemuScancodeToLinuxKey(0xE0FF); got != 0 {
		t.Errorf("unknown scancode should miss: got %d, want 0", got)
	}
	if got := qemuScancodeToLinuxKey(0xFF); got != 0 {
		t.Errorf("unknown non-extended scancode should miss: got %d, want 0", got)
	}
}

func TestQemuScancodeIsExtended(t *testing.T) {
	cases := []struct {
		scancode uint32
		want     bool
	}{
		{0x1E, false},
		{0xE048, true},
		{0xE000, true},
		{0xFF, false},
		{0xE0FF, true},
	}
	for _, tc := range cases {
		if got := qemuScancodeIsExtended(tc.scancode); got != tc.want {
			t.Errorf("isExtended(0x%X) = %v, want %v", tc.scancode, got, tc.want)
		}
	}
}

func TestQemuScancodeLowByte(t *testing.T) {
	if got := qemuScancodeLowByte(0xE048); got != 0x48 {
		t.Errorf("lowByte(0xE048) = 0x%X, want 0x48", got)
	}
	if got := qemuScancodeLowByte(0x1E); got != 0x1E {
		t.Errorf("lowByte(0x1E) = 0x%X, want 0x1E", got)
	}
}
