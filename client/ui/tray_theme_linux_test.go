//go:build linux && !(linux && 386)

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadKdeComplementaryBackground(t *testing.T) {
	// Mirrors the KDE test VM's kdeglobals: Window light, Complementary dark.
	// The tray sits on the panel, which Plasma paints from Complementary, so
	// the panel is dark even though the global color-scheme is Light.
	content := `[Colors:Window]
BackgroundNormal=239,240,241

[Colors:Complementary]
BackgroundAlternate=27,30,32
BackgroundNormal=42,46,50

[General]
ColorSchemeHash=0be804dba87e3512aeb4be3d78ed981f59f0f2f4
`
	path := filepath.Join(t.TempDir(), "kdeglobals")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	rgb, ok := readKdeComplementaryBackground(path)
	if !ok {
		t.Fatal("expected to find Complementary BackgroundNormal")
	}
	if rgb != [3]uint8{42, 46, 50} {
		t.Fatalf("rgb = %v, want [42 46 50]", rgb)
	}
	if !isDarkRGB(rgb[0], rgb[1], rgb[2]) {
		t.Fatal("panel colour 42,46,50 should be dark")
	}
	// The Window background (what color-scheme reflects) is light — the bug
	// this fix addresses is picking the icon from that instead of the panel.
	if isDarkRGB(239, 240, 241) {
		t.Fatal("window colour 239,240,241 should be light")
	}
}

func TestReadKdeComplementaryBackgroundMissingGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kdeglobals")
	if err := os.WriteFile(path, []byte("[Colors:Window]\nBackgroundNormal=1,2,3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readKdeComplementaryBackground(path); ok {
		t.Fatal("expected not-ok when Complementary group is absent")
	}
}

func TestParseRGB(t *testing.T) {
	if _, ok := parseRGB("1,2"); ok {
		t.Fatal("two components should fail")
	}
	if _, ok := parseRGB("300,0,0"); ok {
		t.Fatal("out-of-range should fail")
	}
	if _, ok := parseRGB("a,b,c"); ok {
		t.Fatal("non-numeric should fail")
	}
	rgb, ok := parseRGB(" 10 , 20 , 30 ")
	if !ok || rgb != [3]uint8{10, 20, 30} {
		t.Fatalf("parseRGB = %v ok=%v, want [10 20 30] true", rgb, ok)
	}
}

func TestIsDarkRGB(t *testing.T) {
	if !isDarkRGB(0, 0, 0) {
		t.Fatal("black is dark")
	}
	if isDarkRGB(255, 255, 255) {
		t.Fatal("white is light")
	}
	if !isDarkRGB(42, 46, 50) {
		t.Fatal("Breeze panel grey is dark")
	}
	if isDarkRGB(239, 240, 241) {
		t.Fatal("Breeze window grey is light")
	}
}
