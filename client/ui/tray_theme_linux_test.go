//go:build linux && !(linux && 386)

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Values measured on Plasma 6.7.4 (Fedora 44) under each Breeze scheme. The
// Complementary group is dark under both, which is why it can't decide the
// panel; Window tracks it.
const (
	kdeglobalsLight = `[Colors:Complementary]
BackgroundAlternate=27,30,32
BackgroundNormal=42,46,50

[Colors:Window]
BackgroundNormal=239,240,241

[General]
ColorSchemeHash=0be804dba87e3512aeb4be3d78ed981f59f0f2f4
`
	kdeglobalsDark = `[Colors:Complementary]
BackgroundNormal=32,35,38

[Colors:Window]
BackgroundNormal=32,35,38

[General]
ColorScheme=BreezeDark
`
)

// kdeConfig points the KDE readers at a temp dir holding the given files, and
// makes isKDE report KDE. An empty body skips the file.
func kdeConfig(t *testing.T, kdeglobals, plasmarc string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{kdeglobalsFile: kdeglobals, plasmarcFile: plasmarc} {
		if body == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_CURRENT_DESKTOP", "KDE")
}

// The reported bug: a Light global scheme left the panel reported dark, so the
// tray kept the white silhouette on a light panel.
func TestKdePanelIsDarkFollowsColourScheme(t *testing.T) {
	for _, tc := range []struct {
		name       string
		kdeglobals string
		wantDark   bool
	}{
		{"light scheme", kdeglobalsLight, false},
		{"dark scheme", kdeglobalsDark, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kdeConfig(t, tc.kdeglobals, "")
			dark, ok := kdePanelIsDark()
			if !ok {
				t.Fatal("expected a conclusive answer from kdeglobals")
			}
			if dark != tc.wantDark {
				t.Fatalf("dark = %v, want %v", dark, tc.wantDark)
			}
		})
	}
}

// A pinned Plasma style paints the panel regardless of the colour scheme, so it
// has to outrank it in both directions.
func TestKdePanelIsDarkPinnedStyleOutranksScheme(t *testing.T) {
	for _, tc := range []struct {
		name       string
		kdeglobals string
		style      string
		wantDark   bool
	}{
		{"dark style, light scheme", kdeglobalsLight, "breeze-dark", true},
		{"light style, dark scheme", kdeglobalsDark, "breeze-light", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kdeConfig(t, tc.kdeglobals, "[Theme]\nname="+tc.style+"\n")
			dark, ok := kdePanelIsDark()
			if !ok {
				t.Fatal("expected a conclusive answer from plasmarc")
			}
			if dark != tc.wantDark {
				t.Fatalf("dark = %v, want %v", dark, tc.wantDark)
			}
		})
	}
}

// "default" fixes nothing, so the colour scheme still decides.
func TestKdePanelIsDarkDefaultStyleDefersToScheme(t *testing.T) {
	kdeConfig(t, kdeglobalsLight, "[Theme]\nname=default\n")
	dark, ok := kdePanelIsDark()
	if !ok {
		t.Fatal("expected the colour scheme to answer")
	}
	if dark {
		t.Fatal("default style on a Light scheme is a light panel")
	}
}

// No colours and no style: stay inconclusive so readDarkMode uses the portal
// rather than guessing.
func TestKdePanelIsDarkInconclusive(t *testing.T) {
	t.Run("no window group", func(t *testing.T) {
		kdeConfig(t, "[Colors:Complementary]\nBackgroundNormal=42,46,50\n", "")
		if _, ok := kdePanelIsDark(); ok {
			t.Fatal("expected not-ok without a Window group")
		}
	})
	t.Run("no kde files", func(t *testing.T) {
		kdeConfig(t, "", "")
		if _, ok := kdePanelIsDark(); ok {
			t.Fatal("expected not-ok with no kdeglobals at all")
		}
	})
	t.Run("not kde", func(t *testing.T) {
		kdeConfig(t, kdeglobalsDark, "")
		t.Setenv("XDG_CURRENT_DESKTOP", "ubuntu:GNOME")
		if _, ok := kdePanelIsDark(); ok {
			t.Fatal("expected not-ok off KDE")
		}
	})
}

func TestPlasmaStyleIsDark(t *testing.T) {
	for _, tc := range []struct {
		style     string
		wantDark  bool
		wantKnown bool
	}{
		{"breeze-dark", true, true},
		{"Breeze Dark", true, true},
		{"breeze-light", false, true},
		{"default", false, false},
		{"oxygen", false, false},
	} {
		t.Run(tc.style, func(t *testing.T) {
			kdeConfig(t, "", "[Theme]\nname="+tc.style+"\n")
			dark, ok := plasmaStyleIsDark()
			if ok != tc.wantKnown || dark != tc.wantDark {
				t.Fatalf("plasmaStyleIsDark() = (%v, %v), want (%v, %v)", dark, ok, tc.wantDark, tc.wantKnown)
			}
		})
	}
	t.Run("absent plasmarc", func(t *testing.T) {
		kdeConfig(t, kdeglobalsLight, "")
		if _, ok := plasmaStyleIsDark(); ok {
			t.Fatal("expected not-ok when plasmarc is absent")
		}
	})
}

func TestReadIniValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), kdeglobalsFile)
	if err := os.WriteFile(path, []byte(kdeglobalsLight), 0o600); err != nil {
		t.Fatal(err)
	}
	// The same key exists in two groups, so a group-blind reader would return
	// whichever came first.
	if v, ok := readIniValue(path, "[Colors:Window]", "BackgroundNormal"); !ok || v != "239,240,241" {
		t.Fatalf("Window BackgroundNormal = %q ok=%v, want \"239,240,241\" true", v, ok)
	}
	if v, ok := readIniValue(path, "[Colors:Complementary]", "BackgroundNormal"); !ok || v != "42,46,50" {
		t.Fatalf("Complementary BackgroundNormal = %q ok=%v, want \"42,46,50\" true", v, ok)
	}
	if _, ok := readIniValue(path, "[Colors:Window]", "ColorSchemeHash"); ok {
		t.Fatal("a key from another group should not be found")
	}
	if _, ok := readIniValue(filepath.Join(t.TempDir(), "absent"), "[Theme]", "name"); ok {
		t.Fatal("a missing file should not be found")
	}
	if _, ok := readIniValue("", "[Theme]", "name"); ok {
		t.Fatal("an empty path should not be found")
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
	if !isDarkRGB(32, 35, 38) {
		t.Fatal("BreezeDark window grey is dark")
	}
	if isDarkRGB(239, 240, 241) {
		t.Fatal("Breeze window grey is light")
	}
}
