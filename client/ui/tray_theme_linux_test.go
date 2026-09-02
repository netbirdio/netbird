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

// plasmaStyle installs a Plasma style of that name under XDG_DATA_HOME. An
// empty colours body installs the style without a colours file, which is what
// the stock "default" style looks like.
func plasmaStyle(t *testing.T, name, colours string) {
	t.Helper()
	data := t.TempDir()
	dir := filepath.Join(data, "plasma", "desktoptheme", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if colours != "" {
		if err := os.WriteFile(filepath.Join(dir, "colors"), []byte(colours), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XDG_DATA_HOME", data)
	// Keep the system dirs out of it so an installed breeze-dark cannot answer.
	t.Setenv("XDG_DATA_DIRS", filepath.Join(data, "empty"))
}

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
	// Point the Plasma style lookup at empty dirs so a style installed on the
	// host cannot answer for a test that did not install one itself. Tests that
	// want a style call plasmaStyle, which overrides these.
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "empty-data-home"))
	t.Setenv("XDG_DATA_DIRS", filepath.Join(dir, "empty-data-dirs"))
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
// has to outrank it in both directions. The styles are installed into the test's
// own XDG_DATA_HOME: reading whatever the host happens to ship would make the
// result depend on the machine.
func TestKdePanelIsDarkPinnedStyleOutranksScheme(t *testing.T) {
	for _, tc := range []struct {
		name         string
		kdeglobals   string
		style        string
		styleColours string
		wantDark     bool
	}{
		{"dark style, light scheme", kdeglobalsLight, "breeze-dark", kdeglobalsDark, true},
		{"light style, dark scheme", kdeglobalsDark, "breeze-light", kdeglobalsLight, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kdeConfig(t, tc.kdeglobals, "[Theme]\nname="+tc.style+"\n")
			plasmaStyle(t, tc.style, tc.styleColours)
			dark, ok := kdePanelIsDark()
			if !ok {
				t.Fatal("expected a conclusive answer from the pinned style")
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

// The panel follows the pinned style's own colours, not its name. Reproduces
// the measured case: a neutrally named style shipping dark colours while
// kdeglobals reports light.
func TestPlasmaStyleIsDarkUsesStyleColours(t *testing.T) {
	for _, tc := range []struct {
		name     string
		style    string
		colours  string
		wantDark bool
	}{
		{"neutral name, dark colours", "nbtestneutral", kdeglobalsDark, true},
		{"neutral name, light colours", "nbtestneutral", kdeglobalsLight, false},
		{"name says dark, colours are light", "midnight-dark", kdeglobalsLight, false},
		{"name says light, colours are dark", "daylight", kdeglobalsDark, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kdeConfig(t, kdeglobalsLight, "[Theme]\nname="+tc.style+"\n")
			plasmaStyle(t, tc.style, tc.colours)
			dark, ok := plasmaStyleIsDark()
			if !ok {
				t.Fatal("a style shipping colours should be conclusive")
			}
			if dark != tc.wantDark {
				t.Fatalf("dark = %v, want %v", dark, tc.wantDark)
			}
		})
	}
}

// End to end through kdePanelIsDark: the style's colours must beat kdeglobals.
func TestKdePanelIsDarkStyleColoursBeatColourScheme(t *testing.T) {
	kdeConfig(t, kdeglobalsLight, "[Theme]\nname=nbtestneutral\n")
	plasmaStyle(t, "nbtestneutral", kdeglobalsDark)
	dark, ok := kdePanelIsDark()
	if !ok {
		t.Fatal("expected a conclusive answer")
	}
	if !dark {
		t.Fatal("a dark-coloured style on a Light scheme is a dark panel")
	}
}

// A style with no colours file is the "default" case: it follows the scheme.
func TestPlasmaStyleIsDarkNoColoursFile(t *testing.T) {
	kdeConfig(t, kdeglobalsLight, "[Theme]\nname=default\n")
	plasmaStyle(t, "default", "")
	if _, ok := plasmaStyleIsDark(); ok {
		t.Fatal("a style without colours must defer to the colour scheme")
	}
	// and the whole resolution then lands on the light scheme
	dark, ok := kdePanelIsDark()
	if !ok || dark {
		t.Fatalf("kdePanelIsDark() = (%v, %v), want (false, true)", dark, ok)
	}
}

func TestPlasmaStyleIsDarkInconclusive(t *testing.T) {
	t.Run("no plasmarc", func(t *testing.T) {
		kdeConfig(t, kdeglobalsLight, "")
		plasmaStyle(t, "unused", kdeglobalsDark)
		if _, ok := plasmaStyleIsDark(); ok {
			t.Fatal("expected not-ok with no plasmarc")
		}
	})
	t.Run("empty style name", func(t *testing.T) {
		kdeConfig(t, kdeglobalsLight, "[Theme]\nname=\n")
		if _, ok := plasmaStyleIsDark(); ok {
			t.Fatal("expected not-ok for an empty style name")
		}
	})
	t.Run("style not installed", func(t *testing.T) {
		kdeConfig(t, kdeglobalsLight, "[Theme]\nname=absent\n")
		plasmaStyle(t, "somethingelse", kdeglobalsDark)
		if _, ok := plasmaStyleIsDark(); ok {
			t.Fatal("expected not-ok when the style is not installed")
		}
	})
	// The name indexes a directory and comes from a config file.
	t.Run("path traversal is rejected", func(t *testing.T) {
		kdeConfig(t, kdeglobalsLight, "[Theme]\nname=../../../../etc\n")
		plasmaStyle(t, "unused", kdeglobalsDark)
		if _, ok := plasmaStyleIsDark(); ok {
			t.Fatal("expected not-ok for a traversing style name")
		}
	})
}

// A local style of the same name shadows the system one, as in Plasma.
func TestPlasmaStyleDirsPreferUserData(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/home/someone/.local/share")
	t.Setenv("XDG_DATA_DIRS", "/usr/local/share:/usr/share")
	got := plasmaStyleDirs("breeze-dark")
	want := []string{
		"/home/someone/.local/share/plasma/desktoptheme/breeze-dark",
		"/usr/local/share/plasma/desktoptheme/breeze-dark",
		"/usr/share/plasma/desktoptheme/breeze-dark",
	}
	if len(got) != len(want) {
		t.Fatalf("plasmaStyleDirs() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("plasmaStyleDirs()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
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
