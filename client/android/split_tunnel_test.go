package android

import (
	"reflect"
	"testing"
)

func TestNormalizeSplitTunnelMode(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want string
	}{
		{name: "exclude is kept", mode: SplitTunnelModeExclude, want: SplitTunnelModeExclude},
		{name: "include is kept", mode: SplitTunnelModeInclude, want: SplitTunnelModeInclude},
		{name: "off is kept", mode: SplitTunnelModeOff, want: SplitTunnelModeOff},
		{name: "empty falls back to off", mode: "", want: SplitTunnelModeOff},
		{name: "a mode from a newer build falls back to off", mode: "only-work-apps", want: SplitTunnelModeOff},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeSplitTunnelMode(tt.mode); got != tt.want {
				t.Errorf("normalizeSplitTunnelMode(%q) = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

func TestSettingsFromSection(t *testing.T) {
	got := settingsFromSection(splitTunnelSection{
		Mode:     SplitTunnelModeExclude,
		Excluded: []string{"com.example.a", "com.example.b"},
		Included: []string{"com.example.c"},
	})

	if got.Mode != SplitTunnelModeExclude {
		t.Errorf("mode = %q, want %q", got.Mode, SplitTunnelModeExclude)
	}
	if got.Excluded.Size() != 2 || got.Excluded.Get(0) != "com.example.a" {
		t.Errorf("excluded = %v, want the two stored packages", packagesOf(got.Excluded))
	}
	if got.Included.Size() != 1 || got.Included.Get(0) != "com.example.c" {
		t.Errorf("included = %v, want the stored package", packagesOf(got.Included))
	}
}

// A profile that has never stored anything decodes into an empty section, and
// must come back as settings that carry every application rather than as nil
// lists the caller would have to guard against.
func TestSettingsFromEmptySectionCarriesEverything(t *testing.T) {
	got := settingsFromSection(splitTunnelSection{})

	if got.Mode != SplitTunnelModeOff {
		t.Errorf("mode = %q, want %q", got.Mode, SplitTunnelModeOff)
	}
	if got.Excluded == nil || got.Included == nil {
		t.Fatal("both selections must be usable lists, not nil")
	}
	if got.Excluded.Size() != 0 || got.Included.Size() != 0 {
		t.Errorf("selections = %v/%v, want both empty", packagesOf(got.Excluded), packagesOf(got.Included))
	}
}

func TestSectionFromSettingsRoundTrip(t *testing.T) {
	settings := NewSplitTunnelSettings()
	settings.Mode = SplitTunnelModeInclude
	settings.Included.Add("com.example.a")
	settings.Excluded.Add("com.example.b")

	section := sectionFromSettings(settings)
	back := settingsFromSection(section)

	if back.Mode != SplitTunnelModeInclude {
		t.Errorf("mode = %q, want %q", back.Mode, SplitTunnelModeInclude)
	}
	if !reflect.DeepEqual(packagesOf(back.Included), []string{"com.example.a"}) {
		t.Errorf("included = %v, want [com.example.a]", packagesOf(back.Included))
	}
	// The inactive selection survives, so switching mode back does not make the
	// user pick their applications again.
	if !reflect.DeepEqual(packagesOf(back.Excluded), []string{"com.example.b"}) {
		t.Errorf("excluded = %v, want [com.example.b]", packagesOf(back.Excluded))
	}
}

func TestSectionFromNilSettings(t *testing.T) {
	section := sectionFromSettings(nil)

	if section.Mode != SplitTunnelModeOff {
		t.Errorf("mode = %q, want %q", section.Mode, SplitTunnelModeOff)
	}
	if len(section.Excluded) != 0 || len(section.Included) != 0 {
		t.Errorf("selections = %v/%v, want both empty", section.Excluded, section.Included)
	}
}

func TestPackageListIgnoresEmptyAndBounds(t *testing.T) {
	list := NewPackageList()
	list.Add("com.example.a")
	list.Add("")

	if list.Size() != 1 {
		t.Errorf("size = %d, want 1", list.Size())
	}
	if list.Get(-1) != "" || list.Get(5) != "" {
		t.Error("out of range access must return an empty string")
	}
}
