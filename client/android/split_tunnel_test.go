package android

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNormalizeSplitTunnelMode(t *testing.T) {
	tests := []struct {
		name string
		mode SplitTunnelMode
		want SplitTunnelMode
	}{
		{name: "exclude is kept", mode: modeExclude, want: modeExclude},
		{name: "include is kept", mode: modeInclude, want: modeInclude},
		{name: "off is kept", mode: modeOff, want: modeOff},
		{name: "a mode from a newer build falls back to off", mode: SplitTunnelMode(7), want: modeOff},
		{name: "a negative mode falls back to off", mode: SplitTunnelMode(-1), want: modeOff},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeSplitTunnelMode(tt.mode); got != tt.want {
				t.Errorf("normalizeSplitTunnelMode(%d) = %d, want %d", tt.mode, got, tt.want)
			}
		})
	}
}

// The constants the Android side reads must stay the values the store writes:
// gomobile carries the ints below, not the typed constants they mirror.
func TestSplitTunnelModeConstantsMirrorTheTypedOnes(t *testing.T) {
	if SplitTunnelModeOff != int(modeOff) {
		t.Errorf("off = %d, want %d", SplitTunnelModeOff, modeOff)
	}
	if SplitTunnelModeExclude != int(modeExclude) {
		t.Errorf("exclude = %d, want %d", SplitTunnelModeExclude, modeExclude)
	}
	if SplitTunnelModeInclude != int(modeInclude) {
		t.Errorf("include = %d, want %d", SplitTunnelModeInclude, modeInclude)
	}
}

func TestSettingsFromSection(t *testing.T) {
	got := settingsFromSection(splitTunnelSection{
		Mode:     modeExclude,
		Excluded: []string{"com.example.a", "com.example.b"},
		Included: []string{"com.example.c"},
	})

	if got.Mode != SplitTunnelModeExclude {
		t.Errorf("mode = %d, want %d", got.Mode, SplitTunnelModeExclude)
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
		t.Errorf("mode = %d, want %d", got.Mode, SplitTunnelModeOff)
	}
	if got.Excluded == nil || got.Included == nil {
		t.Fatal("both selections must be usable lists, not nil")
	}
	if got.Excluded.Size() != 0 || got.Included.Size() != 0 {
		t.Errorf("selections = %v/%v, want both empty", packagesOf(got.Excluded), packagesOf(got.Included))
	}
}

// The section is what the profile's preference file holds, so the mode has to
// survive a JSON round trip as the number the constants name.
func TestSectionEncodesTheModeAsItsNumber(t *testing.T) {
	raw, err := json.Marshal(sectionFromSettings(&SplitTunnelSettings{Mode: SplitTunnelModeInclude}))
	if err != nil {
		t.Fatalf("marshal section: %v", err)
	}

	var back splitTunnelSection
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal section: %v", err)
	}
	if back.Mode != modeInclude {
		t.Errorf("mode = %d, want %d, from %s", back.Mode, modeInclude, raw)
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
		t.Errorf("mode = %d, want %d", back.Mode, SplitTunnelModeInclude)
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

// A mode the Java side never sets, such as one left by a newer build, must not
// reach the stored section either.
func TestSectionFromSettingsNormalizesAnUnknownMode(t *testing.T) {
	section := sectionFromSettings(&SplitTunnelSettings{Mode: 7})

	if section.Mode != modeOff {
		t.Errorf("mode = %d, want %d", section.Mode, modeOff)
	}
}

func TestSectionFromNilSettings(t *testing.T) {
	section := sectionFromSettings(nil)

	if section.Mode != modeOff {
		t.Errorf("mode = %d, want %d", section.Mode, modeOff)
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
