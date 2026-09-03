package android

// SplitTunnelMode is which of the two selections, if either, the tunnel applies.
// Its values land in the profile's stored preferences, so the constants below
// are append-only and must never be reordered.
type SplitTunnelMode int

const (
	modeOff SplitTunnelMode = iota
	modeExclude
	modeInclude
)

// The same modes as basic ints. gomobile drops a constant whose type is not a
// basic one, so these are what reaches the generated Java bindings, and they
// keep the Android side tied to the values above instead of repeating 0, 1, 2.
const (
	SplitTunnelModeOff     = int(modeOff)
	SplitTunnelModeExclude = int(modeExclude)
	SplitTunnelModeInclude = int(modeInclude)
)

type splitTunnelSection struct {
	Mode     SplitTunnelMode `json:"mode"`
	Excluded []string        `json:"excluded"`
	Included []string        `json:"included"`
}

// PackageList wraps []string for gomobile compatibility.
type PackageList struct {
	items []string
}

// NewPackageList creates an empty list to fill via Add.
func NewPackageList() *PackageList {
	return &PackageList{}
}

// Add appends a package name, ignoring empty ones.
func (l *PackageList) Add(s string) {
	if s == "" {
		return
	}
	l.items = append(l.items, s)
}

// Size returns the number of entries.
func (l *PackageList) Size() int {
	return len(l.items)
}

// Get returns the entry at index i, or an empty string when out of range.
func (l *PackageList) Get(i int) string {
	if i < 0 || i >= len(l.items) {
		return ""
	}
	return l.items[i]
}

// SplitTunnelSettings is one profile's choice of which applications the tunnel
// carries. The two selections are kept apart because the platform applies one
// or the other and never both, and so that switching mode does not throw away
// the picks made in the other one.
//
// Mode is an int rather than a SplitTunnelMode because gomobile carries only
// basic types across the binding. It holds one of the SplitTunnelMode*
// constants.
type SplitTunnelSettings struct {
	Mode     int
	Excluded *PackageList
	Included *PackageList
}

// NewSplitTunnelSettings creates settings that carry every application.
func NewSplitTunnelSettings() *SplitTunnelSettings {
	return &SplitTunnelSettings{
		Mode:     SplitTunnelModeOff,
		Excluded: NewPackageList(),
		Included: NewPackageList(),
	}
}

func packagesOf(list *PackageList) []string {
	if list == nil {
		return nil
	}
	out := make([]string, 0, len(list.items))
	out = append(out, list.items...)
	return out
}

// normalizeSplitTunnelMode maps anything outside the known set to off, so a mode
// written by a newer build degrades to carrying every application rather than to
// some other mode's behaviour.
func normalizeSplitTunnelMode(mode SplitTunnelMode) SplitTunnelMode {
	switch mode {
	case modeExclude, modeInclude:
		return mode
	default:
		return modeOff
	}
}

func settingsFromSection(section splitTunnelSection) *SplitTunnelSettings {
	out := NewSplitTunnelSettings()
	out.Mode = int(normalizeSplitTunnelMode(section.Mode))
	for _, pkg := range section.Excluded {
		out.Excluded.Add(pkg)
	}
	for _, pkg := range section.Included {
		out.Included.Add(pkg)
	}
	return out
}

func sectionFromSettings(settings *SplitTunnelSettings) splitTunnelSection {
	if settings == nil {
		settings = NewSplitTunnelSettings()
	}
	return splitTunnelSection{
		Mode:     normalizeSplitTunnelMode(SplitTunnelMode(settings.Mode)),
		Excluded: packagesOf(settings.Excluded),
		Included: packagesOf(settings.Included),
	}
}
