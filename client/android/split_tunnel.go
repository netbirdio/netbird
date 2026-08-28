package android

// Split tunnelling modes, stored as strings so an unknown value written by a
// newer build degrades to "off" rather than to some other mode's behaviour.
const (
	SplitTunnelModeOff     = "off"
	SplitTunnelModeExclude = "exclude"
	SplitTunnelModeInclude = "include"
)

type splitTunnelSection struct {
	Mode     string   `json:"mode"`
	Excluded []string `json:"excluded"`
	Included []string `json:"included"`
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
type SplitTunnelSettings struct {
	Mode     string
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

func normalizeSplitTunnelMode(mode string) string {
	switch mode {
	case SplitTunnelModeExclude, SplitTunnelModeInclude:
		return mode
	default:
		return SplitTunnelModeOff
	}
}

func settingsFromSection(section splitTunnelSection) *SplitTunnelSettings {
	out := NewSplitTunnelSettings()
	out.Mode = normalizeSplitTunnelMode(section.Mode)
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
		Mode:     normalizeSplitTunnelMode(settings.Mode),
		Excluded: packagesOf(settings.Excluded),
		Included: packagesOf(settings.Included),
	}
}
