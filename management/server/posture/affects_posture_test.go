package posture

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

// diffFrom builds a MetaDiff from the old/new snapshots AffectsPosture replays against.
func diffFrom(oldMeta, newMeta nbpeer.PeerSystemMeta, oldLoc, newLoc nbpeer.Location) *nbpeer.MetaDiff {
	return &nbpeer.MetaDiff{
		OldMeta:     oldMeta,
		NewMeta:     newMeta,
		OldLocation: oldLoc,
		NewLocation: newLoc,
	}
}

func checks(def ChecksDefinition) []*Checks {
	return []*Checks{{Checks: def}}
}

func TestAffectsPosture_NilDiff(t *testing.T) {
	assert.False(t, AffectsPosture(context.Background(), nil, checks(ChecksDefinition{
		NBVersionCheck: &NBVersionCheck{MinVersion: "1.0.0"},
	})))
}

func TestAffectsPosture_NBVersion(t *testing.T) {
	c := checks(ChecksDefinition{NBVersionCheck: &NBVersionCheck{MinVersion: "1.2.0"}})

	tests := []struct {
		name           string
		oldVer, newVer string
		want           bool
	}{
		{"both above min, no flip", "1.3.0", "1.4.0", false},
		{"both below min, no flip", "1.0.0", "1.1.0", false},
		{"crosses up below->above", "1.1.0", "1.3.0", true},
		{"crosses down above->below", "1.3.0", "1.1.0", true},
		{"unparsable old only -> flip", "garbage", "1.3.0", true},
		{"unparsable both -> no flip", "garbage", "junk", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := diffFrom(
				nbpeer.PeerSystemMeta{WtVersion: tt.oldVer},
				nbpeer.PeerSystemMeta{WtVersion: tt.newVer},
				nbpeer.Location{}, nbpeer.Location{},
			)
			assert.Equal(t, tt.want, AffectsPosture(context.Background(), diff, c))
		})
	}
}

func TestAffectsPosture_OSVersion_KernelBumpWithinMin(t *testing.T) {
	c := checks(ChecksDefinition{OSVersionCheck: &OSVersionCheck{
		Linux: &MinKernelVersionCheck{MinKernelVersion: "5.0.0"},
	}})

	// Kernel moves but stays above the minimum: verdict stays pass -> not affected.
	withinMin := diffFrom(
		nbpeer.PeerSystemMeta{GoOS: "linux", KernelVersion: "5.10.0-arch1"},
		nbpeer.PeerSystemMeta{GoOS: "linux", KernelVersion: "5.15.0-arch2"},
		nbpeer.Location{}, nbpeer.Location{},
	)
	assert.False(t, AffectsPosture(context.Background(), withinMin, c))

	// Kernel drops below the minimum: verdict flips pass -> fail -> affected.
	crossesDown := diffFrom(
		nbpeer.PeerSystemMeta{GoOS: "linux", KernelVersion: "5.10.0-arch1"},
		nbpeer.PeerSystemMeta{GoOS: "linux", KernelVersion: "4.19.0-arch1"},
		nbpeer.Location{}, nbpeer.Location{},
	)
	assert.True(t, AffectsPosture(context.Background(), crossesDown, c))
}

func TestAffectsPosture_OSVersion_GoOSSwitchFlipsVerdict(t *testing.T) {
	// Only Linux is constrained. An OS outside the switch (freebsd) passes; switching to a
	// failing linux kernel flips the verdict pass -> fail.
	c := checks(ChecksDefinition{OSVersionCheck: &OSVersionCheck{
		Linux: &MinKernelVersionCheck{MinKernelVersion: "6.0.0"},
	}})

	diff := diffFrom(
		nbpeer.PeerSystemMeta{GoOS: "freebsd"},
		nbpeer.PeerSystemMeta{GoOS: "linux", KernelVersion: "4.19.0"},
		nbpeer.Location{}, nbpeer.Location{},
	)
	assert.True(t, AffectsPosture(context.Background(), diff, c))
}

func TestAffectsPosture_Process_GoOSSwitchFlipsVerdict(t *testing.T) {
	// Process runs at a linux path. Switching GoOS to windows (no WindowsPath configured)
	// flips the verdict.
	c := checks(ChecksDefinition{ProcessCheck: &ProcessCheck{
		Processes: []Process{{LinuxPath: "/usr/bin/foo"}},
	}})

	files := []nbpeer.File{{Path: "/usr/bin/foo", ProcessIsRunning: true}}
	diff := diffFrom(
		nbpeer.PeerSystemMeta{GoOS: "linux", Files: files},
		nbpeer.PeerSystemMeta{GoOS: "windows", Files: files},
		nbpeer.Location{}, nbpeer.Location{},
	)
	assert.True(t, AffectsPosture(context.Background(), diff, c))
}

func TestAffectsPosture_Process_UnrelatedFileChange(t *testing.T) {
	// A tracked process stays running while an unrelated file is added: the verdict does
	// not move, so posture is not affected.
	c := checks(ChecksDefinition{ProcessCheck: &ProcessCheck{
		Processes: []Process{{LinuxPath: "/usr/bin/foo"}},
	}})

	diff := diffFrom(
		nbpeer.PeerSystemMeta{GoOS: "linux", Files: []nbpeer.File{
			{Path: "/usr/bin/foo", ProcessIsRunning: true},
		}},
		nbpeer.PeerSystemMeta{GoOS: "linux", Files: []nbpeer.File{
			{Path: "/usr/bin/foo", ProcessIsRunning: true},
			{Path: "/usr/bin/bar", ProcessIsRunning: true},
		}},
		nbpeer.Location{}, nbpeer.Location{},
	)
	assert.False(t, AffectsPosture(context.Background(), diff, c))
}

func TestAffectsPosture_GeoLocation(t *testing.T) {
	c := checks(ChecksDefinition{GeoLocationCheck: &GeoLocationCheck{
		Action:    CheckActionAllow,
		Locations: []Location{{CountryCode: "DE"}},
	}})

	// Moving within allowed countries keeps the verdict; moving out flips it.
	stayAllowed := diffFrom(
		nbpeer.PeerSystemMeta{}, nbpeer.PeerSystemMeta{},
		nbpeer.Location{CountryCode: "DE", CityName: "Berlin"},
		nbpeer.Location{CountryCode: "DE", CityName: "Munich"},
	)
	assert.False(t, AffectsPosture(context.Background(), stayAllowed, c))

	moveOut := diffFrom(
		nbpeer.PeerSystemMeta{}, nbpeer.PeerSystemMeta{},
		nbpeer.Location{CountryCode: "DE"},
		nbpeer.Location{CountryCode: "FR"},
	)
	assert.True(t, AffectsPosture(context.Background(), moveOut, c))
}

func TestAffectsPosture_PeerNetworkRange_ConnectionIP(t *testing.T) {
	// The check reads the connection IP. Moving out of the allowed range flips the verdict;
	// moving within it does not.
	_, allowed, _ := net.ParseCIDR("10.0.0.0/8")
	c := checks(ChecksDefinition{PeerNetworkRangeCheck: &PeerNetworkRangeCheck{
		Action: CheckActionAllow,
		Ranges: []netip.Prefix{netip.MustParsePrefix(allowed.String())},
	}})

	movesOutOfRange := diffFrom(
		nbpeer.PeerSystemMeta{}, nbpeer.PeerSystemMeta{},
		nbpeer.Location{ConnectionIP: net.ParseIP("10.1.2.3")},
		nbpeer.Location{ConnectionIP: net.ParseIP("8.8.8.8")},
	)
	assert.True(t, AffectsPosture(context.Background(), movesOutOfRange, c))

	staysInRange := diffFrom(
		nbpeer.PeerSystemMeta{}, nbpeer.PeerSystemMeta{},
		nbpeer.Location{ConnectionIP: net.ParseIP("10.1.2.3")},
		nbpeer.Location{ConnectionIP: net.ParseIP("10.9.9.9")},
	)
	assert.False(t, AffectsPosture(context.Background(), staysInRange, c))
}

func TestAffectsPosture_IrrelevantFieldChange(t *testing.T) {
	// Hostname changes but no check reads it: not affected even with checks present.
	c := checks(ChecksDefinition{
		NBVersionCheck:   &NBVersionCheck{MinVersion: "1.0.0"},
		GeoLocationCheck: &GeoLocationCheck{Action: CheckActionAllow, Locations: []Location{{CountryCode: "DE"}}},
	})

	diff := diffFrom(
		nbpeer.PeerSystemMeta{Hostname: "old", WtVersion: "1.5.0"},
		nbpeer.PeerSystemMeta{Hostname: "new", WtVersion: "1.5.0"},
		nbpeer.Location{CountryCode: "DE"}, nbpeer.Location{CountryCode: "DE"},
	)
	assert.False(t, AffectsPosture(context.Background(), diff, c))
}

func TestAffectsPosture_NoChecks(t *testing.T) {
	diff := diffFrom(
		nbpeer.PeerSystemMeta{WtVersion: "1.0.0"},
		nbpeer.PeerSystemMeta{WtVersion: "2.0.0"},
		nbpeer.Location{}, nbpeer.Location{},
	)
	assert.False(t, AffectsPosture(context.Background(), diff, nil))
}
