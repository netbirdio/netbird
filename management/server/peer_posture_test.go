package server

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

func diffFrom(oldMeta, newMeta nbpeer.PeerSystemMeta, oldLoc, newLoc nbpeer.Location) *nbpeer.MetaDiff {
	return &nbpeer.MetaDiff{
		OldMeta:     oldMeta,
		NewMeta:     newMeta,
		OldLocation: oldLoc,
		NewLocation: newLoc,
	}
}

func postureBundle(def nmdata.ChecksDefinition) []*nmdata.PostureChecks {
	return []*nmdata.PostureChecks{{Checks: def}}
}

func TestMetaDiffAffectsPosture_NBVersion(t *testing.T) {
	c := postureBundle(nmdata.ChecksDefinition{NBVersionCheck: &nmdata.NBVersionCheck{MinVersion: "1.2.0"}})

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
			assert.Equal(t, tt.want, metaDiffAffectsPosture(diff, c))
		})
	}
}

func TestMetaDiffAffectsPosture_OSVersion_KernelBumpWithinMin(t *testing.T) {
	c := postureBundle(nmdata.ChecksDefinition{OSVersionCheck: &nmdata.OSVersionCheck{
		Linux: &nmdata.MinKernelVersionCheck{MinKernelVersion: "5.0.0"},
	}})

	withinMin := diffFrom(
		nbpeer.PeerSystemMeta{GoOS: "linux", KernelVersion: "5.10.0-arch1"},
		nbpeer.PeerSystemMeta{GoOS: "linux", KernelVersion: "5.15.0-arch2"},
		nbpeer.Location{}, nbpeer.Location{},
	)
	assert.False(t, metaDiffAffectsPosture(withinMin, c))

	crossesDown := diffFrom(
		nbpeer.PeerSystemMeta{GoOS: "linux", KernelVersion: "5.10.0-arch1"},
		nbpeer.PeerSystemMeta{GoOS: "linux", KernelVersion: "4.19.0-arch1"},
		nbpeer.Location{}, nbpeer.Location{},
	)
	assert.True(t, metaDiffAffectsPosture(crossesDown, c))
}

func TestMetaDiffAffectsPosture_OSVersion_GoOSSwitchFlipsVerdict(t *testing.T) {
	c := postureBundle(nmdata.ChecksDefinition{OSVersionCheck: &nmdata.OSVersionCheck{
		Linux: &nmdata.MinKernelVersionCheck{MinKernelVersion: "6.0.0"},
	}})

	diff := diffFrom(
		nbpeer.PeerSystemMeta{GoOS: "freebsd"},
		nbpeer.PeerSystemMeta{GoOS: "linux", KernelVersion: "4.19.0"},
		nbpeer.Location{}, nbpeer.Location{},
	)
	assert.True(t, metaDiffAffectsPosture(diff, c))
}

func TestMetaDiffAffectsPosture_Process_GoOSSwitchFlipsVerdict(t *testing.T) {
	c := postureBundle(nmdata.ChecksDefinition{ProcessCheck: &nmdata.ProcessCheck{
		Processes: []nmdata.Process{{LinuxPath: "/usr/bin/foo"}},
	}})

	files := []nbpeer.File{{Path: "/usr/bin/foo", ProcessIsRunning: true}}
	diff := diffFrom(
		nbpeer.PeerSystemMeta{GoOS: "linux", Files: files},
		nbpeer.PeerSystemMeta{GoOS: "windows", Files: files},
		nbpeer.Location{}, nbpeer.Location{},
	)
	assert.True(t, metaDiffAffectsPosture(diff, c))
}

func TestMetaDiffAffectsPosture_Process_UnrelatedFileChange(t *testing.T) {
	c := postureBundle(nmdata.ChecksDefinition{ProcessCheck: &nmdata.ProcessCheck{
		Processes: []nmdata.Process{{LinuxPath: "/usr/bin/foo"}},
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
	assert.False(t, metaDiffAffectsPosture(diff, c))
}

func TestMetaDiffAffectsPosture_GeoLocation(t *testing.T) {
	c := postureBundle(nmdata.ChecksDefinition{GeoLocationCheck: &nmdata.GeoLocationCheck{
		Action:    posture.CheckActionAllow,
		Locations: []nmdata.GeoLocation{{CountryCode: "DE"}},
	}})

	stayAllowed := diffFrom(
		nbpeer.PeerSystemMeta{}, nbpeer.PeerSystemMeta{},
		nbpeer.Location{CountryCode: "DE", CityName: "Berlin"},
		nbpeer.Location{CountryCode: "DE", CityName: "Munich"},
	)
	assert.False(t, metaDiffAffectsPosture(stayAllowed, c))

	moveOut := diffFrom(
		nbpeer.PeerSystemMeta{}, nbpeer.PeerSystemMeta{},
		nbpeer.Location{CountryCode: "DE"},
		nbpeer.Location{CountryCode: "FR"},
	)
	assert.True(t, metaDiffAffectsPosture(moveOut, c))
}

func TestMetaDiffAffectsPosture_PeerNetworkRange_ConnectionIP(t *testing.T) {
	c := postureBundle(nmdata.ChecksDefinition{PeerNetworkRangeCheck: &nmdata.PeerNetworkRangeCheck{
		Action: posture.CheckActionAllow,
		Ranges: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}})

	movesOutOfRange := diffFrom(
		nbpeer.PeerSystemMeta{}, nbpeer.PeerSystemMeta{},
		nbpeer.Location{ConnectionIP: net.ParseIP("10.1.2.3")},
		nbpeer.Location{ConnectionIP: net.ParseIP("8.8.8.8")},
	)
	assert.True(t, metaDiffAffectsPosture(movesOutOfRange, c))

	staysInRange := diffFrom(
		nbpeer.PeerSystemMeta{}, nbpeer.PeerSystemMeta{},
		nbpeer.Location{ConnectionIP: net.ParseIP("10.1.2.3")},
		nbpeer.Location{ConnectionIP: net.ParseIP("10.9.9.9")},
	)
	assert.False(t, metaDiffAffectsPosture(staysInRange, c))
}

func TestMetaDiffAffectsPosture_IrrelevantFieldChange(t *testing.T) {
	c := postureBundle(nmdata.ChecksDefinition{
		NBVersionCheck:   &nmdata.NBVersionCheck{MinVersion: "1.0.0"},
		GeoLocationCheck: &nmdata.GeoLocationCheck{Action: posture.CheckActionAllow, Locations: []nmdata.GeoLocation{{CountryCode: "DE"}}},
	})

	diff := diffFrom(
		nbpeer.PeerSystemMeta{Hostname: "old", WtVersion: "1.5.0"},
		nbpeer.PeerSystemMeta{Hostname: "new", WtVersion: "1.5.0"},
		nbpeer.Location{CountryCode: "DE"}, nbpeer.Location{CountryCode: "DE"},
	)
	assert.False(t, metaDiffAffectsPosture(diff, c))
}

func TestMetaDiffAffectsPosture_NoChecks(t *testing.T) {
	diff := diffFrom(
		nbpeer.PeerSystemMeta{WtVersion: "1.0.0"},
		nbpeer.PeerSystemMeta{WtVersion: "2.0.0"},
		nbpeer.Location{}, nbpeer.Location{},
	)
	assert.False(t, metaDiffAffectsPosture(diff, nil))
}

func TestProcessPeerPostureChecks(t *testing.T) {
	policy := &types.Policy{
		Enabled:             true,
		SourcePostureChecks: []string{"pc1"},
		Rules: []*types.PolicyRule{
			{Enabled: false, Sources: []string{"g-disabled"}, SourceResource: types.Resource{ID: "peer-disabled", Type: types.ResourceTypePeer}},
			{Enabled: true, Sources: []string{"g-src"}, Destinations: []string{"g-dst"}},
			{Enabled: true, SourceResource: types.Resource{ID: "peer-direct", Type: types.ResourceTypePeer}, Destinations: []string{"g-dst"}},
			{Enabled: true, SourceResource: types.Resource{ID: "peer-as-host", Type: types.ResourceTypeHost}, Destinations: []string{"g-dst"}},
		},
	}

	assert.Equal(t, []string{"pc1"}, processPeerPostureChecks(policy, "peer-in-group", []string{"g-src"}), "source group member")
	assert.Equal(t, []string{"pc1"}, processPeerPostureChecks(policy, "peer-direct", nil), "direct source peer")
	assert.Empty(t, processPeerPostureChecks(policy, "peer-elsewhere", []string{"g-dst"}), "destination-only peer")
	assert.Empty(t, processPeerPostureChecks(policy, "peer-disabled", []string{"g-disabled"}), "disabled rule")
	assert.Empty(t, processPeerPostureChecks(policy, "peer-as-host", nil), "source resource of a non-peer type")
}
