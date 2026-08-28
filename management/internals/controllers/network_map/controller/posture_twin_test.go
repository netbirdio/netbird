package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

func TestPeerPostureChecksFromData_ReturnsTwinsUnchanged(t *testing.T) {
	check := &nmdata.PostureChecks{
		ID: "pc1",
		Checks: nmdata.ChecksDefinition{
			NBVersionCheck: &nmdata.NBVersionCheck{MinVersion: "0.30.0"},
			OSVersionCheck: &nmdata.OSVersionCheck{Linux: &nmdata.MinKernelVersionCheck{MinKernelVersion: "6.1"}},
		},
	}
	nmData := &networkmap.NetworkMapData{
		Groups: map[string]*nmdata.Group{"g1": {ID: "g1", Peers: []string{"peer1"}}},
		Policies: []*nmdata.Policy{{
			ID:                  "policy1",
			Enabled:             true,
			SourcePostureChecks: []string{"pc1"},
			Rules:               []*nmdata.PolicyRule{{ID: "rule1", Enabled: true, Sources: []string{"g1"}}},
		}},
		PostureChecks: map[string]*nmdata.PostureChecks{"pc1": check},
	}

	got := peerPostureChecksFromData(nmData, "peer1")
	require.Len(t, got, 1)
	assert.Same(t, check, got[0])
	assert.Len(t, got[0].GetChecks(), 2)

	assert.Empty(t, peerPostureChecksFromData(nmData, "peer-outside-source-group"))
}
