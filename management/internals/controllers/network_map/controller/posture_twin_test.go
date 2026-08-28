package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/types"
)

func postureSelectionData(policies ...*nmdata.Policy) *networkmap.NetworkMapData {
	return &networkmap.NetworkMapData{
		Groups:   map[string]*nmdata.Group{"g-src": {ID: "g-src", Peers: []string{"peer-group"}}},
		Policies: policies,
		PostureChecks: map[string]*nmdata.PostureChecks{
			"pc1": {ID: "pc1", Checks: nmdata.ChecksDefinition{NBVersionCheck: &nmdata.NBVersionCheck{MinVersion: "0.30.0"}}},
		},
	}
}

func gatedPolicy(id string, rule *nmdata.PolicyRule, checkIDs ...string) *nmdata.Policy {
	return &nmdata.Policy{ID: id, Enabled: true, SourcePostureChecks: checkIDs, Rules: []*nmdata.PolicyRule{rule}}
}

func checkIDs(checks []*nmdata.PostureChecks) []string {
	ids := make([]string, 0, len(checks))
	for _, c := range checks {
		ids = append(ids, c.ID)
	}
	return ids
}

func TestPeerPostureChecksFromData_SelectsPolicySourcePeers(t *testing.T) {
	groupRule := &nmdata.PolicyRule{ID: "r-group", Enabled: true, Sources: []string{"g-src"}, Destinations: []string{"g-dst"}}
	directRule := &nmdata.PolicyRule{ID: "r-direct", Enabled: true, SourceResource: nmdata.Resource{ID: "peer-direct", Type: string(types.ResourceTypePeer)}, Destinations: []string{"g-dst"}}

	t.Run("source group member and direct source peer both get the checks", func(t *testing.T) {
		nmData := postureSelectionData(gatedPolicy("p1", groupRule, "pc1"), gatedPolicy("p2", directRule, "pc1"))

		assert.Equal(t, []string{"pc1"}, checkIDs(peerPostureChecksFromData(nmData, "peer-group")))
		assert.Equal(t, []string{"pc1"}, checkIDs(peerPostureChecksFromData(nmData, "peer-direct")))
		assert.Empty(t, peerPostureChecksFromData(nmData, "peer-elsewhere"))
	})

	t.Run("source resource of a non-peer type never matches a peer", func(t *testing.T) {
		hostRule := &nmdata.PolicyRule{ID: "r-host", Enabled: true, SourceResource: nmdata.Resource{ID: "peer-direct", Type: string(types.ResourceTypeHost)}, Destinations: []string{"g-dst"}}
		nmData := postureSelectionData(gatedPolicy("p1", hostRule, "pc1"))

		assert.Empty(t, peerPostureChecksFromData(nmData, "peer-direct"))
	})

	t.Run("same check through two policies is returned once", func(t *testing.T) {
		nmData := postureSelectionData(gatedPolicy("p1", groupRule, "pc1"), gatedPolicy("p2", groupRule, "pc1"))

		assert.Equal(t, []string{"pc1"}, checkIDs(peerPostureChecksFromData(nmData, "peer-group")))
	})

	t.Run("disabled policy, disabled rule and dangling check are ignored", func(t *testing.T) {
		disabledPolicy := gatedPolicy("p-off", groupRule, "pc1")
		disabledPolicy.Enabled = false
		disabledRule := &nmdata.PolicyRule{ID: "r-off", Enabled: false, Sources: []string{"g-src"}}
		nmData := postureSelectionData(disabledPolicy, gatedPolicy("p-rule-off", disabledRule, "pc1"), gatedPolicy("p-dangling", groupRule, "pc-missing"))

		assert.Empty(t, peerPostureChecksFromData(nmData, "peer-group"))
	})
}
