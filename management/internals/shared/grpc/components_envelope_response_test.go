package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// TestComputeSSHEnabledForPeer covers both Calculate-mirroring branches:
// explicit NetbirdSSH protocol, and the legacy implicit case where a
// TCP/22 (or 22022 / ALL / port-range-covering-22) rule activates SSH when
// the destination peer has SSHEnabled=true locally.
func TestComputeSSHEnabledForPeer(t *testing.T) {
	const targetPeerID = "target"
	const targetGroupID = "g_dst"

	mkComponents := func(rule *nmdata.PolicyRule, sshEnabled bool) (*types.NetworkMapComponents, *nmdata.Peer) {
		peer := &nmdata.Peer{ID: targetPeerID, SSHEnabled: sshEnabled}
		return &types.NetworkMapComponents{
			Peers:  map[string]*nmdata.Peer{targetPeerID: peer},
			Groups: map[string]*nmdata.Group{targetGroupID: {Name: "dst", Peers: []string{targetPeerID}}},
			Policies: []*nmdata.Policy{{
				ID:      "p",
				Enabled: true,
				Rules:   []*nmdata.PolicyRule{rule},
			}},
		}, peer
	}

	cases := []struct {
		name        string
		peerSSH     bool
		rule        nmdata.PolicyRule
		wantEnabled bool
	}{
		{
			name:    "explicit-netbird-ssh-activates-regardless-of-peer-ssh",
			peerSSH: false,
			rule: nmdata.PolicyRule{
				Enabled: true, Protocol: string(types.PolicyRuleProtocolNetbirdSSH),
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "implicit-tcp-22-with-peer-ssh",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled: true, Protocol: string(types.PolicyRuleProtocolTCP), Ports: []string{"22"},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "implicit-tcp-22-without-peer-ssh-disabled",
			peerSSH: false,
			rule: nmdata.PolicyRule{
				Enabled: true, Protocol: string(types.PolicyRuleProtocolTCP), Ports: []string{"22"},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: false,
		},
		{
			name:    "implicit-tcp-22022-with-peer-ssh",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled: true, Protocol: string(types.PolicyRuleProtocolTCP), Ports: []string{"22022"},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "implicit-all-protocol-with-peer-ssh",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled: true, Protocol: string(types.PolicyRuleProtocolALL),
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "implicit-port-range-covers-22",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled:      true,
				Protocol:     string(types.PolicyRuleProtocolTCP),
				PortRanges:   []nmdata.RulePortRange{{Start: 20, End: 30}},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "tcp-80-no-ssh",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled: true, Protocol: string(types.PolicyRuleProtocolTCP), Ports: []string{"80"},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: false,
		},
		{
			name:    "disabled-rule-skipped",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled: false, Protocol: string(types.PolicyRuleProtocolNetbirdSSH),
				Destinations: []string{targetGroupID},
			},
			wantEnabled: false,
		},
		{
			name:    "peer-not-in-destinations",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled: true, Protocol: string(types.PolicyRuleProtocolNetbirdSSH),
				Destinations: []string{"g_other"}, // target not in this group
			},
			wantEnabled: false,
		},
		{
			name:    "peer-typed-destination-resource-matches",
			peerSSH: false,
			rule: nmdata.PolicyRule{
				Enabled:             true,
				Protocol:            string(types.PolicyRuleProtocolNetbirdSSH),
				DestinationResource: nmdata.Resource{ID: targetPeerID, Type: string(types.ResourceTypePeer)},
			},
			wantEnabled: true,
		},
		{
			name:    "non-peer-destination-resource-falls-through-to-groups",
			peerSSH: false,
			rule: nmdata.PolicyRule{
				Enabled:             true,
				Protocol:            string(types.PolicyRuleProtocolNetbirdSSH),
				DestinationResource: nmdata.Resource{ID: targetPeerID, Type: "host"}, // wrong type
				Destinations:        []string{targetGroupID},                         // saved by group fallback
			},
			wantEnabled: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, peer := mkComponents(&tc.rule, tc.peerSSH)
			got := computeSSHEnabledForPeer(c, peer)
			assert.Equal(t, tc.wantEnabled, got)
		})
	}
}

// TestComputeSSHEnabledForPeer_TargetMissingFromComponents covers the
// belt-and-suspenders presence guard mirroring Calculate's
// getAllPeersFromGroups invariant.
func TestComputeSSHEnabledForPeer_TargetMissingFromComponents(t *testing.T) {
	peer := &nmdata.Peer{ID: "missing", SSHEnabled: true}
	c := &types.NetworkMapComponents{
		Peers: map[string]*nmdata.Peer{}, // target peer NOT present
		Groups: map[string]*nmdata.Group{
			"g": {Peers: []string{"missing"}},
		},
		Policies: []*nmdata.Policy{{
			ID: "p", Enabled: true,
			Rules: []*nmdata.PolicyRule{{
				Enabled: true, Protocol: string(types.PolicyRuleProtocolNetbirdSSH),
				Destinations: []string{"g"},
			}},
		}},
	}
	assert.False(t, computeSSHEnabledForPeer(c, peer),
		"missing target peer must short-circuit to false, not consult policies")
}

// TestComputeSSHEnabledForPeer_NilInputs guards the cheap nil-checks at
// function entry — Calculate doesn't accept nil either, but the helper is
// exported indirectly via ToComponentSyncResponse and may receive nil
// components on graceful-degrade paths.
func TestComputeSSHEnabledForPeer_NilInputs(t *testing.T) {
	assert.False(t, computeSSHEnabledForPeer(nil, &nmdata.Peer{ID: "x"}))
	assert.False(t, computeSSHEnabledForPeer(&types.NetworkMapComponents{}, nil))
}
