package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

// TestComputeSSHEnabledForPeer covers both Calculate-mirroring branches:
// explicit NetbirdSSH protocol, and the legacy implicit case where a
// TCP/22 (or 22022 / ALL / port-range-covering-22) rule activates SSH when
// the destination peer has SSHEnabled=true locally.
func TestComputeSSHEnabledForPeer(t *testing.T) {
	const targetPeerID = "target"
	const targetGroupID = "g_dst"

	mkComponents := func(rule *types.PolicyRule, sshEnabled bool) (*types.NetworkMapComponents, *nbpeer.Peer) {
		peer := &nbpeer.Peer{ID: targetPeerID, SSHEnabled: sshEnabled}
		group := &types.Group{ID: targetGroupID, Name: "dst", Peers: []string{targetPeerID}}
		return &types.NetworkMapComponents{
			Peers:  map[string]*nbpeer.Peer{targetPeerID: peer},
			Groups: map[string]*types.Group{targetGroupID: group},
			Policies: []*types.Policy{{
				ID:      "p",
				Enabled: true,
				Rules:   []*types.PolicyRule{rule},
			}},
		}, peer
	}

	cases := []struct {
		name        string
		peerSSH     bool
		rule        types.PolicyRule
		wantEnabled bool
	}{
		{
			name:    "explicit-netbird-ssh-activates-regardless-of-peer-ssh",
			peerSSH: false,
			rule: types.PolicyRule{
				Enabled: true, Protocol: types.PolicyRuleProtocolNetbirdSSH,
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "implicit-tcp-22-with-peer-ssh",
			peerSSH: true,
			rule: types.PolicyRule{
				Enabled: true, Protocol: types.PolicyRuleProtocolTCP, Ports: []string{"22"},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "implicit-tcp-22-without-peer-ssh-disabled",
			peerSSH: false,
			rule: types.PolicyRule{
				Enabled: true, Protocol: types.PolicyRuleProtocolTCP, Ports: []string{"22"},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: false,
		},
		{
			name:    "implicit-tcp-22022-with-peer-ssh",
			peerSSH: true,
			rule: types.PolicyRule{
				Enabled: true, Protocol: types.PolicyRuleProtocolTCP, Ports: []string{"22022"},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "implicit-all-protocol-with-peer-ssh",
			peerSSH: true,
			rule: types.PolicyRule{
				Enabled: true, Protocol: types.PolicyRuleProtocolALL,
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "implicit-port-range-covers-22",
			peerSSH: true,
			rule: types.PolicyRule{
				Enabled:      true,
				Protocol:     types.PolicyRuleProtocolTCP,
				PortRanges:   []types.RulePortRange{{Start: 20, End: 30}},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "tcp-80-no-ssh",
			peerSSH: true,
			rule: types.PolicyRule{
				Enabled: true, Protocol: types.PolicyRuleProtocolTCP, Ports: []string{"80"},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: false,
		},
		{
			name:    "disabled-rule-skipped",
			peerSSH: true,
			rule: types.PolicyRule{
				Enabled: false, Protocol: types.PolicyRuleProtocolNetbirdSSH,
				Destinations: []string{targetGroupID},
			},
			wantEnabled: false,
		},
		{
			name:    "peer-not-in-destinations",
			peerSSH: true,
			rule: types.PolicyRule{
				Enabled: true, Protocol: types.PolicyRuleProtocolNetbirdSSH,
				Destinations: []string{"g_other"}, // target not in this group
			},
			wantEnabled: false,
		},
		{
			name:    "peer-typed-destination-resource-matches",
			peerSSH: false,
			rule: types.PolicyRule{
				Enabled:             true,
				Protocol:            types.PolicyRuleProtocolNetbirdSSH,
				DestinationResource: types.Resource{ID: targetPeerID, Type: types.ResourceTypePeer},
			},
			wantEnabled: true,
		},
		{
			name:    "non-peer-destination-resource-falls-through-to-groups",
			peerSSH: false,
			rule: types.PolicyRule{
				Enabled:             true,
				Protocol:            types.PolicyRuleProtocolNetbirdSSH,
				DestinationResource: types.Resource{ID: targetPeerID, Type: "host"}, // wrong type
				Destinations:        []string{targetGroupID},                        // saved by group fallback
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
	peer := &nbpeer.Peer{ID: "missing", SSHEnabled: true}
	c := &types.NetworkMapComponents{
		Peers: map[string]*nbpeer.Peer{}, // target peer NOT present
		Groups: map[string]*types.Group{
			"g": {ID: "g", Peers: []string{"missing"}},
		},
		Policies: []*types.Policy{{
			ID: "p", Enabled: true,
			Rules: []*types.PolicyRule{{
				Enabled: true, Protocol: types.PolicyRuleProtocolNetbirdSSH,
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
	assert.False(t, computeSSHEnabledForPeer(nil, &nbpeer.Peer{ID: "x"}))
	assert.False(t, computeSSHEnabledForPeer(&types.NetworkMapComponents{}, nil))
}
