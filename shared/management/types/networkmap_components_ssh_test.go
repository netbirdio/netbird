package types

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// TestPeerSSHEnabled covers both Calculate-mirroring branches:
// explicit NetbirdSSH protocol, and the legacy implicit case where a
// TCP/22 (or 22022 / ALL / port-range-covering-22) rule activates SSH when
// the destination peer has SSHEnabled=true locally.
func TestPeerSSHEnabled(t *testing.T) {
	const targetPeerID = "target"
	const targetGroupID = "g_dst"

	mkComponents := func(rule *nmdata.PolicyRule, sshEnabled bool) (*NetworkMapComponents, *nmdata.Peer) {
		peer := &nmdata.Peer{ID: targetPeerID, SSHEnabled: sshEnabled}
		return &NetworkMapComponents{
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
				Enabled: true, Protocol: string(PolicyRuleProtocolNetbirdSSH),
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "implicit-tcp-22-with-peer-ssh",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled: true, Protocol: string(PolicyRuleProtocolTCP), Ports: []string{"22"},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "implicit-tcp-22-without-peer-ssh-disabled",
			peerSSH: false,
			rule: nmdata.PolicyRule{
				Enabled: true, Protocol: string(PolicyRuleProtocolTCP), Ports: []string{"22"},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: false,
		},
		{
			name:    "implicit-tcp-22022-with-peer-ssh",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled: true, Protocol: string(PolicyRuleProtocolTCP), Ports: []string{"22022"},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "implicit-all-protocol-with-peer-ssh",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled: true, Protocol: string(PolicyRuleProtocolALL),
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "implicit-port-range-covers-22",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled:      true,
				Protocol:     string(PolicyRuleProtocolTCP),
				PortRanges:   []nmdata.RulePortRange{{Start: 20, End: 30}},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: true,
		},
		{
			name:    "tcp-80-no-ssh",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled: true, Protocol: string(PolicyRuleProtocolTCP), Ports: []string{"80"},
				Destinations: []string{targetGroupID},
			},
			wantEnabled: false,
		},
		{
			name:    "disabled-rule-skipped",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled: false, Protocol: string(PolicyRuleProtocolNetbirdSSH),
				Destinations: []string{targetGroupID},
			},
			wantEnabled: false,
		},
		{
			name:    "peer-not-in-destinations",
			peerSSH: true,
			rule: nmdata.PolicyRule{
				Enabled: true, Protocol: string(PolicyRuleProtocolNetbirdSSH),
				Destinations: []string{"g_other"}, // target not in this group
			},
			wantEnabled: false,
		},
		{
			name:    "peer-typed-destination-resource-matches",
			peerSSH: false,
			rule: nmdata.PolicyRule{
				Enabled:             true,
				Protocol:            string(PolicyRuleProtocolNetbirdSSH),
				DestinationResource: nmdata.Resource{ID: targetPeerID, Type: string(ResourceTypePeer)},
			},
			wantEnabled: true,
		},
		{
			name:    "non-peer-destination-resource-falls-through-to-groups",
			peerSSH: false,
			rule: nmdata.PolicyRule{
				Enabled:             true,
				Protocol:            string(PolicyRuleProtocolNetbirdSSH),
				DestinationResource: nmdata.Resource{ID: targetPeerID, Type: "host"}, // wrong type
				Destinations:        []string{targetGroupID},                         // saved by group fallback
			},
			wantEnabled: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, peer := mkComponents(&tc.rule, tc.peerSSH)
			got := c.PeerSSHEnabled(peer)
			assert.Equal(t, tc.wantEnabled, got)
		})
	}
}

// TestPeerSSHEnabled_TargetMissingFromComponents covers the
// presence guard mirroring Calculate's peer lookup.
func TestPeerSSHEnabled_TargetMissingFromComponents(t *testing.T) {
	peer := &nmdata.Peer{ID: "missing", SSHEnabled: true}
	c := &NetworkMapComponents{
		Peers: map[string]*nmdata.Peer{}, // target peer NOT present
		Groups: map[string]*nmdata.Group{
			"g": {Peers: []string{"missing"}},
		},
		Policies: []*nmdata.Policy{{
			ID: "p", Enabled: true,
			Rules: []*nmdata.PolicyRule{{
				Enabled: true, Protocol: string(PolicyRuleProtocolNetbirdSSH),
				Destinations: []string{"g"},
			}},
		}},
	}
	assert.False(t, c.PeerSSHEnabled(peer),
		"missing target peer must short-circuit to false, not consult policies")
}

// TestPeerSSHEnabled_NilInputs guards the nil checks at function entry.
func TestPeerSSHEnabled_NilInputs(t *testing.T) {
	assert.False(t, (*NetworkMapComponents)(nil).PeerSSHEnabled(&nmdata.Peer{ID: "x"}))
	assert.False(t, (&NetworkMapComponents{}).PeerSSHEnabled(nil))
}

func TestSSHTargetPeerIDs(t *testing.T) {
	const (
		local  = "local"
		remote = "remote"
		gSrc   = "g_src"
		gDst   = "g_dst"
	)

	sshRule := func() *nmdata.PolicyRule {
		return &nmdata.PolicyRule{
			Enabled: true, Protocol: string(PolicyRuleProtocolNetbirdSSH),
			Sources: []string{gSrc}, Destinations: []string{gDst},
		}
	}
	legacyRule := func() *nmdata.PolicyRule {
		return &nmdata.PolicyRule{
			Enabled: true, Protocol: string(PolicyRuleProtocolTCP), Ports: []string{"22"},
			Sources: []string{gSrc}, Destinations: []string{gDst},
		}
	}

	cases := []struct {
		name         string
		mutate       func(c *NetworkMapComponents, p *nmdata.Policy, r *nmdata.PolicyRule)
		rule         func() *nmdata.PolicyRule
		remoteSSH    bool
		remoteServer bool
		want         []string
	}{
		{name: "explicit-netbird-ssh", rule: sshRule, remoteServer: true, want: []string{remote}},
		{name: "legacy-with-remote-ssh-enabled", rule: legacyRule, remoteSSH: true, remoteServer: true, want: []string{remote}},
		{name: "legacy-without-remote-ssh-enabled", rule: legacyRule, remoteServer: true, want: []string{}},
		{name: "remote-server-ssh-not-allowed", rule: sshRule, want: []string{}},
		{
			name: "peer-typed-source-and-destination", rule: sshRule, remoteServer: true,
			mutate: func(_ *NetworkMapComponents, _ *nmdata.Policy, r *nmdata.PolicyRule) {
				r.Sources, r.Destinations = nil, nil
				r.SourceResource = nmdata.Resource{ID: local, Type: string(ResourceTypePeer)}
				r.DestinationResource = nmdata.Resource{ID: remote, Type: string(ResourceTypePeer)}
			},
			want: []string{remote},
		},
		{
			name: "local-fails-source-posture-check", rule: sshRule, remoteServer: true,
			mutate: func(c *NetworkMapComponents, p *nmdata.Policy, _ *nmdata.PolicyRule) {
				p.SourcePostureChecks = []string{"pc"}
				c.PostureFailedPeers = map[string]map[string]struct{}{"pc": {local: {}}}
			},
			want: []string{},
		},
		{
			name: "disabled-policy", rule: sshRule, remoteServer: true,
			mutate: func(_ *NetworkMapComponents, p *nmdata.Policy, _ *nmdata.PolicyRule) { p.Enabled = false },
			want:   []string{},
		},
		{
			name: "disabled-rule", rule: sshRule, remoteServer: true,
			mutate: func(_ *NetworkMapComponents, _ *nmdata.Policy, r *nmdata.PolicyRule) { r.Enabled = false },
			want:   []string{},
		},
		{
			name: "bidirectional-local-is-destination", rule: sshRule, remoteServer: true,
			mutate: func(_ *NetworkMapComponents, _ *nmdata.Policy, r *nmdata.PolicyRule) {
				r.Bidirectional = true
				r.Sources, r.Destinations = []string{gDst}, []string{gSrc}
			},
			want: []string{},
		},
		{
			name: "local-never-in-own-result", rule: sshRule, remoteServer: true,
			mutate: func(c *NetworkMapComponents, _ *nmdata.Policy, _ *nmdata.PolicyRule) {
				c.Groups[gDst].Peers = []string{local, remote}
				c.Peers[local].SSHEnabled = true
				c.Peers[local].Meta.Flags.ServerSSHAllowed = true
			},
			want: []string{remote},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := tc.rule()
			policy := &nmdata.Policy{ID: "p", Enabled: true, Rules: []*nmdata.PolicyRule{rule}}
			remotePeer := &nmdata.Peer{ID: remote, SSHEnabled: tc.remoteSSH}
			remotePeer.Meta.Flags.ServerSSHAllowed = tc.remoteServer
			c := &NetworkMapComponents{
				PeerID: local,
				Peers:  map[string]*nmdata.Peer{local: {ID: local}, remote: remotePeer},
				Groups: map[string]*nmdata.Group{
					gSrc: {Peers: []string{local}},
					gDst: {Peers: []string{remote}},
				},
				Policies: []*nmdata.Policy{policy},
			}
			if tc.mutate != nil {
				tc.mutate(c, policy, rule)
			}

			got := c.SSHTargetPeerIDs()

			want := make(map[string]struct{}, len(tc.want))
			for _, id := range tc.want {
				want[id] = struct{}{}
			}
			assert.Equal(t, want, got)
		})
	}

	assert.Nil(t, (*NetworkMapComponents)(nil).SSHTargetPeerIDs())
}
