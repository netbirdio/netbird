package acl

import (
	"context"
	"net"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/acl/mocks"
	"github.com/netbirdio/netbird/iface"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

func TestDefaultManager(t *testing.T) {
	networkMap := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "80",
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_DROP,
				Protocol:  mgmProto.RuleProtocol_UDP,
				Port:      "53",
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	ip, network, err := net.ParseCIDR("172.0.0.1/32")
	if err != nil {
		t.Fatalf("failed to parse IP address: %v", err)
	}

	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(iface.WGAddress{
		IP:      ip,
		Network: network,
	}).AnyTimes()

	// we receive one rule from the management so for testing purposes ignore it
	fw, err := firewall.NewFirewall(context.Background(), ifaceMock)
	if err != nil {
		t.Errorf("create firewall: %v", err)
		return
	}
	defer func(fw manager.Manager) {
		_ = fw.Reset()
	}(fw)
	acl := NewDefaultManager(fw)

	t.Run("apply firewall rules", func(t *testing.T) {
		acl.ApplyFiltering(networkMap)

		if len(acl.peerRulesPairs) != 2 {
			t.Errorf("firewall rules not applied: %v", acl.peerRulesPairs)
			return
		}
	})

	t.Run("add extra rules", func(t *testing.T) {
		existedPairs := map[string]struct{}{}
		for id := range acl.peerRulesPairs {
			existedPairs[id.GetRuleID()] = struct{}{}
		}

		// remove first rule
		networkMap.FirewallRules = networkMap.FirewallRules[1:]
		networkMap.FirewallRules = append(
			networkMap.FirewallRules,
			&mgmProto.FirewallRule{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_DROP,
				Protocol:  mgmProto.RuleProtocol_ICMP,
			},
		)

		acl.ApplyFiltering(networkMap)

		// we should have one old and one new rule in the existed rules
		if len(acl.peerRulesPairs) != 2 {
			t.Errorf("firewall rules not applied")
			return
		}

		// check that old rule was removed
		previousCount := 0
		for id := range acl.peerRulesPairs {
			if _, ok := existedPairs[id.GetRuleID()]; ok {
				previousCount++
			}
		}
		if previousCount != 1 {
			t.Errorf("old rule was not removed")
		}
	})

	t.Run("handle default rules", func(t *testing.T) {
		networkMap.FirewallRules = networkMap.FirewallRules[:0]

		networkMap.FirewallRulesIsEmpty = true
		if acl.ApplyFiltering(networkMap); len(acl.peerRulesPairs) != 0 {
			t.Errorf("rules should be empty if FirewallRulesIsEmpty is set, got: %v", len(acl.peerRulesPairs))
			return
		}

		networkMap.FirewallRulesIsEmpty = false
		acl.ApplyFiltering(networkMap)
		if len(acl.peerRulesPairs) != 2 {
			t.Errorf("rules should contain 2 rules if FirewallRulesIsEmpty is not set, got: %v", len(acl.peerRulesPairs))
			return
		}
	})
}

func TestDefaultManagerSquashRules(t *testing.T) {
	networkMap := &mgmProto.NetworkMap{
		RemotePeers: []*mgmProto.RemotePeerConfig{
			{AllowedIps: []string{"10.93.0.1"}},
			{AllowedIps: []string{"10.93.0.2"}},
			{AllowedIps: []string{"10.93.0.3"}},
			{AllowedIps: []string{"10.93.0.4"}},
		},
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.4",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.4",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
		},
	}

	manager := &DefaultManager{}
	rules, _ := manager.squashAcceptRules(networkMap)
	if len(rules) != 2 {
		t.Errorf("rules should contain 2, got: %v", rules)
		return
	}

	r := rules[0]
	switch {
	case r.PeerIP != "0.0.0.0":
		t.Errorf("IP should be 0.0.0.0, got: %v", r.PeerIP)
		return
	case r.Direction != mgmProto.RuleDirection_IN:
		t.Errorf("direction should be IN, got: %v", r.Direction)
		return
	case r.Protocol != mgmProto.RuleProtocol_ALL:
		t.Errorf("protocol should be ALL, got: %v", r.Protocol)
		return
	case r.Action != mgmProto.RuleAction_ACCEPT:
		t.Errorf("action should be ACCEPT, got: %v", r.Action)
		return
	}

	r = rules[1]
	switch {
	case r.PeerIP != "0.0.0.0":
		t.Errorf("IP should be 0.0.0.0, got: %v", r.PeerIP)
		return
	case r.Direction != mgmProto.RuleDirection_OUT:
		t.Errorf("direction should be OUT, got: %v", r.Direction)
		return
	case r.Protocol != mgmProto.RuleProtocol_ALL:
		t.Errorf("protocol should be ALL, got: %v", r.Protocol)
		return
	case r.Action != mgmProto.RuleAction_ACCEPT:
		t.Errorf("action should be ACCEPT, got: %v", r.Action)
		return
	}
}

func TestDefaultManagerSquashRulesNoAffect(t *testing.T) {
	networkMap := &mgmProto.NetworkMap{
		RemotePeers: []*mgmProto.RemotePeerConfig{
			{AllowedIps: []string{"10.93.0.1"}},
			{AllowedIps: []string{"10.93.0.2"}},
			{AllowedIps: []string{"10.93.0.3"}},
			{AllowedIps: []string{"10.93.0.4"}},
		},
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.4",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
			},
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.4",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_UDP,
			},
		},
	}

	manager := &DefaultManager{}
	if rules, _ := manager.squashAcceptRules(networkMap); len(rules) != len(networkMap.FirewallRules) {
		t.Errorf("we should get the same amount of rules as output, got %v", len(rules))
	}
}

func TestDefaultManagerEnableSSHRules(t *testing.T) {
	networkMap := &mgmProto.NetworkMap{
		PeerConfig: &mgmProto.PeerConfig{
			SshConfig: &mgmProto.SSHConfig{
				SshEnabled: true,
			},
		},
		RemotePeers: []*mgmProto.RemotePeerConfig{
			{AllowedIps: []string{"10.93.0.1"}},
			{AllowedIps: []string{"10.93.0.2"}},
			{AllowedIps: []string{"10.93.0.3"}},
		},
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_UDP,
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	ip, network, err := net.ParseCIDR("172.0.0.1/32")
	if err != nil {
		t.Fatalf("failed to parse IP address: %v", err)
	}

	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(iface.WGAddress{
		IP:      ip,
		Network: network,
	}).AnyTimes()

	// we receive one rule from the management so for testing purposes ignore it
	fw, err := firewall.NewFirewall(context.Background(), ifaceMock)
	if err != nil {
		t.Errorf("create firewall: %v", err)
		return
	}
	defer func(fw manager.Manager) {
		_ = fw.Reset()
	}(fw)
	acl := NewDefaultManager(fw)

	acl.ApplyFiltering(networkMap)

	if len(acl.peerRulesPairs) != 4 {
		t.Errorf("expect 4 rules (last must be SSH), got: %d", len(acl.peerRulesPairs))
		return
	}
}
