package acl

import (
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/netbirdio/netbird/client/internal/acl/mocks"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

func TestDefaultManager(t *testing.T) {
	networkMap := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.FirewallRule_OUT,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_TCP,
				Port:      "80",
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.FirewallRule_OUT,
				Action:    mgmProto.FirewallRule_DROP,
				Protocol:  mgmProto.FirewallRule_UDP,
				Port:      "53",
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iface := mocks.NewMockIFaceMapper(ctrl)
	iface.EXPECT().IsUserspaceBind().Return(true)
	// iface.EXPECT().Name().Return("lo")
	iface.EXPECT().SetFiltering(gomock.Any())

	// we receive one rule from the management so for testing purposes ignore it
	acl, err := Create(iface)
	if err != nil {
		t.Errorf("create ACL manager: %v", err)
		return
	}
	defer acl.Stop()

	t.Run("apply firewall rules", func(t *testing.T) {
		acl.ApplyFiltering(networkMap)

		if len(acl.rulesPairs) != 2 {
			t.Errorf("firewall rules not applied: %v", acl.rulesPairs)
			return
		}
	})

	t.Run("add extra rules", func(t *testing.T) {
		// remove first rule
		networkMap.FirewallRules = networkMap.FirewallRules[1:]
		networkMap.FirewallRules = append(
			networkMap.FirewallRules,
			&mgmProto.FirewallRule{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.FirewallRule_IN,
				Action:    mgmProto.FirewallRule_DROP,
				Protocol:  mgmProto.FirewallRule_ICMP,
			},
		)

		existedRulesID := map[string]struct{}{}
		for id := range acl.rulesPairs {
			existedRulesID[id] = struct{}{}
		}

		acl.ApplyFiltering(networkMap)

		// we should have one old and one new rule in the existed rules
		if len(acl.rulesPairs) != 2 {
			t.Errorf("firewall rules not applied")
			return
		}

		// check that old rules was removed
		for id := range existedRulesID {
			if _, ok := acl.rulesPairs[id]; ok {
				t.Errorf("old rule was not removed")
				return
			}
		}
	})

	t.Run("handle default rules", func(t *testing.T) {
		networkMap.FirewallRules = networkMap.FirewallRules[:0]

		networkMap.FirewallRulesIsEmpty = true
		if acl.ApplyFiltering(networkMap); len(acl.rulesPairs) != 0 {
			t.Errorf("rules should be empty if FirewallRulesIsEmpty is set, got: %v", len(acl.rulesPairs))
			return
		}

		networkMap.FirewallRulesIsEmpty = false
		acl.ApplyFiltering(networkMap)
		if len(acl.rulesPairs) != 2 {
			t.Errorf("rules should contain 2 rules if FirewallRulesIsEmpty is not set, got: %v", len(acl.rulesPairs))
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
				Direction: mgmProto.FirewallRule_IN,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.FirewallRule_IN,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.FirewallRule_IN,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			{
				PeerIP:    "10.93.0.4",
				Direction: mgmProto.FirewallRule_IN,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.FirewallRule_OUT,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.FirewallRule_OUT,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.FirewallRule_OUT,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			{
				PeerIP:    "10.93.0.4",
				Direction: mgmProto.FirewallRule_OUT,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
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
	if r.PeerIP != "0.0.0.0" {
		t.Errorf("IP should be 0.0.0.0, got: %v", r.PeerIP)
		return
	} else if r.Direction != mgmProto.FirewallRule_IN {
		t.Errorf("direction should be IN, got: %v", r.Direction)
		return
	} else if r.Protocol != mgmProto.FirewallRule_ALL {
		t.Errorf("protocol should be ALL, got: %v", r.Protocol)
		return
	} else if r.Action != mgmProto.FirewallRule_ACCEPT {
		t.Errorf("action should be ACCEPT, got: %v", r.Action)
		return
	}

	r = rules[1]
	if r.PeerIP != "0.0.0.0" {
		t.Errorf("IP should be 0.0.0.0, got: %v", r.PeerIP)
		return
	} else if r.Direction != mgmProto.FirewallRule_OUT {
		t.Errorf("direction should be OUT, got: %v", r.Direction)
		return
	} else if r.Protocol != mgmProto.FirewallRule_ALL {
		t.Errorf("protocol should be ALL, got: %v", r.Protocol)
		return
	} else if r.Action != mgmProto.FirewallRule_ACCEPT {
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
				Direction: mgmProto.FirewallRule_IN,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.FirewallRule_IN,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.FirewallRule_IN,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			{
				PeerIP:    "10.93.0.4",
				Direction: mgmProto.FirewallRule_IN,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_TCP,
			},
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.FirewallRule_OUT,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.FirewallRule_OUT,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.FirewallRule_OUT,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_ALL,
			},
			{
				PeerIP:    "10.93.0.4",
				Direction: mgmProto.FirewallRule_OUT,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_UDP,
			},
		},
	}

	manager := &DefaultManager{}
	if rules, _ := manager.squashAcceptRules(networkMap); len(rules) != len(networkMap.FirewallRules) {
		t.Errorf("we should got same amount of rules as intput, got %v", len(rules))
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
				Direction: mgmProto.FirewallRule_IN,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_TCP,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.FirewallRule_IN,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_TCP,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.FirewallRule_OUT,
				Action:    mgmProto.FirewallRule_ACCEPT,
				Protocol:  mgmProto.FirewallRule_UDP,
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iface := mocks.NewMockIFaceMapper(ctrl)
	iface.EXPECT().IsUserspaceBind().Return(true)
	// iface.EXPECT().Name().Return("lo")
	iface.EXPECT().SetFiltering(gomock.Any())

	// we receive one rule from the management so for testing purposes ignore it
	acl, err := Create(iface)
	if err != nil {
		t.Errorf("create ACL manager: %v", err)
		return
	}
	defer acl.Stop()

	acl.ApplyFiltering(networkMap)

	if len(acl.rulesPairs) != 4 {
		t.Errorf("expect 4 rules (last must be SSH), got: %d", len(acl.rulesPairs))
		return
	}
}
