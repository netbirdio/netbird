package acl

import (
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/netbirdio/netbird/client/internal/acl/mocks"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

func TestDefaultManager(t *testing.T) {
	fwRules := []*mgmProto.FirewallRule{
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
		acl.ApplyFiltering(fwRules, false)

		if len(acl.rulesPairs) != 2 {
			t.Errorf("firewall rules not applied: %v", acl.rulesPairs)
			return
		}
	})

	t.Run("add extra rules", func(t *testing.T) {
		// remove first rule
		fwRules = fwRules[1:]
		fwRules = append(fwRules, &mgmProto.FirewallRule{
			PeerIP:    "10.93.0.3",
			Direction: mgmProto.FirewallRule_IN,
			Action:    mgmProto.FirewallRule_DROP,
			Protocol:  mgmProto.FirewallRule_ICMP,
		})

		existedRulesID := map[string]struct{}{}
		for id := range acl.rulesPairs {
			existedRulesID[id] = struct{}{}
		}

		acl.ApplyFiltering(fwRules, false)

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
		acl.ApplyFiltering(nil, false)
		if len(acl.rulesPairs) != 0 {
			t.Errorf("rules should be empty if default not allowed, got: %v rules", len(acl.rulesPairs))
			return
		}

		acl.ApplyFiltering(nil, true)
		if len(acl.rulesPairs) != 2 {
			t.Errorf("two default rules should be set if default is allowed, got: %v rules", len(acl.rulesPairs))
			return
		}
	})
}
