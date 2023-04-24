package acl

import (
	"runtime"
	"testing"

	mgmProto "github.com/netbirdio/netbird/management/proto"
)

func TestDefaultManager(t *testing.T) {
	// TODO: enable when other platform will be added
	if runtime.GOOS != "linux" {
		t.Skipf("ACL manager not supported in the: %s", runtime.GOOS)
		return
	}

	fwRules := []*mgmProto.FirewallRule{
		{
			PeerID:    "test",
			PeerIP:    "10.93.0.1",
			Direction: "dst",
			Action:    "accept",
			Protocol:  "tcp",
			Port:      "80",
		},
		{
			PeerID:    "test2",
			PeerIP:    "10.93.0.2",
			Direction: "dst",
			Action:    "drop",
			Protocol:  "udp",
			Port:      "53",
		},
	}

	// we receive one rule from the management so for testing purposes ignore it
	acl, err := Create("lo")
	if err != nil {
		t.Errorf("create ACL manager: %v", err)
		return
	}

	t.Run("apply firewall rules", func(t *testing.T) {
		acl.ApplyFiltering(fwRules)

		if len(acl.rules) != 2 {
			t.Errorf("firewall rules not applied: %v", acl.rules)
			return
		}
	})

	t.Run("add extra rules", func(t *testing.T) {
		// remove first rule
		fwRules = fwRules[1:]
		fwRules = append(fwRules, &mgmProto.FirewallRule{
			PeerID:    "test3",
			PeerIP:    "10.93.0.3",
			Direction: "src",
			Action:    "drop",
			Protocol:  "icmp",
		})

		existedRulesID := map[string]struct{}{}
		for id := range acl.rules {
			existedRulesID[id] = struct{}{}
		}

		acl.ApplyFiltering(fwRules)

		// we should have one old and one new rule in the existed rules
		if len(acl.rules) != 2 {
			t.Errorf("firewall rules not applied")
			return
		}

		// check that old rules was removed
		for id := range existedRulesID {
			if _, ok := acl.rules[id]; ok {
				t.Errorf("old rule was not removed")
				return
			}
		}
	})
}
