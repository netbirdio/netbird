package types

import (
	"net/netip"
	"testing"
)

func TestGetResourceType(t *testing.T) {
	tests := []struct {
		input          string
		expectedType   NetworkResourceType
		expectedErr    bool
		expectedDomain string
		expectedPrefix netip.Prefix
	}{
		// Valid host IPs
		{"1.1.1.1", Host, false, "", netip.MustParsePrefix("1.1.1.1/32")},
		{"1.1.1.1/32", Host, false, "", netip.MustParsePrefix("1.1.1.1/32")},
		// Valid subnets
		{"192.168.1.0/24", Subnet, false, "", netip.MustParsePrefix("192.168.1.0/24")},
		{"10.0.0.0/16", Subnet, false, "", netip.MustParsePrefix("10.0.0.0/16")},
		// Valid domains
		{"example.com", Domain, false, "example.com", netip.Prefix{}},
		{"*.example.com", Domain, false, "*.example.com", netip.Prefix{}},
		{"sub.example.com", Domain, false, "sub.example.com", netip.Prefix{}},
		{"example.x", Domain, false, "example.x", netip.Prefix{}},
		{"internal", Domain, false, "internal", netip.Prefix{}},
		// Invalid inputs
		{"1.1.1.1/abc", "", true, "", netip.Prefix{}},
		{"-invalid.com", "", true, "", netip.Prefix{}},
		{"", "", true, "", netip.Prefix{}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, domain, prefix, err := GetResourceType(tt.input)

			if result != tt.expectedType {
				t.Errorf("Expected type %v, got %v", tt.expectedType, result)
			}

			if tt.expectedErr && err == nil {
				t.Errorf("Expected error, got nil")
			}

			if prefix != tt.expectedPrefix {
				t.Errorf("Expected address %v, got %v", tt.expectedPrefix, prefix)
			}

			if domain != tt.expectedDomain {
				t.Errorf("Expected domain %v, got %v", tt.expectedDomain, domain)
			}
		})
	}
}

func TestNetworkResourceEqual(t *testing.T) {
	base := &NetworkResource{
		ID:          "r1",
		NetworkID:   "n1",
		AccountID:   "acc",
		Name:        "resource",
		Description: "desc",
		Type:        Subnet,
		Address:     "10.0.0.0/24",
		Prefix:      netip.MustParsePrefix("10.0.0.0/24"),
		GroupIDs:    []string{"g1", "g2"},
		Enabled:     true,
	}

	reordered := base.Copy()
	reordered.GroupIDs = []string{"g2", "g1"}
	reordered.Address = ""
	reordered.PublicID = "different"
	if !base.Equal(reordered) {
		t.Fatal("group order, address and public ID should not matter")
	}

	tests := map[string]func(r *NetworkResource){
		"name":        func(r *NetworkResource) { r.Name = "other" },
		"description": func(r *NetworkResource) { r.Description = "other" },
		"enabled":     func(r *NetworkResource) { r.Enabled = false },
		"network":     func(r *NetworkResource) { r.NetworkID = "n2" },
		"prefix":      func(r *NetworkResource) { r.Prefix = netip.MustParsePrefix("10.0.1.0/24") },
		"domain": func(r *NetworkResource) {
			r.Type, r.Domain, r.Prefix = Domain, "example.com", netip.Prefix{}
		},
		"group swap":  func(r *NetworkResource) { r.GroupIDs = []string{"g1", "g3"} },
		"group added": func(r *NetworkResource) { r.GroupIDs = append(r.GroupIDs, "g3") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := base.Copy()
			changed.GroupIDs = append([]string(nil), base.GroupIDs...)
			mutate(changed)
			if base.Equal(changed) {
				t.Errorf("resources differing by %s should not be equal", name)
			}
		})
	}
}
