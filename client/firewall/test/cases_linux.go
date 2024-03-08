//go:build !android

package test

import firewall "github.com/netbirdio/netbird/client/firewall/manager"

var (
	InsertRuleTestCases = []struct {
		Name      string
		InputPair firewall.RouterPair
		IsV6      bool
	}{
		{
			Name: "Insert Forwarding IPV4 Rule",
			InputPair: firewall.RouterPair{
				ID:          "zxa",
				Source:      "100.100.100.1/32",
				Destination: "100.100.200.0/24",
				Masquerade:  false,
			},
		},
		{
			Name: "Insert Forwarding And Nat IPV4 Rules",
			InputPair: firewall.RouterPair{
				ID:          "zxa",
				Source:      "100.100.100.1/32",
				Destination: "100.100.200.0/24",
				Masquerade:  true,
			},
		},
		{
			Name: "Insert Forwarding IPV6 Rule",
			InputPair: firewall.RouterPair{
				ID:          "zxa",
				Source:      "2001:db8:0123:4567::1/128",
				Destination: "2001:db8:0123:abcd::/64",
				Masquerade:  false,
			},
			IsV6: true,
		},
		{
			Name: "Insert Forwarding And Nat IPV6 Rules",
			InputPair: firewall.RouterPair{
				ID:          "zxa",
				Source:      "2001:db8:0123:4567::1/128",
				Destination: "2001:db8:0123:abcd::/64",
				Masquerade:  true,
			},
			IsV6: true,
		},
	}

	RemoveRuleTestCases = []struct {
		Name      string
		InputPair firewall.RouterPair
		IsV6      bool
	}{
		{
			Name: "Remove Forwarding And Nat IPV4 Rules",
			InputPair: firewall.RouterPair{
				ID:          "zxa",
				Source:      "100.100.100.1/32",
				Destination: "100.100.200.0/24",
				Masquerade:  true,
			},
		},
		{
			Name: "Remove Forwarding And Nat IPV6 Rules",
			InputPair: firewall.RouterPair{
				ID:          "zxa",
				Source:      "2001:db8:0123:4567::1/128",
				Destination: "2001:db8:0123:abcd::/64",
				Masquerade:  true,
			},
			IsV6: true,
		},
	}
)
