package routemanager

var insertRuleTestCases = []struct {
	name      string
	inputPair routerPair
	ipVersion string
}{
	{
		name: "Insert Forwarding IPV4 Rule",
		inputPair: routerPair{
			ID:          "zxa",
			source:      "100.100.100.1/32",
			destination: "100.100.200.0/24",
			masquerade:  false,
		},
		ipVersion: ipv4,
	},
	{
		name: "Insert Forwarding And Nat IPV4 Rules",
		inputPair: routerPair{
			ID:          "zxa",
			source:      "100.100.100.1/32",
			destination: "100.100.200.0/24",
			masquerade:  true,
		},
		ipVersion: ipv4,
	},
	{
		name: "Insert Forwarding IPV6 Rule",
		inputPair: routerPair{
			ID:          "zxa",
			source:      "fc00::1/128",
			destination: "fc12::/64",
			masquerade:  false,
		},
		ipVersion: ipv6,
	},
	{
		name: "Insert Forwarding And Nat IPV6 Rules",
		inputPair: routerPair{
			ID:          "zxa",
			source:      "fc00::1/128",
			destination: "fc12::/64",
			masquerade:  true,
		},
		ipVersion: ipv6,
	},
}

var removeRuleTestCases = []struct {
	name      string
	inputPair routerPair
	ipVersion string
}{
	{
		name: "Remove Forwarding And Nat IPV4 Rules",
		inputPair: routerPair{
			ID:          "zxa",
			source:      "100.100.100.1/32",
			destination: "100.100.200.0/24",
			masquerade:  true,
		},
		ipVersion: ipv4,
	},
	{
		name: "Remove Forwarding And Nat IPV6 Rules",
		inputPair: routerPair{
			ID:          "zxa",
			source:      "fc00::1/128",
			destination: "fc12::/64",
			masquerade:  true,
		},
		ipVersion: ipv6,
	},
}
