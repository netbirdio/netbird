package routemanager

var insertRuleTestCases = []struct {
	name      string
	inputPair routerPair
}{
	{
		name: "Insert Forwarding IPV4 Rule",
		inputPair: routerPair{
			ID:          "zxa",
			source:      "100.100.100.1/32",
			destination: "100.100.200.0/24",
			masquerade:  false,
		},
	},
	{
		name: "Insert Forwarding And Nat IPV4 Rules",
		inputPair: routerPair{
			ID:          "zxa",
			source:      "100.100.100.1/32",
			destination: "100.100.200.0/24",
			masquerade:  true,
		},
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
	},
}
