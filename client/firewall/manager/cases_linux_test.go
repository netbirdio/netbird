package manager

var InsertRuleTestCases = []struct {
	name      string
	inputPair RouterPair
}{
	{
		name: "Insert Forwarding IPV4 Rule",
		inputPair: RouterPair{
			ID:          "zxa",
			Source:      "100.100.100.1/32",
			Destination: "100.100.200.0/24",
			Masquerade:  false,
		},
	},
	{
		name: "Insert Forwarding And Nat IPV4 Rules",
		inputPair: RouterPair{
			ID:          "zxa",
			Source:      "100.100.100.1/32",
			Destination: "100.100.200.0/24",
			Masquerade:  true,
		},
	},
}

var RemoveRuleTestCases = []struct {
	name      string
	inputPair RouterPair
	ipVersion string
}{
	{
		name: "Remove Forwarding And Nat IPV4 Rules",
		inputPair: RouterPair{
			ID:          "zxa",
			Source:      "100.100.100.1/32",
			Destination: "100.100.200.0/24",
			Masquerade:  true,
		},
	},
}
