package cmd

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
	nbstatus "github.com/netbirdio/netbird/client/status"
)

var forwardingRulesCmd = &cobra.Command{
	Use:   "forwarding",
	Short: "List forwarding rules",
	Long:  `Commands to list forwarding rules.`,
}

var forwardingRulesListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List forwarding rules",
	Example: "  netbird forwarding list",
	Long:    "Commands to list forwarding rules.",
	RunE:    listForwardingRules,
}

func init() {
	forwardingRulesListCmd.PersistentFlags().BoolVarP(&jsonFlag, "json", "j", false, "display command result in json format")
	forwardingRulesListCmd.PersistentFlags().BoolVarP(&yamlFlag, "yaml", "y", false, "display command result in yaml format")
	forwardingRulesListCmd.MarkFlagsMutuallyExclusive("json", "yaml")
}

func listForwardingRules(cmd *cobra.Command, _ []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.ForwardingRules(cmd.Context(), &proto.EmptyRequest{})
	if err != nil {
		return fmt.Errorf("failed to list network: %v", status.Convert(err).Message())
	}

	rules := resp.GetRules()
	sortForwardingRules(rules)

	if jsonFlag || yamlFlag {
		return emitForwardingList(cmd, rules)
	}

	if len(rules) == 0 {
		cmd.Println("No forwarding rules available.")
		return nil
	}

	printForwardingRules(cmd, rules)
	return nil
}

func sortForwardingRules(rules []*proto.ForwardingRule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].GetTranslatedAddress() != rules[j].GetTranslatedAddress() {
			return rules[i].GetTranslatedAddress() < rules[j].GetTranslatedAddress()
		}
		if rules[i].GetProtocol() != rules[j].GetProtocol() {
			return rules[i].GetProtocol() < rules[j].GetProtocol()
		}
		return getFirstPort(rules[i].GetDestinationPort()) < getFirstPort(rules[j].GetDestinationPort())
	})
}

func emitForwardingList(cmd *cobra.Command, rules []*proto.ForwardingRule) error {
	out := &nbstatus.ForwardingListOutput{Rules: make([]nbstatus.ForwardingRuleOutput, 0, len(rules))}
	for _, rule := range rules {
		row := nbstatus.ForwardingRuleOutput{
			TranslatedAddress:  rule.GetTranslatedAddress(),
			TranslatedHostname: rule.GetTranslatedHostname(),
			Protocol:           rule.GetProtocol(),
		}
		if s, ok := portToStringOpt(rule.GetDestinationPort()); ok {
			row.DestinationPort = &s
		}
		if s, ok := portToStringOpt(rule.GetTranslatedPort()); ok {
			row.TranslatedPort = &s
		}
		out.Rules = append(out.Rules, row)
	}

	if jsonFlag {
		s, err := out.JSON()
		if err != nil {
			return err
		}
		cmd.Println(s)
		return nil
	}
	s, err := out.YAML()
	if err != nil {
		return err
	}
	cmd.Print(s)
	return nil
}

func printForwardingRules(cmd *cobra.Command, rules []*proto.ForwardingRule) {
	cmd.Println("Available forwarding rules:")

	var lastIP string
	for _, rule := range rules {
		dPort := portToString(rule.GetDestinationPort())
		tPort := portToString(rule.GetTranslatedPort())
		if lastIP != rule.GetTranslatedAddress() {
			lastIP = rule.GetTranslatedAddress()
			cmd.Printf("\nTranslated peer: %s\n", rule.GetTranslatedHostname())
		}

		cmd.Printf("  Local %s/%s to %s:%s\n", rule.GetProtocol(), dPort, rule.GetTranslatedAddress(), tPort)
	}
}

func getFirstPort(portInfo *proto.PortInfo) int {
	switch v := portInfo.PortSelection.(type) {
	case *proto.PortInfo_Port:
		return int(v.Port)
	case *proto.PortInfo_Range_:
		return int(v.Range.GetStart())
	default:
		return 0
	}
}

func portToString(translatedPort *proto.PortInfo) string {
	if s, ok := portToStringOpt(translatedPort); ok {
		return s
	}
	return "No port specified"
}

// portToStringOpt returns the formatted port string and whether port info was
// actually present. Used by the structured (json/yaml) output so the absent
// case becomes a missing field instead of a sentinel string.
func portToStringOpt(p *proto.PortInfo) (string, bool) {
	switch v := p.GetPortSelection().(type) {
	case *proto.PortInfo_Port:
		return fmt.Sprintf("%d", v.Port), true
	case *proto.PortInfo_Range_:
		return fmt.Sprintf("%d-%d", v.Range.GetStart(), v.Range.GetEnd()), true
	default:
		return "", false
	}
}
