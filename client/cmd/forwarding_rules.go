package cmd

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
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

	if len(resp.GetRules()) == 0 {
		cmd.Println("No forwarding rules available.")
		return nil
	}

	printForwardingRules(cmd, resp.GetRules())
	return nil
}

func printForwardingRules(cmd *cobra.Command, rules []*proto.ForwardingRule) {
	cmd.Println("Available forwarding rules:")

	// Sort rules by translated address
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].GetTranslatedAddress() != rules[j].GetTranslatedAddress() {
			return rules[i].GetTranslatedAddress() < rules[j].GetTranslatedAddress()
		}
		if rules[i].GetProtocol() != rules[j].GetProtocol() {
			return rules[i].GetProtocol() < rules[j].GetProtocol()
		}

		return getFirstPort(rules[i].GetDestinationPort()) < getFirstPort(rules[j].GetDestinationPort())
	})

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
	switch v := translatedPort.PortSelection.(type) {
	case *proto.PortInfo_Port:
		return fmt.Sprintf("%d", v.Port)
	case *proto.PortInfo_Range_:
		return fmt.Sprintf("%d-%d", v.Range.GetStart(), v.Range.GetEnd())
	default:
		return "No port specified"
	}
}
