package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

var appendFlag bool

var networksCMD = &cobra.Command{
	Use:     "networks",
	Aliases: []string{"routes"},
	Short:   "Manage connections to NetBird Networks and Resources",
	Long:    `Commands to list, select, or deselect networks. Replaces the "routes" command.`,
}

var routesListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List networks",
	Example: "  netbird networks list",
	Long:    "List all available network routes.",
	RunE:    networksList,
}

var routesSelectCmd = &cobra.Command{
	Use:     "select network...|all",
	Short:   "Select network",
	Long:    "Select a list of networks by identifiers or 'all' to clear all selections and to accept all (including new) networks.\nDefault mode is replace, use -a to append to already selected networks.",
	Example: "  netbird networks select all\n  netbird networks select route1 route2\n  netbird routes select -a route3",
	Args:    cobra.MinimumNArgs(1),
	RunE:    networksSelect,
}

var routesDeselectCmd = &cobra.Command{
	Use:     "deselect network...|all",
	Short:   "Deselect networks",
	Long:    "Deselect previously selected networks by identifiers or 'all' to disable accepting any networks.",
	Example: "  netbird networks deselect all\n  netbird networks deselect route1 route2",
	Args:    cobra.MinimumNArgs(1),
	RunE:    networksDeselect,
}

func init() {
	routesSelectCmd.PersistentFlags().BoolVarP(&appendFlag, "append", "a", false, "Append to current network selection instead of replacing")
}

func networksList(cmd *cobra.Command, _ []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.ListNetworks(cmd.Context(), &proto.ListNetworksRequest{})
	if err != nil {
		return fmt.Errorf("failed to list network: %v", status.Convert(err).Message())
	}

	if len(resp.Routes) == 0 {
		cmd.Println("No networks available.")
		return nil
	}

	printNetworks(cmd, resp)

	return nil
}

func printNetworks(cmd *cobra.Command, resp *proto.ListNetworksResponse) {
	cmd.Println("Available Networks:")
	for _, route := range resp.Routes {
		printNetwork(cmd, route)
	}
}

func printNetwork(cmd *cobra.Command, route *proto.Network) {
	selectedStatus := getSelectedStatus(route)
	domains := route.GetDomains()

	if len(domains) > 0 {
		printDomainRoute(cmd, route, domains, selectedStatus)
	} else {
		printNetworkRoute(cmd, route, selectedStatus)
	}
}

func getSelectedStatus(route *proto.Network) string {
	if route.GetSelected() {
		return "Selected"
	}
	return "Not Selected"
}

func printDomainRoute(cmd *cobra.Command, route *proto.Network, domains []string, selectedStatus string) {
	cmd.Printf("\n  - ID: %s\n    Domains: %s\n    Status: %s\n", route.GetID(), strings.Join(domains, ", "), selectedStatus)
	resolvedIPs := route.GetResolvedIPs()

	if len(resolvedIPs) > 0 {
		printResolvedIPs(cmd, domains, resolvedIPs)
	} else {
		cmd.Printf("    Resolved IPs: -\n")
	}
}

func printNetworkRoute(cmd *cobra.Command, route *proto.Network, selectedStatus string) {
	cmd.Printf("\n  - ID: %s\n    Network: %s\n    Status: %s\n", route.GetID(), route.GetRange(), selectedStatus)
}

func printResolvedIPs(cmd *cobra.Command, _ []string, resolvedIPs map[string]*proto.IPList) {
	cmd.Printf("    Resolved IPs:\n")
	for resolvedDomain, ipList := range resolvedIPs {
		cmd.Printf("      [%s]: %s\n", resolvedDomain, strings.Join(ipList.GetIps(), ", "))
	}
}

func networksSelect(cmd *cobra.Command, args []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	req := &proto.SelectNetworksRequest{
		NetworkIDs: args,
	}

	if len(args) == 1 && args[0] == "all" {
		req.All = true
	} else if appendFlag {
		req.Append = true
	}

	if _, err := client.SelectNetworks(cmd.Context(), req); err != nil {
		return fmt.Errorf("failed to select networks: %v", status.Convert(err).Message())
	}

	cmd.Println("Networks selected successfully.")

	return nil
}

func networksDeselect(cmd *cobra.Command, args []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	req := &proto.SelectNetworksRequest{
		NetworkIDs: args,
	}

	if len(args) == 1 && args[0] == "all" {
		req.All = true
	}

	if _, err := client.DeselectNetworks(cmd.Context(), req); err != nil {
		return fmt.Errorf("failed to deselect networks: %v", status.Convert(err).Message())
	}

	cmd.Println("Networks deselected successfully.")

	return nil
}
