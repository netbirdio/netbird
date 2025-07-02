package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/netbirdio/netbird/client/proto"
)

var (
	setFlags = &SharedFlags{}

	setCmd = &cobra.Command{
		Use:   "set",
		Short: "Update NetBird client configuration",
		Long:  `Update NetBird client configuration without connecting. Uses the same flags as 'netbird up' but only updates the configuration file.`,
		RunE:  setFunc,
	}
)

func init() {
	// Add all shared flags to the set command
	AddSharedFlags(setCmd, setFlags)
	// Note: We don't add up-only flags like --no-browser to set command
}

func setFunc(cmd *cobra.Command, _ []string) error {
	SetFlagsFromEnvVars(rootCmd)
	SetFlagsFromEnvVars(cmd)

	cmd.SetOut(cmd.OutOrStdout())

	// Validate inputs (reuse validation logic from up.go)
	if err := validateNATExternalIPs(setFlags.NATExternalIPs); err != nil {
		return err
	}

	if cmd.Flag(dnsLabelsFlag).Changed {
		if _, err := validateDnsLabels(setFlags.DNSLabels); err != nil {
			return err
		}
	}

	var customDNSAddressConverted []byte
	if cmd.Flag(dnsResolverAddress).Changed {
		var err error
		customDNSAddressConverted, err = parseCustomDNSAddress(cmd.Flag(dnsResolverAddress).Changed)
		if err != nil {
			return err
		}
	}

	// Connect to daemon
	ctx := cmd.Context()
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close connection: %v\n", closeErr)
		}
	}()

	client := proto.NewDaemonServiceClient(conn)
	req := &proto.SetConfigRequest{}

	// Set fields based on changed flags
	if cmd.Flag(enableRosenpassFlag).Changed {
		req.RosenpassEnabled = &setFlags.RosenpassEnabled
	}

	if cmd.Flag(rosenpassPermissiveFlag).Changed {
		req.RosenpassPermissive = &setFlags.RosenpassPermissive
	}

	if cmd.Flag(serverSSHAllowedFlag).Changed {
		req.ServerSSHAllowed = &setFlags.ServerSSHAllowed
	}

	if cmd.Flag(disableAutoConnectFlag).Changed {
		req.DisableAutoConnect = &setFlags.AutoConnectDisabled
	}

	if cmd.Flag(networkMonitorFlag).Changed {
		req.NetworkMonitor = &setFlags.NetworkMonitor
	}

	if cmd.Flag(interfaceNameFlag).Changed {
		if err := parseInterfaceName(setFlags.InterfaceName); err != nil {
			return err
		}
		req.InterfaceName = &setFlags.InterfaceName
	}

	if cmd.Flag(wireguardPortFlag).Changed {
		port := int64(setFlags.WireguardPort)
		req.WireguardPort = &port
	}

	if cmd.Flag(dnsResolverAddress).Changed {
		customAddr := string(customDNSAddressConverted)
		req.CustomDNSAddress = &customAddr
	}

	if cmd.Flag(extraIFaceBlackListFlag).Changed {
		req.ExtraIFaceBlacklist = setFlags.ExtraIFaceBlackList
	}

	if cmd.Flag(dnsLabelsFlag).Changed {
		req.DnsLabels = setFlags.DNSLabels
		req.CleanDNSLabels = &[]bool{setFlags.DNSLabels != nil && len(setFlags.DNSLabels) == 0}[0]
	}

	if cmd.Flag(externalIPMapFlag).Changed {
		req.NatExternalIPs = setFlags.NATExternalIPs
		req.CleanNATExternalIPs = &[]bool{setFlags.NATExternalIPs != nil && len(setFlags.NATExternalIPs) == 0}[0]
	}

	if cmd.Flag(dnsRouteIntervalFlag).Changed {
		req.DnsRouteInterval = durationpb.New(setFlags.DNSRouteInterval)
	}

	if cmd.Flag(disableClientRoutesFlag).Changed {
		req.DisableClientRoutes = &setFlags.DisableClientRoutes
	}

	if cmd.Flag(disableServerRoutesFlag).Changed {
		req.DisableServerRoutes = &setFlags.DisableServerRoutes
	}

	if cmd.Flag(disableDNSFlag).Changed {
		req.DisableDns = &setFlags.DisableDNS
	}

	if cmd.Flag(disableFirewallFlag).Changed {
		req.DisableFirewall = &setFlags.DisableFirewall
	}

	if cmd.Flag(blockLANAccessFlag).Changed {
		req.BlockLanAccess = &setFlags.BlockLANAccess
	}

	if cmd.Flag(blockInboundFlag).Changed {
		req.BlockInbound = &setFlags.BlockInbound
	}

	if cmd.Flag(enableLazyConnectionFlag).Changed {
		req.LazyConnectionEnabled = &setFlags.LazyConnEnabled
	}

	// Send the request
	if _, err := client.SetConfig(ctx, req); err != nil {
		return fmt.Errorf("update configuration: %w", err)
	}

	cmd.Println("Configuration updated successfully")
	return nil
}
