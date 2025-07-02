package cmd

import (
	"fmt"
	"os"
	osuser "os/user"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/management/domain"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

var setCmd = &cobra.Command{
	Use:   "set <setting> <value>",
	Short: "Set a configuration value without running up",
	Long: `Set a configuration value in the Netbird config file without running 'up'.

You can also set values via environment variables NB_<SETTING> or WT_<SETTING> (e.g. NB_INTERFACE_NAME=utun5 netbird set interface-name).

Supported settings:
  management-url            (string)   e.g. https://api.netbird.io:443
  admin-url                 (string)   e.g. https://app.netbird.io:443
  interface-name            (string)   e.g. utun5
  external-ip-map           (list)     comma-separated, e.g. 12.34.56.78,12.34.56.79/eth0
  extra-iface-blacklist     (list)     comma-separated, e.g. eth1,eth2
  dns-resolver-address      (string)   e.g. 127.0.0.1:5053
  extra-dns-labels          (list)     comma-separated, e.g. vpc1,mgmt1
  preshared-key             (string)
  enable-rosenpass          (bool)     true/false
  rosenpass-permissive      (bool)     true/false
  allow-server-ssh          (bool)     true/false
  network-monitor           (bool)     true/false
  disable-auto-connect      (bool)     true/false
  disable-client-routes     (bool)     true/false
  disable-server-routes     (bool)     true/false
  disable-dns               (bool)     true/false
  disable-firewall          (bool)     true/false
  block-lan-access          (bool)     true/false
  block-inbound             (bool)     true/false
  enable-lazy-connection    (bool)     true/false
  wireguard-port            (int)      e.g. 51820
  dns-router-interval       (duration) e.g. 1m, 30s

Examples:
  NB_INTERFACE_NAME=utun5 netbird set interface-name
  netbird set wireguard-port 51820
  netbird set external-ip-map 12.34.56.78,12.34.56.79/eth0
  netbird set enable-rosenpass true
  netbird set dns-router-interval 2m
  netbird set extra-dns-labels vpc1,mgmt1
  netbird set disable-firewall true
`,
	Args: cobra.ExactArgs(2),
	RunE: setFunc,
}

func init() {
	rootCmd.AddCommand(setCmd)
}

func setFunc(cmd *cobra.Command, args []string) error {
	setting := args[0]
	var value string

	// Check environment variables first
	upper := strings.ToUpper(strings.ReplaceAll(setting, "-", "_"))
	if v, ok := os.LookupEnv("NB_" + upper); ok {
		value = v
	} else if v, ok := os.LookupEnv("WT_" + upper); ok {
		value = v
	} else {
		if len(args) < 2 {
			return fmt.Errorf("missing value for setting %s", setting)
		}
		value = args[1]
	}

	// If not root, try to use the daemon (only if cmd is not nil)
	if cmd != nil {
		if u, err := osuser.Current(); err == nil && u.Uid != "0" {
			conn, err := getClient(cmd)
			if err == nil {
				defer conn.Close()
				client := proto.NewDaemonServiceClient(conn)
				_, err = client.SetConfigValue(cmd.Context(), &proto.SetConfigValueRequest{Setting: setting, Value: value})
				if err == nil {
					if cmd != nil {
						cmd.Println("Configuration updated via daemon.")
					} else {
						fmt.Println("Configuration updated via daemon.")
					}
					return nil
				}
				if s, ok := status.FromError(err); ok {
					return fmt.Errorf("daemon error: %v", s.Message())
				}
				return fmt.Errorf("failed to update config via daemon: %v", err)
			}
			// else: fall back to direct file write
		}
	}

	switch setting {
	case "management-url":
		input := internal.ConfigInput{ConfigPath: configPath, ManagementURL: value}
		_, err := internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set management-url: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set management-url to: %s\n", value)
		} else {
			fmt.Printf("Set management-url to: %s\n", value)
		}
	case "admin-url":
		input := internal.ConfigInput{ConfigPath: configPath, AdminURL: value}
		_, err := internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set admin-url: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set admin-url to: %s\n", value)
		} else {
			fmt.Printf("Set admin-url to: %s\n", value)
		}
	case "interface-name":
		if err := parseInterfaceName(value); err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, InterfaceName: &value}
		_, err := internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set interface-name: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set interface-name to: %s\n", value)
		} else {
			fmt.Printf("Set interface-name to: %s\n", value)
		}
	case "external-ip-map":
		var ips []string
		if value == "" {
			ips = []string{}
		} else {
			ips = strings.Split(value, ",")
		}
		if err := validateNATExternalIPs(ips); err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, NATExternalIPs: ips}
		_, err := internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set external-ip-map: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set external-ip-map to: %v\n", ips)
		} else {
			fmt.Printf("Set external-ip-map to: %v\n", ips)
		}
	case "extra-iface-blacklist":
		var ifaces []string
		if value == "" {
			ifaces = []string{}
		} else {
			ifaces = strings.Split(value, ",")
		}
		input := internal.ConfigInput{ConfigPath: configPath, ExtraIFaceBlackList: ifaces}
		_, err := internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set extra-iface-blacklist: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set extra-iface-blacklist to: %v\n", ifaces)
		} else {
			fmt.Printf("Set extra-iface-blacklist to: %v\n", ifaces)
		}
	case "dns-resolver-address":
		if value != "" && !isValidAddrPort(value) {
			return fmt.Errorf("%s is invalid, it should be formatted as IP:Port string or as an empty string like \"\"", value)
		}
		input := internal.ConfigInput{ConfigPath: configPath, CustomDNSAddress: []byte(value)}
		_, err := internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set dns-resolver-address: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set dns-resolver-address to: %s\n", value)
		} else {
			fmt.Printf("Set dns-resolver-address to: %s\n", value)
		}
	case "extra-dns-labels":
		var labels []string
		if value == "" {
			labels = []string{}
		} else {
			labels = strings.Split(value, ",")
		}
		domains, err := domain.ValidateDomains(labels)
		if err != nil {
			return fmt.Errorf("invalid DNS labels: %v", err)
		}
		input := internal.ConfigInput{ConfigPath: configPath, DNSLabels: domains}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set extra-dns-labels: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set extra-dns-labels to: %v\n", labels)
		} else {
			fmt.Printf("Set extra-dns-labels to: %v\n", labels)
		}
	case "preshared-key":
		input := internal.ConfigInput{ConfigPath: configPath, PreSharedKey: &value}
		_, err := internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set preshared-key: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set preshared-key to: %s\n", value)
		} else {
			fmt.Printf("Set preshared-key to: %s\n", value)
		}
	case "hostname":
		// Hostname is not persisted in config, so just print a warning
		if cmd != nil {
			cmd.Printf("Warning: hostname is not persisted in config. Use --hostname with up command.\n")
		} else {
			fmt.Printf("Warning: hostname is not persisted in config. Use --hostname with up command.\n")
		}
	case "enable-rosenpass":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, RosenpassEnabled: &b}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set enable-rosenpass: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set enable-rosenpass to: %v\n", b)
		} else {
			fmt.Printf("Set enable-rosenpass to: %v\n", b)
		}
	case "rosenpass-permissive":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, RosenpassPermissive: &b}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set rosenpass-permissive: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set rosenpass-permissive to: %v\n", b)
		} else {
			fmt.Printf("Set rosenpass-permissive to: %v\n", b)
		}
	case "allow-server-ssh":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, ServerSSHAllowed: &b}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set allow-server-ssh: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set allow-server-ssh to: %v\n", b)
		} else {
			fmt.Printf("Set allow-server-ssh to: %v\n", b)
		}
	case "network-monitor":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, NetworkMonitor: &b}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set network-monitor: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set network-monitor to: %v\n", b)
		} else {
			fmt.Printf("Set network-monitor to: %v\n", b)
		}
	case "disable-auto-connect":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, DisableAutoConnect: &b}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set disable-auto-connect: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set disable-auto-connect to: %v\n", b)
		} else {
			fmt.Printf("Set disable-auto-connect to: %v\n", b)
		}
	case "disable-client-routes":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, DisableClientRoutes: &b}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set disable-client-routes: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set disable-client-routes to: %v\n", b)
		} else {
			fmt.Printf("Set disable-client-routes to: %v\n", b)
		}
	case "disable-server-routes":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, DisableServerRoutes: &b}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set disable-server-routes: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set disable-server-routes to: %v\n", b)
		} else {
			fmt.Printf("Set disable-server-routes to: %v\n", b)
		}
	case "disable-dns":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, DisableDNS: &b}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set disable-dns: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set disable-dns to: %v\n", b)
		} else {
			fmt.Printf("Set disable-dns to: %v\n", b)
		}
	case "disable-firewall":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, DisableFirewall: &b}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set disable-firewall: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set disable-firewall to: %v\n", b)
		} else {
			fmt.Printf("Set disable-firewall to: %v\n", b)
		}
	case "block-lan-access":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, BlockLANAccess: &b}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set block-lan-access: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set block-lan-access to: %v\n", b)
		} else {
			fmt.Printf("Set block-lan-access to: %v\n", b)
		}
	case "block-inbound":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, BlockInbound: &b}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set block-inbound: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set block-inbound to: %v\n", b)
		} else {
			fmt.Printf("Set block-inbound to: %v\n", b)
		}
	case "enable-lazy-connection":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		input := internal.ConfigInput{ConfigPath: configPath, LazyConnectionEnabled: &b}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set enable-lazy-connection: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set enable-lazy-connection to: %v\n", b)
		} else {
			fmt.Printf("Set enable-lazy-connection to: %v\n", b)
		}
	case "wireguard-port":
		p, err := parseUint16(value)
		if err != nil {
			return err
		}
		pi := int(p)
		input := internal.ConfigInput{ConfigPath: configPath, WireguardPort: &pi}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set wireguard-port: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set wireguard-port to: %d\n", p)
		} else {
			fmt.Printf("Set wireguard-port to: %d\n", p)
		}
	case "dns-router-interval":
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid duration: %v", err)
		}
		input := internal.ConfigInput{ConfigPath: configPath, DNSRouteInterval: &d}
		_, err = internal.UpdateOrCreateConfig(input)
		if err != nil {
			return fmt.Errorf("failed to set dns-router-interval: %v", err)
		}
		if cmd != nil {
			cmd.Printf("Set dns-router-interval to: %s\n", d)
		} else {
			fmt.Printf("Set dns-router-interval to: %s\n", d)
		}
	default:
		return fmt.Errorf("unknown setting: %s", setting)
	}

	if cmd != nil {
		cmd.Println("Configuration updated successfully.")
	} else {
		fmt.Println("Configuration updated successfully.")
	}
	return nil
}

func parseBool(val string) (bool, error) {
	v := strings.ToLower(val)
	if v == "true" || v == "1" {
		return true, nil
	}
	if v == "false" || v == "0" {
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean value: %s", val)
}

func parseUint16(val string) (uint16, error) {
	var p uint16
	_, err := fmt.Sscanf(val, "%d", &p)
	if err != nil {
		return 0, fmt.Errorf("invalid uint16 value: %s", val)
	}
	return p, nil
}
