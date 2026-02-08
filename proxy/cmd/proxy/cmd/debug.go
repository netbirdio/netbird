package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/proxy/internal/debug"
)

var (
	debugAddr  string
	jsonOutput bool

	// status filters
	statusFilterByIPs            []string
	statusFilterByNames          []string
	statusFilterByStatus         string
	statusFilterByConnectionType string
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug commands for inspecting proxy state",
	Long:  "Debug commands for inspecting the reverse proxy state via the debug HTTP endpoint.",
}

var debugHealthCmd = &cobra.Command{
	Use:          "health",
	Short:        "Show proxy health status",
	RunE:         runDebugHealth,
	SilenceUsage: true,
}

var debugClientsCmd = &cobra.Command{
	Use:          "clients",
	Aliases:      []string{"list"},
	Short:        "List all connected clients",
	RunE:         runDebugClients,
	SilenceUsage: true,
}

var debugStatusCmd = &cobra.Command{
	Use:          "status <account-id>",
	Short:        "Show client status",
	Args:         cobra.ExactArgs(1),
	RunE:         runDebugStatus,
	SilenceUsage: true,
}

var debugSyncCmd = &cobra.Command{
	Use:          "sync-response <account-id>",
	Short:        "Show client sync response",
	Args:         cobra.ExactArgs(1),
	RunE:         runDebugSync,
	SilenceUsage: true,
}

var pingTimeout string

var debugPingCmd = &cobra.Command{
	Use:          "ping <account-id> <host> [port]",
	Short:        "TCP ping through a client",
	Long:         "Perform a TCP ping through a client's network to test connectivity.\nPort defaults to 80 if not specified.",
	Args:         cobra.RangeArgs(2, 3),
	RunE:         runDebugPing,
	SilenceUsage: true,
}

var debugLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Manage client logging",
	Long:  "Commands to manage logging settings for a client connected through the proxy.",
}

var debugLogLevelCmd = &cobra.Command{
	Use:          "level <account-id> <level>",
	Short:        "Set client log level",
	Long:         "Set the log level for a client (trace, debug, info, warn, error).",
	Args:         cobra.ExactArgs(2),
	RunE:         runDebugLogLevel,
	SilenceUsage: true,
}

var debugStartCmd = &cobra.Command{
	Use:          "start <account-id>",
	Short:        "Start a client",
	Args:         cobra.ExactArgs(1),
	RunE:         runDebugStart,
	SilenceUsage: true,
}

var debugStopCmd = &cobra.Command{
	Use:          "stop <account-id>",
	Short:        "Stop a client",
	Args:         cobra.ExactArgs(1),
	RunE:         runDebugStop,
	SilenceUsage: true,
}

func init() {
	debugCmd.PersistentFlags().StringVar(&debugAddr, "addr", envStringOrDefault("NB_PROXY_DEBUG_ADDRESS", "localhost:8444"), "Debug endpoint address")
	debugCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output JSON instead of pretty format")

	debugStatusCmd.Flags().StringSliceVar(&statusFilterByIPs, "filter-by-ips", nil, "Filter by peer IPs (comma-separated)")
	debugStatusCmd.Flags().StringSliceVar(&statusFilterByNames, "filter-by-names", nil, "Filter by peer names (comma-separated)")
	debugStatusCmd.Flags().StringVar(&statusFilterByStatus, "filter-by-status", "", "Filter by status (idle|connecting|connected)")
	debugStatusCmd.Flags().StringVar(&statusFilterByConnectionType, "filter-by-connection-type", "", "Filter by connection type (P2P|Relayed)")

	debugPingCmd.Flags().StringVar(&pingTimeout, "timeout", "", "Ping timeout (e.g., 10s)")

	debugCmd.AddCommand(debugHealthCmd)
	debugCmd.AddCommand(debugClientsCmd)
	debugCmd.AddCommand(debugStatusCmd)
	debugCmd.AddCommand(debugSyncCmd)
	debugCmd.AddCommand(debugPingCmd)
	debugLogCmd.AddCommand(debugLogLevelCmd)
	debugCmd.AddCommand(debugLogCmd)
	debugCmd.AddCommand(debugStartCmd)
	debugCmd.AddCommand(debugStopCmd)

	rootCmd.AddCommand(debugCmd)
}

func getDebugClient(cmd *cobra.Command) *debug.Client {
	return debug.NewClient(debugAddr, jsonOutput, cmd.OutOrStdout())
}

func runDebugHealth(cmd *cobra.Command, _ []string) error {
	return getDebugClient(cmd).Health(cmd.Context())
}

func runDebugClients(cmd *cobra.Command, _ []string) error {
	return getDebugClient(cmd).ListClients(cmd.Context())
}

func runDebugStatus(cmd *cobra.Command, args []string) error {
	return getDebugClient(cmd).ClientStatus(cmd.Context(), args[0], debug.StatusFilters{
		IPs:            statusFilterByIPs,
		Names:          statusFilterByNames,
		Status:         statusFilterByStatus,
		ConnectionType: statusFilterByConnectionType,
	})
}

func runDebugSync(cmd *cobra.Command, args []string) error {
	return getDebugClient(cmd).ClientSyncResponse(cmd.Context(), args[0])
}

func runDebugPing(cmd *cobra.Command, args []string) error {
	port := 80
	if len(args) > 2 {
		p, err := strconv.Atoi(args[2])
		if err != nil {
			return fmt.Errorf("invalid port: %w", err)
		}
		port = p
	}
	return getDebugClient(cmd).PingTCP(cmd.Context(), args[0], args[1], port, pingTimeout)
}

func runDebugLogLevel(cmd *cobra.Command, args []string) error {
	return getDebugClient(cmd).SetLogLevel(cmd.Context(), args[0], args[1])
}

func runDebugStart(cmd *cobra.Command, args []string) error {
	return getDebugClient(cmd).StartClient(cmd.Context(), args[0])
}

func runDebugStop(cmd *cobra.Command, args []string) error {
	return getDebugClient(cmd).StopClient(cmd.Context(), args[0])
}
