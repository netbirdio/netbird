package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

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

var debugCaptureCmd = &cobra.Command{
	Use:   "capture <account-id> [filter expression]",
	Short: "Capture packets on a client's WireGuard interface",
	Long: `Captures decrypted packets flowing through a client's WireGuard interface.

Default output is human-readable text. Use --pcap or --output for pcap binary.
Filter arguments after the account ID use BPF-like syntax.

Examples:
  netbird-proxy debug capture <account-id>
  netbird-proxy debug capture <account-id> --duration 1m host 10.0.0.1
  netbird-proxy debug capture <account-id> host 10.0.0.1 and tcp port 443
  netbird-proxy debug capture <account-id> not port 22
  netbird-proxy debug capture <account-id> -o capture.pcap
  netbird-proxy debug capture <account-id> --pcap | tcpdump -r - -n
  netbird-proxy debug capture <account-id> --pcap | tshark -r -`,
	Args:         cobra.MinimumNArgs(1),
	RunE:         runDebugCapture,
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

	debugCaptureCmd.Flags().DurationP("duration", "d", 0, "Capture duration (0 = server default)")
	debugCaptureCmd.Flags().Bool("pcap", false, "Force pcap binary output (default when --output is set)")
	debugCaptureCmd.Flags().BoolP("verbose", "v", false, "Show seq/ack, TTL, window, total length (text mode)")
	debugCaptureCmd.Flags().Bool("ascii", false, "Print payload as ASCII after each packet (text mode)")
	debugCaptureCmd.Flags().StringP("output", "o", "", "Write pcap to file instead of stdout")

	debugCmd.AddCommand(debugHealthCmd)
	debugCmd.AddCommand(debugClientsCmd)
	debugCmd.AddCommand(debugStatusCmd)
	debugCmd.AddCommand(debugSyncCmd)
	debugCmd.AddCommand(debugPingCmd)
	debugLogCmd.AddCommand(debugLogLevelCmd)
	debugCmd.AddCommand(debugLogCmd)
	debugCmd.AddCommand(debugStartCmd)
	debugCmd.AddCommand(debugStopCmd)
	debugCmd.AddCommand(debugCaptureCmd)

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

func runDebugCapture(cmd *cobra.Command, args []string) error {
	duration, _ := cmd.Flags().GetDuration("duration")
	forcePcap, _ := cmd.Flags().GetBool("pcap")
	verbose, _ := cmd.Flags().GetBool("verbose")
	ascii, _ := cmd.Flags().GetBool("ascii")
	outPath, _ := cmd.Flags().GetString("output")

	// Default to text. Use pcap when --pcap is set or --output is given.
	wantText := !forcePcap && outPath == ""

	var filterExpr string
	if len(args) > 1 {
		filterExpr = strings.Join(args[1:], " ")
	}

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	out, cleanup, err := captureOutputWriter(cmd, outPath)
	if err != nil {
		return err
	}
	defer cleanup()

	if wantText {
		cmd.PrintErrln("Capturing packets... Press Ctrl+C to stop.")
	} else {
		cmd.PrintErrln("Capturing packets (pcap)... Press Ctrl+C to stop.")
	}

	var durationStr string
	if duration > 0 {
		durationStr = duration.String()
	}

	err = getDebugClient(cmd).Capture(ctx, debug.CaptureOptions{
		AccountID:  args[0],
		Duration:   durationStr,
		FilterExpr: filterExpr,
		Text:       wantText,
		Verbose:    verbose,
		ASCII:      ascii,
		Output:     out,
	})
	if err != nil {
		return err
	}

	cmd.PrintErrln("\nCapture finished.")
	return nil
}

// captureOutputWriter returns the writer and cleanup function for capture output.
func captureOutputWriter(cmd *cobra.Command, outPath string) (out *os.File, cleanup func(), err error) {
	if outPath != "" {
		f, err := os.CreateTemp(filepath.Dir(outPath), filepath.Base(outPath)+".*.tmp")
		if err != nil {
			return nil, nil, fmt.Errorf("create output file: %w", err)
		}
		tmpPath := f.Name()
		return f, func() {
			if err := f.Close(); err != nil {
				cmd.PrintErrf("close output file: %v\n", err)
			}
			if fi, err := os.Stat(tmpPath); err == nil && fi.Size() > 0 {
				if err := os.Rename(tmpPath, outPath); err != nil {
					cmd.PrintErrf("rename output file: %v\n", err)
				} else {
					cmd.PrintErrf("Wrote %s\n", outPath)
				}
			} else {
				os.Remove(tmpPath)
			}
		}, nil
	}

	return os.Stdout, func() {
		// no cleanup needed for stdout
	}, nil
}
