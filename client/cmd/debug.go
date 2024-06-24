package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/server"
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debugging commands",
	Long:  "Provides commands for debugging and logging control within the Netbird daemon.",
}

var debugBundleCmd = &cobra.Command{
	Use:     "bundle",
	Example: "  netbird debug bundle",
	Short:   "Create a debug bundle",
	Long:    "Generates a compressed archive of the daemon's logs and status for debugging purposes.",
	RunE:    debugBundle,
}

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "Manage logging for the Netbird daemon",
	Long:  `Commands to manage logging settings for the Netbird daemon, including ICE, gRPC, and general log levels.`,
}

var logLevelCmd = &cobra.Command{
	Use:   "level <level>",
	Short: "Set the logging level for this session",
	Long: `Sets the logging level for the current session. This setting is temporary and will revert to the default on daemon restart.
Available log levels are:
  panic:   for panic level, highest level of severity
  fatal:   for fatal level errors that cause the program to exit
  error:   for error conditions
  warn:    for warning conditions
  info:    for informational messages
  debug:   for debug-level messages
  trace:   for trace-level messages, which include more fine-grained information than debug`,
	Args: cobra.ExactArgs(1),
	RunE: setLogLevel,
}

var forCmd = &cobra.Command{
	Use:     "for <time>",
	Short:   "Run debug logs for a specified duration and create a debug bundle",
	Long:    `Sets the logging level to trace, runs for the specified duration, and then generates a debug bundle.`,
	Example: "  netbird debug for 5m",
	Args:    cobra.ExactArgs(1),
	RunE:    runForDuration,
}

func debugBundle(cmd *cobra.Command, _ []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.DebugBundle(cmd.Context(), &proto.DebugBundleRequest{
		Anonymize: anonymizeFlag,
		Status:    getStatusOutput(cmd),
	})
	if err != nil {
		return fmt.Errorf("failed to bundle debug: %v", status.Convert(err).Message())
	}

	cmd.Println(resp.GetPath())

	return nil
}

func setLogLevel(cmd *cobra.Command, args []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	level := server.ParseLogLevel(args[0])
	if level == proto.LogLevel_UNKNOWN {
		return fmt.Errorf("unknown log level: %s. Available levels are: panic, fatal, error, warn, info, debug, trace\n", args[0])
	}

	_, err = client.SetLogLevel(cmd.Context(), &proto.SetLogLevelRequest{
		Level: level,
	})
	if err != nil {
		return fmt.Errorf("failed to set log level: %v", status.Convert(err).Message())
	}

	cmd.Println("Log level set successfully to", args[0])
	return nil
}

func runForDuration(cmd *cobra.Command, args []string) error {
	duration, err := time.ParseDuration(args[0])
	if err != nil {
		return fmt.Errorf("invalid duration format: %v", err)
	}

	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)

	stat, err := client.Status(cmd.Context(), &proto.StatusRequest{})
	if err != nil {
		return fmt.Errorf("failed to get status: %v", status.Convert(err).Message())
	}

	restoreUp := stat.Status == string(internal.StatusConnected) || stat.Status == string(internal.StatusConnecting)

	initialLogLevel, err := client.GetLogLevel(cmd.Context(), &proto.GetLogLevelRequest{})
	if err != nil {
		return fmt.Errorf("failed to get log level: %v", status.Convert(err).Message())
	}

	if _, err := client.Down(cmd.Context(), &proto.DownRequest{}); err != nil {
		return fmt.Errorf("failed to down: %v", status.Convert(err).Message())
	}
	cmd.Println("Netbird down")

	initialLevelTrace := initialLogLevel.GetLevel() >= proto.LogLevel_TRACE
	if !initialLevelTrace {
		_, err = client.SetLogLevel(cmd.Context(), &proto.SetLogLevelRequest{
			Level: proto.LogLevel_TRACE,
		})
		if err != nil {
			return fmt.Errorf("failed to set log level to TRACE: %v", status.Convert(err).Message())
		}
		cmd.Println("Log level set to trace.")
	}

	time.Sleep(1 * time.Second)

	if _, err := client.Up(cmd.Context(), &proto.UpRequest{}); err != nil {
		return fmt.Errorf("failed to up: %v", status.Convert(err).Message())
	}
	cmd.Println("Netbird up")

	time.Sleep(3 * time.Second)

	headerPostUp := fmt.Sprintf("----- Netbird post-up - Timestamp: %s", time.Now().Format(time.RFC3339))
	statusOutput := fmt.Sprintf("%s\n%s", headerPostUp, getStatusOutput(cmd))

	if waitErr := waitForDurationOrCancel(cmd.Context(), duration, cmd); waitErr != nil {
		return waitErr
	}
	cmd.Println("\nDuration completed")

	headerPreDown := fmt.Sprintf("----- Netbird pre-down - Timestamp: %s - Duration: %s", time.Now().Format(time.RFC3339), duration)
	statusOutput = fmt.Sprintf("%s\n%s\n%s", statusOutput, headerPreDown, getStatusOutput(cmd))

	if _, err := client.Down(cmd.Context(), &proto.DownRequest{}); err != nil {
		return fmt.Errorf("failed to down: %v", status.Convert(err).Message())
	}
	cmd.Println("Netbird down")

	time.Sleep(1 * time.Second)

	if restoreUp {
		if _, err := client.Up(cmd.Context(), &proto.UpRequest{}); err != nil {
			return fmt.Errorf("failed to up: %v", status.Convert(err).Message())
		}
		cmd.Println("Netbird up")
	}

	if !initialLevelTrace {
		if _, err := client.SetLogLevel(cmd.Context(), &proto.SetLogLevelRequest{Level: initialLogLevel.GetLevel()}); err != nil {
			return fmt.Errorf("failed to restore log level: %v", status.Convert(err).Message())
		}
		cmd.Println("Log level restored to", initialLogLevel.GetLevel())
	}

	cmd.Println("Creating debug bundle...")

	resp, err := client.DebugBundle(cmd.Context(), &proto.DebugBundleRequest{
		Anonymize: anonymizeFlag,
		Status:    statusOutput,
	})
	if err != nil {
		return fmt.Errorf("failed to bundle debug: %v", status.Convert(err).Message())
	}

	cmd.Println(resp.GetPath())

	return nil
}

func getStatusOutput(cmd *cobra.Command) string {
	var statusOutputString string
	statusResp, err := getStatus(cmd.Context())
	if err != nil {
		cmd.PrintErrf("Failed to get status: %v\n", err)
	} else {
		statusOutputString = parseToFullDetailSummary(convertToStatusOutputOverview(statusResp))
	}
	return statusOutputString
}

func waitForDurationOrCancel(ctx context.Context, duration time.Duration, cmd *cobra.Command) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				elapsed := time.Since(startTime)
				if elapsed >= duration {
					return
				}
				remaining := duration - elapsed
				cmd.Printf("\rRemaining time: %s", formatDuration(remaining))
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d %= time.Hour
	m := d / time.Minute
	d %= time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}
