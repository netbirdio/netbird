package cmd

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

var debugCPUCmd = &cobra.Command{
	Use:   "cpu",
	Short: "Profile the daemon's CPU usage",
	Long: `Starts and stops CPU profiling in the running daemon without restarting it.
The profile is included in the next debug bundle as cpu.prof.`,
}

var debugCPUStartCmd = &cobra.Command{
	Use:     "start",
	Short:   "Start CPU profiling in the daemon",
	Example: "  netbird debug cpu start",
	Args:    cobra.NoArgs,
	RunE:    debugCPUStart,
}

var debugCPUStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop CPU profiling in the daemon",
	Long: `Stops CPU profiling. The captured profile stays in the daemon until the next
debug bundle is created, which includes it as cpu.prof.`,
	Example: "  netbird debug cpu stop && netbird debug bundle",
	Args:    cobra.NoArgs,
	RunE:    debugCPUStop,
}

func debugCPUStart(cmd *cobra.Command, _ []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Errorf(errCloseConnection, err)
		}
	}()

	if _, err := proto.NewDaemonServiceClient(conn).StartCPUProfile(cmd.Context(), &proto.StartCPUProfileRequest{}); err != nil {
		return fmt.Errorf("start CPU profiling: %v", status.Convert(err).Message())
	}

	cmd.Println("CPU profiling started. Run `netbird debug cpu stop` and then `netbird debug bundle` to collect it.")
	return nil
}

func debugCPUStop(cmd *cobra.Command, _ []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Errorf(errCloseConnection, err)
		}
	}()

	if _, err := proto.NewDaemonServiceClient(conn).StopCPUProfile(cmd.Context(), &proto.StopCPUProfileRequest{}); err != nil {
		return fmt.Errorf("stop CPU profiling: %v", status.Convert(err).Message())
	}

	cmd.Println("CPU profiling stopped. Run `netbird debug bundle` to include cpu.prof.")
	return nil
}

func init() {
	debugCPUCmd.AddCommand(debugCPUStartCmd)
	debugCPUCmd.AddCommand(debugCPUStopCmd)
	debugCmd.AddCommand(debugCPUCmd)
}
