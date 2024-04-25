package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debugging commands",
}

var debugBundleCmd = &cobra.Command{
	Use:     "bundle",
	Example: "  netbird debug bundle",
	Short:   "Create a debug bundle",
	RunE:    debugBundle,
}

func debugBundle(cmd *cobra.Command, _ []string) error {
	conn, err := getClient(cmd.Context())
	if err != nil {
		return err
	}
	defer conn.Close()

	var statusOutputString string
	statusResp, err := getStatus(cmd.Context())
	if err != nil {
		cmd.PrintErrf("Failed to get status: %v\n", err)
	} else {
		statusOutputString = parseToFullDetailSummary(convertToStatusOutputOverview(statusResp))
	}

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.DebugBundle(cmd.Context(), &proto.DebugBundleRequest{
		Anonymize: anonymizeFlag,
		Status:    statusOutputString,
	})
	if err != nil {
		return fmt.Errorf("failed to bundle debug: %v", status.Convert(err).Message())
	}

	cmd.Println(resp.GetPath())

	return nil
}
