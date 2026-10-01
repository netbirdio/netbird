package cmd

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

var (
	allFlag bool
)

var stateCmd = &cobra.Command{
	Use:   "state",
	Short: "Manage daemon state",
	Long:  "Provides commands for managing and inspecting the NetBird daemon state.",
}

var stateListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all stored states",
	Long:    "Lists all registered states with their status and basic information.",
	Example: "  netbird state list",
	RunE:    stateList,
}

var stateCleanCmd = &cobra.Command{
	Use:   "clean [state-name]",
	Short: "Clean stored states",
	Long: `Clean specific state or all states. The daemon must not be running.
This will perform cleanup operations and remove the state.`,
	Example: `  netbird state clean dns_state
  netbird state clean --all`,
	RunE: stateClean,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Check mutual exclusivity between --all flag and state-name argument
		if allFlag && len(args) > 0 {
			return fmt.Errorf("cannot specify both --all flag and state name")
		}
		if !allFlag && len(args) != 1 {
			return fmt.Errorf("requires a state name argument or --all flag")
		}
		return nil
	},
}

var stateDeleteCmd = &cobra.Command{
	Use:   "delete [state-name]",
	Short: "Delete stored states",
	Long: `Delete specific state or all states from storage. The daemon must not be running.
This will remove the state without performing any cleanup operations.`,
	Example: `  netbird state delete dns_state
  netbird state delete --all`,
	RunE: stateDelete,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Check mutual exclusivity between --all flag and state-name argument
		if allFlag && len(args) > 0 {
			return fmt.Errorf("cannot specify both --all flag and state name")
		}
		if !allFlag && len(args) != 1 {
			return fmt.Errorf("requires a state name argument or --all flag")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(stateCmd)
	stateCmd.AddCommand(stateListCmd, stateCleanCmd, stateDeleteCmd)

	stateCleanCmd.Flags().BoolVarP(&allFlag, "all", "a", false, "Clean all states")
	stateDeleteCmd.Flags().BoolVarP(&allFlag, "all", "a", false, "Delete all states")
}

func stateList(cmd *cobra.Command, _ []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Errorf(errCloseConnection, err)
		}
	}()

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.ListStates(cmd.Context(), &proto.ListStatesRequest{})
	if err != nil {
		return fmt.Errorf("failed to list states: %v", status.Convert(err).Message())
	}

	cmd.Printf("\nStored states:\n\n")
	for _, state := range resp.States {
		cmd.Printf("- %s\n", state.Name)
	}

	return nil
}

func stateClean(cmd *cobra.Command, args []string) error {
	var stateName string
	if !allFlag {
		stateName = args[0]
	}

	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Errorf(errCloseConnection, err)
		}
	}()

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.CleanState(cmd.Context(), &proto.CleanStateRequest{
		StateName: stateName,
		All:       allFlag,
	})
	if err != nil {
		return fmt.Errorf("failed to clean state: %v", status.Convert(err).Message())
	}

	if resp.CleanedStates == 0 {
		cmd.Println("No states were cleaned")
		return nil
	}

	if allFlag {
		cmd.Printf("Successfully cleaned %d states\n", resp.CleanedStates)
	} else {
		cmd.Printf("Successfully cleaned state %q\n", stateName)
	}

	return nil
}

func stateDelete(cmd *cobra.Command, args []string) error {
	var stateName string
	if !allFlag {
		stateName = args[0]
	}

	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Errorf(errCloseConnection, err)
		}
	}()

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.DeleteState(cmd.Context(), &proto.DeleteStateRequest{
		StateName: stateName,
		All:       allFlag,
	})
	if err != nil {
		return fmt.Errorf("failed to delete state: %v", status.Convert(err).Message())
	}

	if resp.DeletedStates == 0 {
		cmd.Println("No states were deleted")
		return nil
	}

	if allFlag {
		cmd.Printf("Successfully deleted %d states\n", resp.DeletedStates)
	} else {
		cmd.Printf("Successfully deleted state %q\n", stateName)
	}

	return nil
}
