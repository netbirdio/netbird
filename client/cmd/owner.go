package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
)

var ownerCmd = &cobra.Command{
	Use:   "owner",
	Short: "Manage daemon owner UIDs",
	Long: `Manage the list of UIDs allowed to control the NetBird daemon.

Owners are persisted in the active profile config and survive daemon restarts.
The first call from the user logged in at the GUI / console session claims
ownership automatically; these subcommands cover the rest of the lifecycle.`,
}

var ownerAddCmd = &cobra.Command{
	Use:   "add <uid>",
	Short: "Add a UID as an owner of the daemon",
	Long: `Add a UID to the active profile's owner list. Requires root or an
existing owner. Use this to grant another local user permanent access without
having them log in at the console first.`,
	Args: cobra.ExactArgs(1),
	RunE: addOwnerFunc,
}

var ownerResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Clear the daemon's owner list",
	Long: `Clear the active profile's owner list, returning the daemon to its
unconfigured state. The next call from the active console-session user will
re-claim ownership. Requires root.`,
	RunE: resetOwnerFunc,
}

func addOwnerFunc(cmd *cobra.Command, args []string) error {
	if err := setupCmd(cmd); err != nil {
		return err
	}

	uid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("parse uid %q: %w", args[0], err)
	}

	conn, err := DialClientGRPCServer(cmd.Context(), daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	if _, err := client.AddOwner(cmd.Context(), &proto.AddOwnerRequest{Uid: uint32(uid)}); err != nil {
		return fmt.Errorf("add owner: %w", err)
	}

	cmd.Printf("UID %d added as owner\n", uid)
	return nil
}

func resetOwnerFunc(cmd *cobra.Command, _ []string) error {
	if err := setupCmd(cmd); err != nil {
		return err
	}

	conn, err := DialClientGRPCServer(cmd.Context(), daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	if _, err := client.ResetOwner(cmd.Context(), &proto.ResetOwnerRequest{}); err != nil {
		return fmt.Errorf("reset owner: %w", err)
	}

	cmd.Println("daemon owner list cleared; next call from the active console user will re-claim ownership")
	return nil
}
