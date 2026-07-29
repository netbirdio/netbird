package cmd

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

var ownerCmd = &cobra.Command{
	Use:   "owner",
	Short: "Manage who may control the NetBird daemon",
	Long: `Manage the daemon-wide owners.

Owners are enforced on the daemon and stored in the service parameters. All owners
may control the daemon and use the shared default profile (plus root/administrator),
every other profile stays isolated to the user that created it. An unowned daemon
is claimed by the first caller (trust-on-first-use).`,
}

var ownerAddCmd = &cobra.Command{
	Use:   "add <principal>",
	Short: "Add a daemon owner principal",
	Long: `Add a daemon-wide owner principal. Principals are typed:
  uid:1000               a Unix user ID
  gid:1000               a Unix group ID
  group:netbird-admins   a Unix group name (resolved via NSS/getent)
  sid:S-1-5-21-...       a Windows user or group SID

Requires root/administrator or an existing owner.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withDaemon(cmd, func(ctx context.Context, c proto.DaemonServiceClient) error {
			if _, err := c.AddOwner(ctx, &proto.AddOwnerRequest{Principal: args[0]}); err != nil {
				return err
			}
			cmd.Printf("Added daemon owner %q\n", args[0])
			return nil
		})
	},
}

var ownerResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Clear the daemon owner list (root/administrator only)",
	Long: `Clear the daemon-wide owner list, returning the daemon to the unowned
state. The next caller then claims ownership (trust-on-first-use). Requires
root/administrator.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return withDaemon(cmd, func(ctx context.Context, c proto.DaemonServiceClient) error {
			if _, err := c.ResetOwner(ctx, &proto.ResetOwnerRequest{}); err != nil {
				return err
			}
			cmd.Println("Daemon owner list cleared, the next caller will claim ownership")
			return nil
		})
	},
}

var ownerShareCmd = &cobra.Command{
	Use:   "share",
	Short: "Mark the daemon shared (any local user may control it)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return withDaemon(cmd, func(ctx context.Context, c proto.DaemonServiceClient) error {
			if _, err := c.ShareProfile(ctx, &proto.ShareProfileRequest{Shared: true}); err != nil {
				return err
			}
			cmd.Println("Daemon is now shared with all local users")
			return nil
		})
	},
}

var ownerUnshareCmd = &cobra.Command{
	Use:   "unshare",
	Short: "Stop sharing the daemon (restrict to its owners)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return withDaemon(cmd, func(ctx context.Context, c proto.DaemonServiceClient) error {
			if _, err := c.ShareProfile(ctx, &proto.ShareProfileRequest{Shared: false}); err != nil {
				return err
			}
			cmd.Println("Daemon is no longer shared")
			return nil
		})
	},
}

// withDaemon runs fn with a connected daemon client, handling setup and teardown.
func withDaemon(cmd *cobra.Command, fn func(context.Context, proto.DaemonServiceClient) error) error {
	SetFlagsFromEnvVars(rootCmd)
	cmd.SetOut(cmd.OutOrStdout())
	if err := util.InitLog(logLevel, util.LogConsole); err != nil {
		log.Errorf("failed initializing log %v", err)
		return err
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
	defer cancel()

	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		log.Errorf("failed to connect to service CLI interface %v", err)
		return err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			log.Debugf("close daemon connection: %v", cerr)
		}
	}()

	return fn(ctx, proto.NewDaemonServiceClient(conn))
}
