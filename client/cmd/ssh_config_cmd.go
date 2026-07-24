package cmd

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

var (
	setSSHConfigProfile     string
	setSSHConfigUsername    string
	setSSHConfigEnableRoot  bool
	setSSHConfigDisableAuth bool
)

// setSSHConfigCmd applies the privileged SSH settings (enable root login /
// disable auth) to a profile over the daemon IPC. Hidden because users
// interact via `netbird up` / the UI, not directly.
var setSSHConfigCmd = &cobra.Command{
	Use:    SetSSHConfigCmdName,
	Short:  "Apply privileged SSH settings to a profile (internal elevation target)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx := internal.CtxInitState(cmd.Context())

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			return fmt.Errorf("connect to daemon: %w", err)
		}
		defer func() {
			if cerr := conn.Close(); cerr != nil {
				log.Warnf("failed closing daemon gRPC client connection: %v", cerr)
			}
		}()

		var enableRoot, disableAuth *bool
		if cmd.Flags().Changed(enableSSHRootFlag) {
			enableRoot = &setSSHConfigEnableRoot
		}
		if cmd.Flags().Changed(disableSSHAuthFlag) {
			disableAuth = &setSSHConfigDisableAuth
		}

		req := buildSetSSHConfigRequest(setSSHConfigProfile, setSSHConfigUsername, enableRoot, disableAuth)
		if _, err := proto.NewDaemonServiceClient(conn).SetConfig(ctx, req); err != nil {
			return fmt.Errorf("apply SSH config: %w", err)
		}
		return nil
	},
}

// buildSetSSHConfigRequest builds a minimal SetConfigRequest that touches only
// the SSH fields that were provided (nil pointers leave the daemon's stored
// value untouched, matching setupSetConfigReq's pointer semantics).
func buildSetSSHConfigRequest(profileName, username string, enableSSHRoot, disableSSHAuth *bool) *proto.SetConfigRequest {
	return &proto.SetConfigRequest{
		ProfileName:    profileName,
		Username:       username,
		EnableSSHRoot:  enableSSHRoot,
		DisableSSHAuth: disableSSHAuth,
	}
}

func init() {
	setSSHConfigCmd.Flags().StringVar(&setSSHConfigProfile, "profile", "", "profile name to apply the SSH settings to")
	setSSHConfigCmd.Flags().StringVar(&setSSHConfigUsername, "username", "", "owning username of the profile")
	setSSHConfigCmd.Flags().BoolVar(&setSSHConfigEnableRoot, enableSSHRootFlag, false, "enable root login for the SSH server")
	setSSHConfigCmd.Flags().BoolVar(&setSSHConfigDisableAuth, disableSSHAuthFlag, false, "disable SSH authentication")
}
