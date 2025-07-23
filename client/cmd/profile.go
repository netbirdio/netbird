package cmd

import (
	"context"
	"fmt"
	"time"

	"os/user"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "manage Netbird profiles",
	Long:  `Manage Netbird profiles, allowing you to list, switch, and remove profiles.`,
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "list all profiles",
	Long:  `List all available profiles in the Netbird client.`,
	RunE:  listProfilesFunc,
}

var profileAddCmd = &cobra.Command{
	Use:   "add <profile_name>",
	Short: "add a new profile",
	Long:  `Add a new profile to the Netbird client. The profile name must be unique.`,
	Args:  cobra.ExactArgs(1),
	RunE:  addProfileFunc,
}

var profileRemoveCmd = &cobra.Command{
	Use:   "remove <profile_name>",
	Short: "remove a profile",
	Long:  `Remove a profile from the Netbird client. The profile must not be active.`,
	Args:  cobra.ExactArgs(1),
	RunE:  removeProfileFunc,
}

var profileSelectCmd = &cobra.Command{
	Use:   "select <profile_name>",
	Short: "select a profile",
	Long:  `Select a profile to be the active profile in the Netbird client. The profile must exist.`,
	Args:  cobra.ExactArgs(1),
	RunE:  selectProfileFunc,
}

func setupCmd(cmd *cobra.Command) error {
	SetFlagsFromEnvVars(rootCmd)
	SetFlagsFromEnvVars(cmd)

	cmd.SetOut(cmd.OutOrStdout())

	err := util.InitLog(logLevel, "console")
	if err != nil {
		return err
	}

	return nil
}
func listProfilesFunc(cmd *cobra.Command, _ []string) error {
	if err := setupCmd(cmd); err != nil {
		return err
	}

	conn, err := DialClientGRPCServer(cmd.Context(), daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to service CLI interface: %w", err)
	}
	defer conn.Close()

	currUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	daemonClient := proto.NewDaemonServiceClient(conn)

	profiles, err := daemonClient.ListProfiles(cmd.Context(), &proto.ListProfilesRequest{
		Username: currUser.Username,
	})
	if err != nil {
		return err
	}

	// list profiles, add a tick if the profile is active
	cmd.Println("Found", len(profiles.Profiles), "profiles:")
	for _, profile := range profiles.Profiles {
		// use a cross to indicate the passive profiles
		activeMarker := "✗"
		if profile.IsActive {
			activeMarker = "✓"
		}
		cmd.Println(activeMarker, profile.Name)
	}

	return nil
}

func addProfileFunc(cmd *cobra.Command, args []string) error {
	if err := setupCmd(cmd); err != nil {
		return err
	}

	conn, err := DialClientGRPCServer(cmd.Context(), daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to service CLI interface: %w", err)
	}
	defer conn.Close()

	currUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	daemonClient := proto.NewDaemonServiceClient(conn)

	profileName := args[0]

	_, err = daemonClient.AddProfile(cmd.Context(), &proto.AddProfileRequest{
		ProfileName: profileName,
		Username:    currUser.Username,
	})
	if err != nil {
		return err
	}

	cmd.Println("Profile added successfully:", profileName)
	return nil
}

func removeProfileFunc(cmd *cobra.Command, args []string) error {
	if err := setupCmd(cmd); err != nil {
		return err
	}

	conn, err := DialClientGRPCServer(cmd.Context(), daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to service CLI interface: %w", err)
	}
	defer conn.Close()

	currUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	daemonClient := proto.NewDaemonServiceClient(conn)

	profileName := args[0]

	_, err = daemonClient.RemoveProfile(cmd.Context(), &proto.RemoveProfileRequest{
		ProfileName: profileName,
		Username:    currUser.Username,
	})
	if err != nil {
		return err
	}

	cmd.Println("Profile removed successfully:", profileName)
	return nil
}

func selectProfileFunc(cmd *cobra.Command, args []string) error {
	if err := setupCmd(cmd); err != nil {
		return err
	}

	profileManager := profilemanager.NewProfileManager()
	profileName := args[0]

	currUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*7)
	defer cancel()
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to service CLI interface: %w", err)
	}
	defer conn.Close()

	daemonClient := proto.NewDaemonServiceClient(conn)

	profiles, err := daemonClient.ListProfiles(ctx, &proto.ListProfilesRequest{
		Username: currUser.Username,
	})
	if err != nil {
		return fmt.Errorf("list profiles: %w", err)
	}

	var profileExists bool

	for _, profile := range profiles.Profiles {
		if profile.Name == profileName {
			profileExists = true
			break
		}
	}

	if !profileExists {
		return fmt.Errorf("profile %s does not exist", profileName)
	}

	if err := switchProfile(cmd.Context(), profileName, currUser.Username); err != nil {
		return err
	}

	err = profileManager.SwitchProfile(profileName)
	if err != nil {
		return err
	}

	status, err := daemonClient.Status(ctx, &proto.StatusRequest{})
	if err != nil {
		return fmt.Errorf("get service status: %w", err)
	}

	if status.Status == string(internal.StatusConnected) {
		if _, err := daemonClient.Down(ctx, &proto.DownRequest{}); err != nil {
			return fmt.Errorf("call service down method: %w", err)
		}
	}

	cmd.Println("Profile switched successfully to:", profileName)
	return nil
}
