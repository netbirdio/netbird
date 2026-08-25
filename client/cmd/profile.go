package cmd

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

var profileListShowID bool

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage NetBird client profiles",
	Long:  `Commands to list, add, remove, and switch profiles. Profiles allow you to maintain different accounts in one client app.`,
}

var profileListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all profiles",
	Long:    `List all available profiles in the NetBird client.`,
	Aliases: []string{"ls"},
	RunE:    listProfilesFunc,
}

var profileAddCmd = &cobra.Command{
	Use:   "add <profile_name>",
	Short: "Add a new profile",
	Long:  `Add a new profile. Profile name is free-form, a unique ID is generated for the on-disk config file.`,
	Args:  cobra.ExactArgs(1),
	RunE:  addProfileFunc,
}

var profileRenameCmd = &cobra.Command{
	Use:   "rename <profile> <new_profile_name>",
	Short: "Renames an existing profile",
	Long:  `Renames an existing profile (by a name, ID, or unique ID prefix). Profile name is free-form.`,
	Args:  cobra.ExactArgs(2),
	RunE:  renameProfileFunc,
}

var profileRemoveCmd = &cobra.Command{
	Use:     "remove <profile>",
	Short:   "Remove a profile",
	Long:    `Remove a profile by name, ID, or unique ID prefix.`,
	Aliases: []string{"rm"},
	Args:    cobra.ExactArgs(1),
	RunE:    removeProfileFunc,
}

var profileSelectCmd = &cobra.Command{
	Use:   "select <profile>",
	Short: "Select a profile",
	Long:  `Make the specified profile active. Accepts a name, ID, or unique ID prefix.`,
	Args:  cobra.ExactArgs(1),
	RunE:  selectProfileFunc,
}

func init() {
	profileListCmd.Flags().BoolVar(&profileListShowID, "show-id", false, "show the profile ID column")
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

	resp, err := daemonClient.ListProfiles(cmd.Context(), &proto.ListProfilesRequest{
		Username: currUser.Username,
	})
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	if profileListShowID {
		fmt.Fprintln(tw, "ID\tNAME\tACTIVE")
	} else {
		fmt.Fprintln(tw, "NAME\tACTIVE")
	}
	for _, profile := range resp.Profiles {
		marker := ""
		if profile.IsActive {
			marker = "✓"
		}
		name := profilemanager.StripCtrlChars(profile.Name)
		id := profilemanager.ID(profile.Id)
		if profileListShowID {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", id.ShortID(), name, marker)
		} else {
			fmt.Fprintf(tw, "%s\t%s\n", name, marker)
		}
	}
	return tw.Flush()
}

func addProfileFunc(cmd *cobra.Command, args []string) error {
	if err := setupCmd(cmd); err != nil {
		return err
	}

	currUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	conn, err := DialClientGRPCServer(cmd.Context(), daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to service CLI interface: %w", err)
	}
	defer conn.Close()

	daemonClient := proto.NewDaemonServiceClient(conn)
	profileName := args[0]

	id, err := addProfileOnDaemon(cmd.Context(), daemonClient, profileName, currUser.Username)
	if err != nil {
		return err
	}

	dupCount, _ := countProfilesWithName(cmd.Context(), daemonClient, currUser.Username, profileName)
	if dupCount > 1 {
		cmd.Printf("Warning: %d other profile(s) already use the name %q.\n", dupCount-1, profileName)
		cmd.Println("Use `netbird profile list --show-id` to disambiguate later.")
	}

	cmd.Printf("Profile added: %s  %s\n", id.ShortID(), profilemanager.StripCtrlChars(profileName))
	return nil

}

func renameProfileFunc(cmd *cobra.Command, args []string) error {
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
	handle := args[0]
	newProfilename := args[1]

	resp, err := daemonClient.RenameProfile(cmd.Context(), &proto.RenameProfileRequest{
		Handle:         handle,
		Username:       currUser.Username,
		NewProfileName: newProfilename,
	})
	if err != nil {
		return wrapAmbiguityError(err, handle)
	}

	dupCount, _ := countProfilesWithName(cmd.Context(), daemonClient, currUser.Username, newProfilename)
	if dupCount > 1 {
		cmd.Printf("Warning: %d other profile(s) already use the name %q.\n", dupCount-1, newProfilename)
		cmd.Println("Use `netbird profile list --show-id` to disambiguate later.")
	}

	cmd.Printf("Profile renamed from %s to %s\n", profilemanager.StripCtrlChars(resp.OldProfileName), profilemanager.StripCtrlChars(newProfilename))

	return nil
}

func countProfilesWithName(ctx context.Context, c proto.DaemonServiceClient, username, name string) (int, error) {
	resp, err := c.ListProfiles(ctx, &proto.ListProfilesRequest{Username: username})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range resp.Profiles {
		if p.Name == name {
			n++
		}
	}
	return n, nil
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
	handle := args[0]

	resp, err := daemonClient.RemoveProfile(cmd.Context(), &proto.RemoveProfileRequest{
		ProfileName: handle,
		Username:    currUser.Username,
	})
	if err != nil {
		return wrapAmbiguityError(err, handle)
	}

	cmd.Printf("Profile removed: %s\n", resp.Id)
	return nil
}

func selectProfileFunc(cmd *cobra.Command, args []string) error {
	if err := setupCmd(cmd); err != nil {
		return err
	}

	profileManager := profilemanager.NewProfileManager()
	handle := args[0]

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

	switchResp, err := daemonClient.SwitchProfile(ctx, &proto.SwitchProfileRequest{
		ProfileName: &handle,
		Username:    &currUser.Username,
	})
	if err != nil {
		return wrapAmbiguityError(err, handle)
	}

	if err := profileManager.SwitchProfile(profilemanager.ID(switchResp.Id)); err != nil {
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

	id := profilemanager.ID(switchResp.Id)
	cmd.Printf("Profile switched to: %s\n", id.ShortID())
	return nil
}

// wrapAmbiguityError turns the daemon's gRPC InvalidArgument errors
// (which carry the resolver's message verbatim) into CLI-friendly text
// that points the user at --show-id.
func wrapAmbiguityError(err error, handle string) error {
	if err == nil {
		return nil
	}
	st, ok := gstatus.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.InvalidArgument:
		msg := st.Message()
		if strings.Contains(msg, "ambiguous") {
			return errors.New(msg + "\nRun `netbird profile list --show-id` to see IDs, then select by ID prefix:\n  netbird profile select|remove <id-prefix>")
		}
	case codes.NotFound:
		return fmt.Errorf("profile %q not found", handle)
	}
	return err
}

// addProfileOnDaemon issues the AddProfile RPC on an existing daemon client
// and returns the new profile's ID. It is the single entry point for profile
// creation, shared by `netbird profile add` and the `netbird up --profile
// <name>` auto-create path.
func addProfileOnDaemon(ctx context.Context, client proto.DaemonServiceClient, profileName, username string) (profilemanager.ID, error) {
	resp, err := client.AddProfile(ctx, &proto.AddProfileRequest{
		ProfileName: profileName,
		Username:    username,
	})
	if err != nil {
		return "", fmt.Errorf("add profile failed: %w", err)
	}

	return profilemanager.ID(resp.Id), nil
}
