package cmd

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/netbirdio/netbird/idp/oidcprovider"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage IdP users",
	Long:  "Commands for managing users in the embedded IdP",
}

var userAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new user",
	Long:  "Add a new user to the embedded IdP",
	RunE:  userAdd,
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	Long:  "List all users in the embedded IdP",
	RunE:  userList,
}

var userDeleteCmd = &cobra.Command{
	Use:   "delete <username>",
	Short: "Delete a user",
	Long:  "Delete a user from the embedded IdP",
	Args:  cobra.ExactArgs(1),
	RunE:  userDelete,
}

var userPasswordCmd = &cobra.Command{
	Use:   "password <username>",
	Short: "Change user password",
	Long:  "Change password for a user in the embedded IdP",
	Args:  cobra.ExactArgs(1),
	RunE:  userChangePassword,
}

// User add flags
var (
	userUsername  string
	userEmail     string
	userFirstName string
	userLastName  string
	userPassword  string
)

func init() {
	userAddCmd.Flags().StringVarP(&userUsername, "username", "u", "", "username (required)")
	userAddCmd.Flags().StringVarP(&userEmail, "email", "e", "", "email address (required)")
	userAddCmd.Flags().StringVarP(&userFirstName, "first-name", "f", "", "first name")
	userAddCmd.Flags().StringVarP(&userLastName, "last-name", "l", "", "last name")
	userAddCmd.Flags().StringVarP(&userPassword, "password", "p", "", "password (will prompt if not provided)")
	_ = userAddCmd.MarkFlagRequired("username")
	_ = userAddCmd.MarkFlagRequired("email")

	userCmd.AddCommand(userAddCmd)
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userDeleteCmd)
	userCmd.AddCommand(userPasswordCmd)
}

func getStore() (*oidcprovider.Store, error) {
	ctx := context.Background()
	store, err := oidcprovider.NewStore(ctx, config.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open store: %w", err)
	}
	return store, nil
}

func userAdd(cmd *cobra.Command, args []string) error {
	store, err := getStore()
	if err != nil {
		return err
	}
	defer store.Close()

	password := userPassword
	if password == "" {
		// Prompt for password
		fmt.Print("Enter password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println()

		fmt.Print("Confirm password: ")
		byteConfirm, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password confirmation: %w", err)
		}
		fmt.Println()

		if string(bytePassword) != string(byteConfirm) {
			return fmt.Errorf("passwords do not match")
		}
		password = string(bytePassword)
	}

	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	user := &oidcprovider.User{
		Username:      userUsername,
		Email:         userEmail,
		FirstName:     userFirstName,
		LastName:      userLastName,
		Password:      password,
		EmailVerified: true, // Mark as verified since admin is creating the user
	}

	ctx := context.Background()
	if err := store.CreateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	fmt.Printf("User '%s' created successfully (ID: %s)\n", userUsername, user.ID)
	return nil
}

func userList(cmd *cobra.Command, args []string) error {
	store, err := getStore()
	if err != nil {
		return err
	}
	defer store.Close()

	ctx := context.Background()
	users, err := store.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		fmt.Println("No users found")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tUSERNAME\tEMAIL\tNAME\tVERIFIED\tCREATED")
	for _, user := range users {
		name := fmt.Sprintf("%s %s", user.FirstName, user.LastName)
		verified := "No"
		if user.EmailVerified {
			verified = "Yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			user.ID,
			user.Username,
			user.Email,
			name,
			verified,
			user.CreatedAt.Format("2006-01-02 15:04"),
		)
	}
	w.Flush()

	return nil
}

func userDelete(cmd *cobra.Command, args []string) error {
	username := args[0]

	store, err := getStore()
	if err != nil {
		return err
	}
	defer store.Close()

	ctx := context.Background()

	// Find user by username
	user, err := store.GetUserByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("user '%s' not found", username)
	}

	if err := store.DeleteUser(ctx, user.ID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	fmt.Printf("User '%s' deleted successfully\n", username)
	return nil
}

func userChangePassword(cmd *cobra.Command, args []string) error {
	username := args[0]

	store, err := getStore()
	if err != nil {
		return err
	}
	defer store.Close()

	ctx := context.Background()

	// Find user by username
	user, err := store.GetUserByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("user '%s' not found", username)
	}

	// Prompt for new password
	fmt.Print("Enter new password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println()

	fmt.Print("Confirm new password: ")
	byteConfirm, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password confirmation: %w", err)
	}
	fmt.Println()

	if string(bytePassword) != string(byteConfirm) {
		return fmt.Errorf("passwords do not match")
	}

	password := string(bytePassword)
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	if err := store.UpdateUserPassword(ctx, user.ID, password); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	fmt.Printf("Password updated for user '%s'\n", username)
	return nil
}
