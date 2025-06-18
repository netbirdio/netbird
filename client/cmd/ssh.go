package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/util"
)

var (
	port     int
	username string
	host     string
	command  string
)

var sshCmd = &cobra.Command{
	Use:   "ssh [user@]host [command]",
	Short: "Connect to a NetBird peer via SSH",
	Long: `Connect to a NetBird peer using SSH.

Examples:
  netbird ssh peer-hostname
  netbird ssh user@peer-hostname
  netbird ssh peer-hostname --login myuser
  netbird ssh peer-hostname -p 22022
  netbird ssh peer-hostname ls -la
  netbird ssh peer-hostname whoami`,
	DisableFlagParsing: true,
	Args:               validateSSHArgsWithoutFlagParsing,
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)
		SetFlagsFromEnvVars(cmd)

		cmd.SetOut(cmd.OutOrStdout())

		if err := util.InitLog(logLevel, "console"); err != nil {
			return fmt.Errorf("init log: %w", err)
		}

		ctx := internal.CtxInitState(cmd.Context())

		config, err := internal.UpdateConfig(internal.ConfigInput{
			ConfigPath: configPath,
		})
		if err != nil {
			return fmt.Errorf("update config: %w", err)
		}

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		sshctx, cancel := context.WithCancel(ctx)

		go func() {
			if err := runSSH(sshctx, host, []byte(config.SSHKey), cmd); err != nil {
				cmd.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			cancel()
		}()

		select {
		case <-sig:
			cancel()
		case <-sshctx.Done():
		}

		return nil
	},
}

func validateSSHArgsWithoutFlagParsing(_ *cobra.Command, args []string) error {
	if len(args) < 1 {
		return errors.New("host argument required")
	}

	// Reset globals to defaults
	port = nbssh.DefaultSSHPort
	username = ""
	host = ""
	command = ""

	// Create a new FlagSet for parsing SSH-specific flags
	fs := flag.NewFlagSet("ssh-flags", flag.ContinueOnError)
	fs.SetOutput(nil) // Suppress error output

	// Define SSH-specific flags
	portFlag := fs.Int("p", nbssh.DefaultSSHPort, "SSH port")
	fs.Int("port", nbssh.DefaultSSHPort, "SSH port")
	userFlag := fs.String("u", "", "SSH username")
	fs.String("user", "", "SSH username")
	loginFlag := fs.String("login", "", "SSH username (alias for --user)")

	// Parse flags until we hit the hostname (first non-flag argument)
	err := fs.Parse(args)
	if err != nil {
		// If flag parsing fails, treat everything as hostname + command
		// This handles cases like `ssh hostname ls -la` where `-la` should be part of the command
		return parseHostnameAndCommand(args)
	}

	// Get the remaining args (hostname and command)
	remaining := fs.Args()
	if len(remaining) < 1 {
		return errors.New("host argument required")
	}

	// Set parsed values
	port = *portFlag
	if *userFlag != "" {
		username = *userFlag
	} else if *loginFlag != "" {
		username = *loginFlag
	}

	return parseHostnameAndCommand(remaining)
}

func parseHostnameAndCommand(args []string) error {
	if len(args) < 1 {
		return errors.New("host argument required")
	}

	// Parse hostname (possibly with user@host format)
	arg := args[0]
	if strings.Contains(arg, "@") {
		parts := strings.SplitN(arg, "@", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return errors.New("invalid user@host format")
		}
		// Only use username from host if not already set by flags
		if username == "" {
			username = parts[0]
		}
		host = parts[1]
	} else {
		host = arg
	}

	// Set default username if none provided
	if username == "" {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			username = sudoUser
		} else if currentUser, err := user.Current(); err == nil {
			username = currentUser.Username
		} else {
			username = "root"
		}
	}

	// Everything after hostname becomes the command
	if len(args) > 1 {
		command = strings.Join(args[1:], " ")
	}

	return nil
}

func runSSH(ctx context.Context, addr string, pemKey []byte, cmd *cobra.Command) error {
	target := fmt.Sprintf("%s:%d", addr, port)
	c, err := nbssh.DialWithKey(ctx, target, username, pemKey)
	if err != nil {
		cmd.Printf("Failed to connect to %s@%s\n", username, target)
		cmd.Printf("\nTroubleshooting steps:\n")
		cmd.Printf("  1. Check peer connectivity: netbird status\n")
		cmd.Printf("  2. Verify SSH server is enabled on the peer\n")
		cmd.Printf("  3. Ensure correct hostname/IP is used\n\n")
		return fmt.Errorf("dial %s: %w", target, err)
	}
	go func() {
		<-ctx.Done()
		_ = c.Close()
	}()

	if command != "" {
		if err := c.ExecuteCommandWithIO(ctx, command); err != nil {
			return err
		}
	} else {
		if err := c.OpenTerminal(ctx); err != nil {
			return err
		}
	}

	return nil
}

func init() {
	sshCmd.PersistentFlags().IntVarP(&port, "port", "p", nbssh.DefaultSSHPort, "Remote SSH port")
	sshCmd.PersistentFlags().StringVarP(&username, "user", "u", "", "SSH username")
	sshCmd.PersistentFlags().StringVar(&username, "login", "", "SSH username (alias for --user)")
}
