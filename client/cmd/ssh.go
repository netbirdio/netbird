package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/util"
)

var (
	port int
	user = "root"
	host string
)

var sshCmd = &cobra.Command{
	Use: "ssh [user@]host",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires a host argument")
		}

		split := strings.Split(args[0], "@")
		if len(split) == 2 {
			user = split[0]
			host = split[1]
		} else {
			host = args[0]
		}

		return nil
	},
	Short: "connect to a remote SSH server",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)
		SetFlagsFromEnvVars(cmd)

		cmd.SetOut(cmd.OutOrStdout())

		err := util.InitLog(logLevel, "console")
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		if !util.IsAdmin() {
			cmd.Printf("error: you must have Administrator privileges to run this command\n")
			return nil
		}

		ctx := internal.CtxInitState(cmd.Context())

		config, err := internal.UpdateConfig(internal.ConfigInput{
			ConfigPath: configPath,
		})
		if err != nil {
			return err
		}

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		sshctx, cancel := context.WithCancel(ctx)

		go func() {
			// blocking
			if err := runSSH(sshctx, host, []byte(config.SSHKey), cmd); err != nil {
				log.Debug(err)
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

func runSSH(ctx context.Context, addr string, pemKey []byte, cmd *cobra.Command) error {
	c, err := nbssh.DialWithKey(fmt.Sprintf("%s:%d", addr, port), user, pemKey)
	if err != nil {
		cmd.Printf("Error: %v\n", err)
		cmd.Printf("Couldn't connect. Please check the connection status or if the ssh server is enabled on the other peer" +
			"\nYou can verify the connection by running:\n\n" +
			" netbird status\n\n")
		return err
	}
	go func() {
		<-ctx.Done()
		err = c.Close()
		if err != nil {
			return
		}
	}()

	err = c.OpenTerminal()
	if err != nil {
		return err
	}

	return nil
}

func init() {
	sshCmd.PersistentFlags().IntVarP(&port, "port", "p", nbssh.DefaultSSHPort, "Sets remote SSH port. Defaults to "+fmt.Sprint(nbssh.DefaultSSHPort))
}
