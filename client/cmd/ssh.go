package cmd

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"syscall"
)

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "connect to a remote SSH server",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		cmd.SetOut(cmd.OutOrStdout())

		err := util.InitLog(logLevel, "console")
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		ctx := internal.CtxInitState(cmd.Context())

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			return fmt.Errorf("failed to connect to daemon error: %v\n"+
				"If the daemon is not running please run: "+
				"\nnetbird service install \nnetbird service start\n", err)
		}

		defer func() {
			err := conn.Close()
			if err != nil {
				log.Warnf("failed closing dameon gRPC client connection %v", err)
				return
			}
		}()
		client := proto.NewDaemonServiceClient(conn)

		status, err := client.Status(ctx, &proto.StatusRequest{})
		if err != nil {
			return fmt.Errorf("unable to get daemon status: %v", err)
		}

		if status.Status != string(internal.StatusConnected) {
			// todo maybe automatically start it?
			cmd.Printf("You are disconnected from the NetBird network. Please run the UP command first to connect: \n\n" +
				" netbird up \n\n")
			return nil
		}

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		sshctx, cancel := context.WithCancel(ctx)

		go func() {
			if err := runSSH(sshctx); err != nil {
				log.Print(err)
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

func runSSH(ctx context.Context) error {
	c, err := nbssh.DialWithKeyFile("128.199.61.79:43767", "root", "/home/braginini/.ssh/id_rsa")
	if err != nil {
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
