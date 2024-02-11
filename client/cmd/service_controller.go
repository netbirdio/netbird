package cmd

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/client/internal"
	"net"
	"os"
	"strings"
	"time"

	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/server"
	"github.com/netbirdio/netbird/util"
)

func (p *program) Start(svc service.Service) error {
	// Start should not block. Do the actual work async.
	log.Info("starting Netbird service") //nolint
	// in any case, even if configuration does not exists we run daemon to serve CLI gRPC API.
	p.serv = grpc.NewServer()

	split := strings.Split(daemonAddr, "://")
	switch split[0] {
	case "unix":
		// cleanup failed close
		stat, err := os.Stat(split[1])
		if err == nil && !stat.IsDir() {
			if err := os.Remove(split[1]); err != nil {
				log.Debugf("remove socket file: %v", err)
			}
		}
	case "tcp":
	default:
		return fmt.Errorf("unsupported daemon address protocol: %v", split[0])
	}

	listen, err := net.Listen(split[0], split[1])
	if err != nil {
		return fmt.Errorf("failed to listen daemon interface: %w", err)
	}
	go func() {
		defer listen.Close()

		if split[0] == "unix" {
			err = os.Chmod(split[1], 0666)
			if err != nil {
				log.Errorf("failed setting daemon permissions: %v", split[1])
				return
			}
		}

		serverInstance := server.New(p.ctx, configPath, logFile)
		if err := serverInstance.Start(); err != nil {
			log.Fatalf("failed to start daemon: %v", err)
		}
		proto.RegisterDaemonServiceServer(p.serv, serverInstance)

		log.Printf("started daemon server: %v", split[1])
		if err := p.serv.Serve(listen); err != nil {
			log.Errorf("failed to serve daemon requests: %v", err)
		}
	}()
	return nil
}

func (p *program) Stop(srv service.Service) error {
	p.cancel()

	if p.serv != nil {
		p.serv.Stop()
	}

	time.Sleep(time.Second * 2)
	log.Info("stopped Netbird service") //nolint
	return nil
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "runs Netbird as service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)

		cmd.SetOut(cmd.OutOrStdout())

		err := handleRebrand(cmd)
		if err != nil {
			return err
		}

		err = util.InitLog(logLevel, logFile)
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		ctx, cancel := context.WithCancel(cmd.Context())
		SetupCloseHandler(ctx, cancel)

		s, err := newSVC(newProgram(ctx, cancel), newSVCConfig())
		if err != nil {
			return err
		}
		err = s.Run()
		if err != nil {
			return err
		}
		return nil
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "starts Netbird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)

		cmd.SetOut(cmd.OutOrStdout())

		err := handleRebrand(cmd)
		if err != nil {
			return err
		}

		err = util.InitLog(logLevel, logFile)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithCancel(cmd.Context())

		s, err := newSVC(newProgram(ctx, cancel), newSVCConfig())
		if err != nil {
			cmd.PrintErrln(err)
			return err
		}
		err = s.Start()
		if err != nil {
			cmd.PrintErrln(err)
			return err
		}
		cmd.Println("Netbird service has been started")
		return nil
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stops Netbird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)

		cmd.SetOut(cmd.OutOrStdout())

		err := handleRebrand(cmd)
		if err != nil {
			return err
		}

		err = util.InitLog(logLevel, logFile)
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		ctx, cancel := context.WithCancel(cmd.Context())

		s, err := newSVC(newProgram(ctx, cancel), newSVCConfig())
		if err != nil {
			return err
		}
		err = s.Stop()
		if err != nil {
			return err
		}
		cmd.Println("Netbird service has been stopped")
		return nil
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "restarts Netbird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)

		cmd.SetOut(cmd.OutOrStdout())

		err := handleRebrand(cmd)
		if err != nil {
			return err
		}

		err = util.InitLog(logLevel, logFile)
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		ctx, cancel := context.WithCancel(cmd.Context())

		s, err := newSVC(newProgram(ctx, cancel), newSVCConfig())
		if err != nil {
			return err
		}
		err = s.Restart()
		if err != nil {
			return err
		}
		cmd.Println("Netbird service has been restarted")
		return nil
	},
}

func toggleAutostart(cmd *cobra.Command, args []string, toggle bool) error {
	config, err := internal.ReadConfig(configPath)
	if err != nil {
		return err
	}

	if config.Autostart == toggle {
		if toggle {
			cmd.Println("Automatically connecting is already enabled")
			return nil
		}

		cmd.Println("Automatically connecting is already disabled")
		return nil
	}

	updatedConfig, err := internal.UpdateConfig(internal.ConfigInput{Autostart: toggle})
	if err != nil {
		return err
	}

	err = internal.WriteOutConfig(configPath, updatedConfig)
	if err != nil {
		return err
	}

	if toggle {
		cmd.Println("Automatically connecting has been enabled")
		return nil
	}

	cmd.Println("Automatically connecting has been disabled")
	return nil
}

var disableCmd = &cobra.Command{
	Use:   "disable",
	Short: "disable automatically connecting when the Netbird service starts",
	RunE: func(cmd *cobra.Command, args []string) error {
		return toggleAutostart(cmd, args, false)
	},
}

var enableCmd = &cobra.Command{
	Use:   "enable",
	Short: "enable automatically connecting when the Netbird service starts",
	RunE: func(cmd *cobra.Command, args []string) error {
		return toggleAutostart(cmd, args, true)
	},
}
