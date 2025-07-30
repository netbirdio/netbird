//go:build !ios && !android

package cmd

import (
	"context"
	"fmt"
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
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/util"
)

func (p *program) Start(svc service.Service) error {
	// Start should not block. Do the actual work async.
	log.Info("starting Netbird service") //nolint

	// Collect static system and platform information
	system.UpdateStaticInfo()

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
		return fmt.Errorf("listen daemon interface: %w", err)
	}
	go func() {
		defer listen.Close()

		if split[0] == "unix" {
			if err := os.Chmod(split[1], 0666); err != nil {
				log.Errorf("failed setting daemon permissions: %v", split[1])
				return
			}
		}

		serverInstance := server.New(p.ctx, util.FindFirstLogPath(logFiles), profilesDisabled)
		if err := serverInstance.Start(); err != nil {
			log.Fatalf("failed to start daemon: %v", err)
		}
		proto.RegisterDaemonServiceServer(p.serv, serverInstance)

		p.serverInstanceMu.Lock()
		p.serverInstance = serverInstance
		p.serverInstanceMu.Unlock()

		log.Printf("started daemon server: %v", split[1])
		if err := p.serv.Serve(listen); err != nil {
			log.Errorf("failed to serve daemon requests: %v", err)
		}
	}()
	return nil
}

func (p *program) Stop(srv service.Service) error {
	p.serverInstanceMu.Lock()
	if p.serverInstance != nil {
		in := new(proto.DownRequest)
		_, err := p.serverInstance.Down(p.ctx, in)
		if err != nil {
			log.Errorf("failed to stop daemon: %v", err)
		}
	}
	p.serverInstanceMu.Unlock()

	p.cancel()

	if p.serv != nil {
		p.serv.Stop()
	}

	time.Sleep(time.Second * 2)
	log.Info("stopped Netbird service") //nolint
	return nil
}

// Common setup for service control commands
func setupServiceControlCommand(cmd *cobra.Command, ctx context.Context, cancel context.CancelFunc) (service.Service, error) {
	SetFlagsFromEnvVars(rootCmd)
	SetFlagsFromEnvVars(serviceCmd)

	cmd.SetOut(cmd.OutOrStdout())

	if err := handleRebrand(cmd); err != nil {
		return nil, err
	}

	if err := util.InitLog(logLevel, logFiles...); err != nil {
		return nil, fmt.Errorf("init log: %w", err)
	}

	cfg, err := newSVCConfig()
	if err != nil {
		return nil, fmt.Errorf("create service config: %w", err)
	}

	s, err := newSVC(newProgram(ctx, cancel), cfg)
	if err != nil {
		return nil, err
	}

	return s, nil
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "runs Netbird as service",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(cmd.Context())

		SetupCloseHandler(ctx, cancel)
		SetupDebugHandler(ctx, nil, nil, nil, util.FindFirstLogPath(logFiles))

		s, err := setupServiceControlCommand(cmd, ctx, cancel)
		if err != nil {
			return err
		}

		return s.Run()
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "starts Netbird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(cmd.Context())
		s, err := setupServiceControlCommand(cmd, ctx, cancel)
		if err != nil {
			return err
		}

		if err := s.Start(); err != nil {
			return fmt.Errorf("start service: %w", err)
		}
		cmd.Println("Netbird service has been started")
		return nil
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stops Netbird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(cmd.Context())
		s, err := setupServiceControlCommand(cmd, ctx, cancel)
		if err != nil {
			return err
		}

		if err := s.Stop(); err != nil {
			return fmt.Errorf("stop service: %w", err)
		}
		cmd.Println("Netbird service has been stopped")
		return nil
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "restarts Netbird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(cmd.Context())
		s, err := setupServiceControlCommand(cmd, ctx, cancel)
		if err != nil {
			return err
		}

		if err := s.Restart(); err != nil {
			return fmt.Errorf("restart service: %w", err)
		}
		cmd.Println("Netbird service has been restarted")
		return nil
	},
}

var svcStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "shows Netbird service status",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(cmd.Context())
		s, err := setupServiceControlCommand(cmd, ctx, cancel)
		if err != nil {
			return err
		}

		status, err := s.Status()
		if err != nil {
			return fmt.Errorf("get service status: %w", err)
		}

		var statusText string
		switch status {
		case service.StatusRunning:
			statusText = "Running"
		case service.StatusStopped:
			statusText = "Stopped"
		case service.StatusUnknown:
			statusText = "Unknown"
		default:
			statusText = fmt.Sprintf("Unknown (%d)", status)
		}

		cmd.Printf("Netbird service status: %s\n", statusText)
		return nil
	},
}
