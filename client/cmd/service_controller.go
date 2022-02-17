package cmd

import (
	"net"
	"strings"
	"time"

	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/client/internal"
	"github.com/wiretrustee/wiretrustee/client/proto"
	"github.com/wiretrustee/wiretrustee/client/server"
	"github.com/wiretrustee/wiretrustee/util"
	"google.golang.org/grpc"
)

func (p *program) Start(service.Service) error {
	// Start should not block. Do the actual work async.
	log.Info("starting service") //nolint
	go func() {
		// if configuration exists, we just start connections.
		config, err := internal.ReadConfig(managementURL, configPath)
		if err != nil {
			log.Errorf("no config file, skip connection stage: %v", err)
			return
		}
		if err := internal.RunClient(config, stopCh, cleanupCh); err != nil {
			log.Errorf("init connections: %v", err)
		}
	}()
	go func() {
		// in any case, even if configuration does not exists we run daemon to serve CLI gRPC API.
		p.daemonSrv = grpc.NewServer()

		split := strings.SplitN(daemonAddr, ":", 2)
		switch split[0] {
		case "tcp", "unix":
		default:
			log.Errorf("unsupported daemon address protocol: %v", split[0])
			return
		}

		lis, err := net.Listen(split[0], split[1])
		if err != nil {
			log.Fatalf("failed to listen daemon interface: %v", err)
		}

		serverInstance := server.New(managementURL, configPath, stopCh, cleanupCh)
		proto.RegisterDaemonServiceServer(p.daemonSrv, serverInstance)

		log.Printf("started daemon server: %v", daemonAddr)
		if err := p.daemonSrv.Serve(lis); err != nil {
			log.Fatalf("failed to serve daemon requests: %v", err)
		}
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	go func() {
		stopCh <- 1
	}()

	p.daemonSrv.GracefulStop()

	select {
	case <-cleanupCh:
	case <-time.After(time.Second * 10):
		log.Warnf("failed waiting for service cleanup, terminating")
	}
	log.Info("stopped Wiretrustee service") //nolint
	return nil
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "runs wiretrustee as service",
	Run: func(cmd *cobra.Command, args []string) {
		SetFlagsFromEnvVars()

		err := util.InitLog(logLevel, logFile)
		if err != nil {
			log.Errorf("failed initializing log %v", err)
			return
		}

		SetupCloseHandler()

		prg := &program{
			cmd:  cmd,
			args: args,
		}

		s, err := newSVC(prg, newSVCConfig())
		if err != nil {
			cmd.PrintErrln(err)
			return
		}
		err = s.Run()
		if err != nil {
			cmd.PrintErrln(err)
			return
		}
		cmd.Printf("Wiretrustee service is running")
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "starts wiretrustee service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		err := util.InitLog(logLevel, logFile)
		if err != nil {
			log.Errorf("failed initializing log %v", err)
			return err
		}
		s, err := newSVC(&program{}, newSVCConfig())
		if err != nil {
			cmd.PrintErrln(err)
			return err
		}
		err = s.Start()
		if err != nil {
			cmd.PrintErrln(err)
			return err
		}
		cmd.Println("Wiretrustee service has been started")
		return nil
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stops wiretrustee service",
	Run: func(cmd *cobra.Command, args []string) {
		SetFlagsFromEnvVars()

		err := util.InitLog(logLevel, logFile)
		if err != nil {
			log.Errorf("failed initializing log %v", err)
		}
		s, err := newSVC(&program{}, newSVCConfig())
		if err != nil {
			cmd.PrintErrln(err)
			return
		}
		err = s.Stop()
		if err != nil {
			cmd.PrintErrln(err)
			return
		}
		cmd.Println("Wiretrustee service has been stopped")
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "restarts wiretrustee service",
	Run: func(cmd *cobra.Command, args []string) {
		SetFlagsFromEnvVars()

		err := util.InitLog(logLevel, logFile)
		if err != nil {
			log.Errorf("failed initializing log %v", err)
		}
		s, err := newSVC(&program{}, newSVCConfig())
		if err != nil {
			cmd.PrintErrln(err)
			return
		}
		err = s.Restart()
		if err != nil {
			cmd.PrintErrln(err)
			return
		}
		cmd.Println("Wiretrustee service has been restarted")
	},
}
