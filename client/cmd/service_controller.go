package cmd

import (
	"net"
	"os"
	"strings"
	"time"

	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/client/proto"
	"github.com/wiretrustee/wiretrustee/client/server"
	"github.com/wiretrustee/wiretrustee/util"
	"google.golang.org/grpc"
)

func (p *program) Start(svc service.Service) error {
	// Start should not block. Do the actual work async.
	log.Info("starting service") //nolint
	go func() {
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
			log.Errorf("unsupported daemon address protocol: %v", split[0])
			return
		}

		listen, err := net.Listen(split[0], split[1])
		if err != nil {
			log.Fatalf("failed to listen daemon interface: %v", err)
		}
		defer listen.Close()

		serverInstance := server.New(p.ctx, managementURL, configPath, stopCh, cleanupCh)
		if err := serverInstance.Start(); err != nil {
			log.Fatalf("failed start daemon: %v", err)
		}
		proto.RegisterDaemonServiceServer(p.serv, serverInstance)

		log.Printf("started daemon server: %v", split[1])
		if err := p.serv.Serve(listen); err != nil {
			log.Errorf("failed to serve daemon requests: %v", err)
		}
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	go func() {
		stopCh <- 1
	}()

	// stop CLI daemon service
	if p.serv != nil {
		p.serv.GracefulStop()
	}

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

		s, err := newSVC(newProgram(cmd, args), newSVCConfig())
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
		s, err := newSVC(newProgram(cmd, args), newSVCConfig())
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
		s, err := newSVC(newProgram(cmd, args), newSVCConfig())
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
		s, err := newSVC(newProgram(cmd, args), newSVCConfig())
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
