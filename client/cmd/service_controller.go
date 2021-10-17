package cmd

import (
	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/util"
)

func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work async.
	log.Info("starting service") //nolint
	go func() {
		err := runClient()
		if err != nil {
			return
		}

	}()
	return nil
}

func (p *program) Stop(s service.Service) error {
	return nil
}

var (
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "runs wiretrustee as service",
		Run: func(cmd *cobra.Command, args []string) {
			err := util.InitLog(logLevel, logFile)
			if err != nil {
				log.Errorf("failed initializing log %v", err)
				return
			}
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
)

var (
	startCmd = &cobra.Command{
		Use:   "start",
		Short: "starts wiretrustee service",
		RunE: func(cmd *cobra.Command, args []string) error {
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
)

var (
	stopCmd = &cobra.Command{
		Use:   "stop",
		Short: "stops wiretrustee service",
		Run: func(cmd *cobra.Command, args []string) {
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
)

var (
	restartCmd = &cobra.Command{
		Use:   "restart",
		Short: "restarts wiretrustee service",
		Run: func(cmd *cobra.Command, args []string) {
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
)

func init() {
}
