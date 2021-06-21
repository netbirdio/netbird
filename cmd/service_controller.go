package cmd

import (
	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work async.
	logger.Info("Starting service") //nolint
	go upCmd.Run(p.cmd, p.args)
	return nil
}

func (p *program) Stop(s service.Service) error {
	stopUP <- 1
	return nil
}

var (
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "runs wiretrustee as service",
		Run: func(cmd *cobra.Command, args []string) {

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
		Run: func(cmd *cobra.Command, args []string) {

			s, err := newSVC(&program{}, newSVCConfig())
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			err = s.Start()
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			cmd.Printf("Wiretrustee service has been started")
		},
	}
)

var (
	stopCmd = &cobra.Command{
		Use:   "stop",
		Short: "stops wiretrustee service",
		Run: func(cmd *cobra.Command, args []string) {

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
			cmd.Printf("Wiretrustee service has been stopped")
		},
	}
)

var (
	restartCmd = &cobra.Command{
		Use:   "restart",
		Short: "restarts wiretrustee service",
		Run: func(cmd *cobra.Command, args []string) {

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
			cmd.Printf("Wiretrustee service has been restarted")
		},
	}
)

func init() {
}
