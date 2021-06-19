package cmd

import (
	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type program struct {
	cmd  *cobra.Command
	args []string
}

var logger service.Logger

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

			svcConfig := newSVCConfig()

			prg := &program{
				cmd:  cmd,
				args: args,
			}
			s, err := service.New(prg, svcConfig)
			if err != nil {
				log.Fatal(err)
			}
			logger, err = s.Logger(nil)
			if err != nil {
				log.Fatal(err)
			}

			err = s.Run()
			if err != nil {
				logger.Error(err) //nolint
			}
		},
	}
)

func init() {
}
