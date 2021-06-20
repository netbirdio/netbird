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

func newSVCConfig() *service.Config {
	return &service.Config{
		Name:        "wiretrustee",
		DisplayName: "wiretrustee",
		Description: "This is an example Go service.",
	}
}

func newSVC(prg *program, conf *service.Config) (service.Service, error) {
	s, err := service.New(prg, conf)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	logger, err = s.Logger(nil)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return s, nil
}

var (
	serviceCmd = &cobra.Command{
		Use:   "service",
		Short: "manages wiretrustee service",
		//Run: func(cmd *cobra.Command, args []string) {
		//},
	}
)

func init() {
}
