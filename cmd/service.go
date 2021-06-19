package cmd

import (
	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

func newSVCConfig() *service.Config {
	return &service.Config{
		Name:        "wiretrustee",
		DisplayName: "wiretrustee",
		Description: "This is an example Go service.",
	}
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
