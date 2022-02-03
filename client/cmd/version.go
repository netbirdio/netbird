package cmd

import (
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/client/system"
)

var (
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "prints wiretrustee version",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(system.WiretrusteeVersion())
		},
	}
)
