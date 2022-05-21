package cmd

import (
	"github.com/netbirdio/netbird/client/system"
	"github.com/spf13/cobra"
)

var (
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "prints Netbird version",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(system.WiretrusteeVersion())
		},
	}
)
