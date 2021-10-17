package cmd

import "github.com/spf13/cobra"

var (
	Version    string
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "prints wiretrustee version",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(Version)
		},
	}
)
