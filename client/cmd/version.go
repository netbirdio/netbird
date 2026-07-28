package cmd

import (
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/version"
)

var (
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the NetBird's client application version",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.SetOut(cmd.OutOrStdout())
			out := version.NetbirdVersion()
			if version.IsDevelopmentVersion(out) {
				if commit := version.NetbirdCommit(); commit != "" {
					out += "-" + commit
				}
			}
			cmd.Println(out)
		},
	}
)
