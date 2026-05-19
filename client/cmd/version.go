package cmd

import (
	"github.com/spf13/cobra"

	nbstatus "github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/version"
)

var (
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the NetBird's client application version",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SetOut(cmd.OutOrStdout())
			v := version.NetbirdVersion()

			switch {
			case jsonFlag:
				out := &nbstatus.VersionOutput{Version: v}
				s, err := out.JSON()
				if err != nil {
					return err
				}
				cmd.Println(s)
			case yamlFlag:
				out := &nbstatus.VersionOutput{Version: v}
				s, err := out.YAML()
				if err != nil {
					return err
				}
				cmd.Print(s)
			default:
				cmd.Println(v)
			}
			return nil
		},
	}
)

func init() {
	versionCmd.PersistentFlags().BoolVarP(&jsonFlag, "json", "j", false, "display command result in json format")
	versionCmd.PersistentFlags().BoolVarP(&yamlFlag, "yaml", "y", false, "display command result in yaml format")
	versionCmd.MarkFlagsMutuallyExclusive("json", "yaml")
}
