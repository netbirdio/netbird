package cmd

import (
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/certproof"
)

var postureCmd = &cobra.Command{
	Use:    "posture",
	Short:  "Posture helpers invoked by the NetBird daemon",
	Hidden: true,
}

var postureCertProofCmd = &cobra.Command{
	Use:   "cert-proof",
	Short: "Answer certificate posture challenges from the calling user's keychain",
	Long: "Reads a certificate challenge set as JSON on stdin and writes the proofs as JSON on stdout.\n" +
		"The daemon launches this in the console user's desktop session, because a login keychain\n" +
		"cannot be reached from a root daemon. Not intended to be run by hand.",
	Hidden:       true,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Proofs travel on stdout, so every log line has to go elsewhere.
		log.SetOutput(cmd.ErrOrStderr())
		return certproof.RunHelper(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout())
	},
}
