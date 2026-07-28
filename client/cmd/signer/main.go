package main

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "signer",
	Short: "A CLI tool for managing cryptographic keys and artifacts",
	Long: `signer is a command-line tool that helps you manage
root keys, artifact keys, and revocation lists securely.`,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		rootCmd.Println(err)
		os.Exit(1)
	}
}
