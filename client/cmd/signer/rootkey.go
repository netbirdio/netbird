package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/updatemanager/reposign"
)

var (
	privKeyFile    string
	pubKeyFile     string
	rootExpiration time.Duration
)

var createRootKeyCmd = &cobra.Command{
	Use:          "create-root-key",
	Short:        "Create a new root key pair",
	Long:         `Create a new root key pair and specify an expiration time for it.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate expiration
		if rootExpiration <= 0 {
			return fmt.Errorf("--expiration must be a positive duration (e.g., 720h, 365d, 8760h)")
		}

		// Run main logic
		if err := handleGenerateRootKey(cmd, privKeyFile, pubKeyFile, rootExpiration); err != nil {
			return fmt.Errorf("failed to generate root key: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(createRootKeyCmd)
	createRootKeyCmd.Flags().StringVar(&privKeyFile, "priv-key-file", "", "Path to output private key file")
	createRootKeyCmd.Flags().StringVar(&pubKeyFile, "pub-key-file", "", "Path to output public key file")
	createRootKeyCmd.Flags().DurationVar(&rootExpiration, "expiration", 0, "Expiration time for the root key (e.g., 720h,)")

	if err := createRootKeyCmd.MarkFlagRequired("priv-key-file"); err != nil {
		panic(err)
	}
	if err := createRootKeyCmd.MarkFlagRequired("pub-key-file"); err != nil {
		panic(err)
	}
	if err := createRootKeyCmd.MarkFlagRequired("expiration"); err != nil {
		panic(err)
	}
}

func handleGenerateRootKey(cmd *cobra.Command, privKeyFile, pubKeyFile string, expiration time.Duration) error {
	rk, privPEM, pubPEM, err := reposign.GenerateRootKey(expiration)
	if err != nil {
		return fmt.Errorf("generate root key: %w", err)
	}

	// Write private key
	if err := os.WriteFile(privKeyFile, privPEM, 0o600); err != nil {
		return fmt.Errorf("write private key file (%s): %w", privKeyFile, err)
	}

	// Write public key
	if err := os.WriteFile(pubKeyFile, pubPEM, 0o600); err != nil {
		return fmt.Errorf("write public key file (%s): %w", pubKeyFile, err)
	}

	cmd.Printf("%s\n\n", rk.String())
	cmd.Printf("✅ Root key pair generated successfully.\n")
	return nil
}
