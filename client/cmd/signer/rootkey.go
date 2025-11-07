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

var generateRootKeyCmd = &cobra.Command{
	Use:   "generate-root-key",
	Short: "Generate a new root key pair",
	Long: `Generate a new root key pair and specify an expiration time for it.

Example:
  mycli generate-root-key --priv-key-file root.priv --pub-key-file root.pub --expiration 8760h`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate expiration
		if rootExpiration <= 0 {
			return fmt.Errorf("--expiration must be a positive duration (e.g., 720h, 365d, 8760h)")
		}

		// Run main logic
		if err := handleGenerateRootKey(privKeyFile, pubKeyFile, rootExpiration); err != nil {
			return fmt.Errorf("failed to generate root key: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(generateRootKeyCmd)
	generateRootKeyCmd.Flags().StringVar(&privKeyFile, "priv-key-file", "", "Path to output private key file")
	generateRootKeyCmd.Flags().StringVar(&pubKeyFile, "pub-key-file", "", "Path to output public key file")
	generateRootKeyCmd.Flags().DurationVar(&rootExpiration, "expiration", 0, "Expiration time for the root key (e.g., 720h,)")

	if err := generateRootKeyCmd.MarkFlagRequired("priv-key-file"); err != nil {
		panic(err)
	}
	if err := generateRootKeyCmd.MarkFlagRequired("pub-key-file"); err != nil {
		panic(err)
	}
	if err := generateRootKeyCmd.MarkFlagRequired("expiration"); err != nil {
		panic(err)
	}
}

func handleGenerateRootKey(privKeyFile, pubKeyFile string, expiration time.Duration) error {
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

	fmt.Printf("%s\n\n", rk.String())
	fmt.Printf("✅ Root key pair generated successfully.\n")
	return nil
}
