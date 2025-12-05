package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/updatemanager/reposign"
)

const (
	defaultRevocationListExpiration = 365 * 24 * time.Hour // 1 year
)

var (
	keyID              string
	revocationListFile string
	privateRootKeyFile string
	publicRootKeyFile  string
	signatureFile      string
	expirationDuration time.Duration
)

var createRevocationListCmd = &cobra.Command{
	Use:          "create-revocation-list",
	Short:        "Create a new revocation list signed by the private root key",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return handleCreateRevocationList(cmd, revocationListFile, privateRootKeyFile)
	},
}

var extendRevocationListCmd = &cobra.Command{
	Use:          "extend-revocation-list",
	Short:        "Extend an existing revocation list with a given key ID",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return handleExtendRevocationList(cmd, keyID, revocationListFile, privateRootKeyFile)
	},
}

var verifyRevocationListCmd = &cobra.Command{
	Use:          "verify-revocation-list",
	Short:        "Verify a revocation list signature using the public root key",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return handleVerifyRevocationList(cmd, revocationListFile, signatureFile, publicRootKeyFile)
	},
}

func init() {
	rootCmd.AddCommand(createRevocationListCmd)
	rootCmd.AddCommand(extendRevocationListCmd)
	rootCmd.AddCommand(verifyRevocationListCmd)

	createRevocationListCmd.Flags().StringVar(&revocationListFile, "revocation-list-file", "", "Path to the existing revocation list file")
	createRevocationListCmd.Flags().StringVar(&privateRootKeyFile, "private-root-key", "", "Path to the private root key PEM file")
	createRevocationListCmd.Flags().DurationVar(&expirationDuration, "expiration", defaultRevocationListExpiration, "Expiration duration for the revocation list (e.g., 8760h for 1 year)")
	if err := createRevocationListCmd.MarkFlagRequired("revocation-list-file"); err != nil {
		panic(err)
	}
	if err := createRevocationListCmd.MarkFlagRequired("private-root-key"); err != nil {
		panic(err)
	}

	extendRevocationListCmd.Flags().StringVar(&keyID, "key-id", "", "ID of the key to extend the revocation list for")
	extendRevocationListCmd.Flags().StringVar(&revocationListFile, "revocation-list-file", "", "Path to the existing revocation list file")
	extendRevocationListCmd.Flags().StringVar(&privateRootKeyFile, "private-root-key", "", "Path to the private root key PEM file")
	extendRevocationListCmd.Flags().DurationVar(&expirationDuration, "expiration", defaultRevocationListExpiration, "Expiration duration for the revocation list (e.g., 8760h for 1 year)")
	if err := extendRevocationListCmd.MarkFlagRequired("key-id"); err != nil {
		panic(err)
	}
	if err := extendRevocationListCmd.MarkFlagRequired("revocation-list-file"); err != nil {
		panic(err)
	}
	if err := extendRevocationListCmd.MarkFlagRequired("private-root-key"); err != nil {
		panic(err)
	}

	verifyRevocationListCmd.Flags().StringVar(&revocationListFile, "revocation-list-file", "", "Path to the revocation list file")
	verifyRevocationListCmd.Flags().StringVar(&signatureFile, "signature-file", "", "Path to the signature file")
	verifyRevocationListCmd.Flags().StringVar(&publicRootKeyFile, "public-root-key", "", "Path to the public root key PEM file")
	if err := verifyRevocationListCmd.MarkFlagRequired("revocation-list-file"); err != nil {
		panic(err)
	}
	if err := verifyRevocationListCmd.MarkFlagRequired("signature-file"); err != nil {
		panic(err)
	}
	if err := verifyRevocationListCmd.MarkFlagRequired("public-root-key"); err != nil {
		panic(err)
	}
}

func handleCreateRevocationList(cmd *cobra.Command, revocationListFile string, privateRootKeyFile string) error {
	privKeyPEM, err := os.ReadFile(privateRootKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read private root key file: %w", err)
	}

	privateRootKey, err := reposign.ParseRootKey(privKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private root key: %w", err)
	}

	rlBytes, sigBytes, err := reposign.CreateRevocationList(*privateRootKey, expirationDuration)
	if err != nil {
		return fmt.Errorf("failed to create revocation list: %w", err)
	}

	if err := writeOutputFiles(revocationListFile, revocationListFile+".sig", rlBytes, sigBytes); err != nil {
		return fmt.Errorf("failed to write output files: %w", err)
	}

	cmd.Println("✅ Revocation list created successfully")
	return nil
}

func handleExtendRevocationList(cmd *cobra.Command, keyID, revocationListFile, privateRootKeyFile string) error {
	privKeyPEM, err := os.ReadFile(privateRootKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read private root key file: %w", err)
	}

	privateRootKey, err := reposign.ParseRootKey(privKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private root key: %w", err)
	}

	rlBytes, err := os.ReadFile(revocationListFile)
	if err != nil {
		return fmt.Errorf("failed to read revocation list file: %w", err)
	}

	rl, err := reposign.ParseRevocationList(rlBytes)
	if err != nil {
		return fmt.Errorf("failed to parse revocation list: %w", err)
	}

	kid, err := reposign.ParseKeyID(keyID)
	if err != nil {
		return fmt.Errorf("invalid key ID: %w", err)
	}

	newRLBytes, sigBytes, err := reposign.ExtendRevocationList(*privateRootKey, *rl, kid, expirationDuration)
	if err != nil {
		return fmt.Errorf("failed to extend revocation list: %w", err)
	}

	if err := writeOutputFiles(revocationListFile, revocationListFile+".sig", newRLBytes, sigBytes); err != nil {
		return fmt.Errorf("failed to write output files: %w", err)
	}

	cmd.Println("✅ Revocation list extended successfully")
	return nil
}

func handleVerifyRevocationList(cmd *cobra.Command, revocationListFile, signatureFile, publicRootKeyFile string) error {
	// Read revocation list file
	rlBytes, err := os.ReadFile(revocationListFile)
	if err != nil {
		return fmt.Errorf("failed to read revocation list file: %w", err)
	}

	// Read signature file
	sigBytes, err := os.ReadFile(signatureFile)
	if err != nil {
		return fmt.Errorf("failed to read signature file: %w", err)
	}

	// Read public root key file
	pubKeyPEM, err := os.ReadFile(publicRootKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read public root key file: %w", err)
	}

	// Parse public root key
	publicKey, err := reposign.ParseRootPublicKey(pubKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse public root key: %w", err)
	}

	// Parse signature
	signature, err := reposign.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	// Validate revocation list
	rl, err := reposign.ValidateRevocationList([]reposign.PublicKey{publicKey}, rlBytes, *signature)
	if err != nil {
		return fmt.Errorf("failed to validate revocation list: %w", err)
	}

	// Display results
	cmd.Println("✅ Revocation list signature is valid")
	cmd.Printf("Last Updated: %s\n", rl.LastUpdated.Format(time.RFC3339))
	cmd.Printf("Expires At: %s\n", rl.ExpiresAt.Format(time.RFC3339))
	cmd.Printf("Number of revoked keys: %d\n", len(rl.Revoked))

	if len(rl.Revoked) > 0 {
		cmd.Println("\nRevoked Keys:")
		for keyID, revokedTime := range rl.Revoked {
			cmd.Printf("  - %s (revoked at: %s)\n", keyID, revokedTime.Format(time.RFC3339))
		}
	}

	return nil
}

func writeOutputFiles(rlPath, sigPath string, rlBytes, sigBytes []byte) error {
	if err := os.WriteFile(rlPath, rlBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write revocation list file: %w", err)
	}
	if err := os.WriteFile(sigPath, sigBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write signature file: %w", err)
	}
	return nil
}
