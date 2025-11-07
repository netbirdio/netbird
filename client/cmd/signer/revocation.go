package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/updatemanager/reposign"
)

var (
	keyID              string
	revocationListFile string
	privateRootKeyFile string
)

var createRevocationListCmd = &cobra.Command{
	Use:   "create-revocation-list",
	Short: "Create a new revocation list signed by the private root key",
	RunE: func(cmd *cobra.Command, args []string) error {
		return handleCreateRevocationList(revocationListFile, privateRootKeyFile)
	},
}

var extendRevocationListCmd = &cobra.Command{
	Use:   "extend-revocation-list",
	Short: "Extend an existing revocation list with a given key ID",
	RunE: func(cmd *cobra.Command, args []string) error {
		return handleExtendRevocationList(keyID, revocationListFile, privateRootKeyFile)
	},
}

func init() {
	rootCmd.AddCommand(createRevocationListCmd)
	rootCmd.AddCommand(extendRevocationListCmd)

	createRevocationListCmd.Flags().StringVar(&revocationListFile, "revocation-list-file", "", "Path to the existing revocation list file")
	createRevocationListCmd.Flags().StringVar(&privateRootKeyFile, "private-root-key", "", "Path to the private root key PEM file")
	if err := createRevocationListCmd.MarkFlagRequired("revocation-list-file"); err != nil {
		panic(err)
	}
	if err := createRevocationListCmd.MarkFlagRequired("private-root-key"); err != nil {
		panic(err)
	}

	extendRevocationListCmd.Flags().StringVar(&keyID, "key-id", "", "ID of the key to extend the revocation list for")
	extendRevocationListCmd.Flags().StringVar(&revocationListFile, "revocation-list-file", "", "Path to the existing revocation list file")
	extendRevocationListCmd.Flags().StringVar(&privateRootKeyFile, "private-root-key", "", "Path to the private root key PEM file")
	if err := extendRevocationListCmd.MarkFlagRequired("key-id"); err != nil {
		panic(err)
	}
	if err := extendRevocationListCmd.MarkFlagRequired("revocation-list-file"); err != nil {
		panic(err)
	}
	if err := extendRevocationListCmd.MarkFlagRequired("private-root-key"); err != nil {
		panic(err)
	}
}

func handleCreateRevocationList(revocationListFile string, privateRootKeyFile string) error {
	privKeyPEM, err := os.ReadFile(privateRootKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read private root key file: %w", err)
	}

	privateRootKey, err := reposign.ParseRootKey(privKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private root key: %w", err)
	}

	rlBytes, sigBytes, err := reposign.CreateRevocationList(*privateRootKey)
	if err != nil {
		return fmt.Errorf("failed to create revocation list: %w", err)
	}

	if err := writeOutputFiles(revocationListFile, revocationListFile+".sig", rlBytes, sigBytes); err != nil {
		return fmt.Errorf("failed to write output files: %w", err)
	}

	fmt.Println("✅ Revocation list created successfully")
	return nil
}

func handleExtendRevocationList(keyID, revocationListFile, privateRootKeyFile string) error {
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

	newRLBytes, sigBytes, err := reposign.ExtendRevocationList(*privateRootKey, *rl, kid)
	if err != nil {
		return fmt.Errorf("failed to extend revocation list: %w", err)
	}

	if err := writeOutputFiles(revocationListFile, revocationListFile+".sig", newRLBytes, sigBytes); err != nil {
		return fmt.Errorf("failed to write output files: %w", err)
	}

	fmt.Println("✅ Revocation list extended successfully")
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
