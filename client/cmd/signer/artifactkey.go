package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/updatemanager/reposign"
)

var (
	bundlePubKeysRootPrivKeyFile string
	bundlePubKeysPubKeyFiles     []string
	bundlePubKeysFile            string

	createArtifactKeyRootPrivKeyFile string
	createArtifactKeyPrivKeyFile     string
	createArtifactKeyPubKeyFile      string
	createArtifactKeyExpiration      time.Duration
)

var createArtifactKeyCmd = &cobra.Command{
	Use:   "create-artifact-key",
	Short: "Create a new artifact signing key",
	Long: `Generate a new artifact signing key pair signed by the root private key.
The artifact key will be used to sign software artifacts/updates.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if createArtifactKeyExpiration <= 0 {
			return fmt.Errorf("--expiration must be a positive duration (e.g., 720h, 365d, 8760h)")
		}

		if err := handleCreateArtifactKey(cmd, createArtifactKeyRootPrivKeyFile, createArtifactKeyPrivKeyFile, createArtifactKeyPubKeyFile, createArtifactKeyExpiration); err != nil {
			return fmt.Errorf("failed to create artifact key: %w", err)
		}
		return nil
	},
}

var bundlePubKeysCmd = &cobra.Command{
	Use:   "bundle-pub-keys",
	Short: "Bundle multiple artifact public keys into a signed package",
	Long: `Bundle one or more artifact public keys into a signed package using the root private key.
This command is typically used to distribute or authorize a set of valid artifact signing keys.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(bundlePubKeysPubKeyFiles) == 0 {
			return fmt.Errorf("at least one --artifact-pub-key-file must be provided")
		}

		if err := handleBundlePubKeys(cmd, bundlePubKeysRootPrivKeyFile, bundlePubKeysPubKeyFiles, bundlePubKeysFile); err != nil {
			return fmt.Errorf("failed to bundle public keys: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(createArtifactKeyCmd)

	createArtifactKeyCmd.Flags().StringVar(&createArtifactKeyRootPrivKeyFile, "root-private-key-file", "", "Path to the root private key file used to sign the artifact key")
	createArtifactKeyCmd.Flags().StringVar(&createArtifactKeyPrivKeyFile, "artifact-priv-key-file", "", "Path where the artifact private key will be saved")
	createArtifactKeyCmd.Flags().StringVar(&createArtifactKeyPubKeyFile, "artifact-pub-key-file", "", "Path where the artifact public key will be saved")
	createArtifactKeyCmd.Flags().DurationVar(&createArtifactKeyExpiration, "expiration", 0, "Expiration duration for the artifact key (e.g., 720h, 365d, 8760h)")

	if err := createArtifactKeyCmd.MarkFlagRequired("root-private-key-file"); err != nil {
		panic(fmt.Errorf("mark root-private-key-file as required: %w", err))
	}
	if err := createArtifactKeyCmd.MarkFlagRequired("artifact-priv-key-file"); err != nil {
		panic(fmt.Errorf("mark artifact-priv-key-file as required: %w", err))
	}
	if err := createArtifactKeyCmd.MarkFlagRequired("artifact-pub-key-file"); err != nil {
		panic(fmt.Errorf("mark artifact-pub-key-file as required: %w", err))
	}
	if err := createArtifactKeyCmd.MarkFlagRequired("expiration"); err != nil {
		panic(fmt.Errorf("mark expiration as required: %w", err))
	}

	rootCmd.AddCommand(bundlePubKeysCmd)

	bundlePubKeysCmd.Flags().StringVar(&bundlePubKeysRootPrivKeyFile, "root-private-key-file", "", "Path to the root private key file used to sign the bundle")
	bundlePubKeysCmd.Flags().StringArrayVar(&bundlePubKeysPubKeyFiles, "artifact-pub-key-file", nil, "Path(s) to the artifact public key files to include in the bundle (can be repeated)")
	bundlePubKeysCmd.Flags().StringVar(&bundlePubKeysFile, "bundle-pub-key-file", "", "Path where the public keys will be saved")

	if err := bundlePubKeysCmd.MarkFlagRequired("root-private-key-file"); err != nil {
		panic(fmt.Errorf("mark root-private-key-file as required: %w", err))
	}
	if err := bundlePubKeysCmd.MarkFlagRequired("artifact-pub-key-file"); err != nil {
		panic(fmt.Errorf("mark artifact-pub-key-file as required: %w", err))
	}
	if err := bundlePubKeysCmd.MarkFlagRequired("bundle-pub-key-file"); err != nil {
		panic(fmt.Errorf("mark bundle-pub-key-file as required: %w", err))
	}
}

func handleCreateArtifactKey(cmd *cobra.Command, rootPrivKeyFile, artifactPrivKeyFile, artifactPubKeyFile string, expiration time.Duration) error {
	cmd.Println("Creating new artifact signing key...")

	privKeyPEM, err := os.ReadFile(rootPrivKeyFile)
	if err != nil {
		return fmt.Errorf("read root private key file: %w", err)
	}

	privateRootKey, err := reposign.ParseRootKey(privKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private root key: %w", err)
	}

	artifactKey, privPEM, pubPEM, signature, err := reposign.GenerateArtifactKey(privateRootKey, expiration)
	if err != nil {
		return fmt.Errorf("generate artifact key: %w", err)
	}

	if err := os.WriteFile(artifactPrivKeyFile, privPEM, 0o600); err != nil {
		return fmt.Errorf("write private key file (%s): %w", artifactPrivKeyFile, err)
	}

	if err := os.WriteFile(artifactPubKeyFile, pubPEM, 0o600); err != nil {
		return fmt.Errorf("write public key file (%s): %w", artifactPubKeyFile, err)
	}

	signatureFile := artifactPubKeyFile + ".sig"
	if err := os.WriteFile(signatureFile, signature, 0o600); err != nil {
		return fmt.Errorf("write signature file (%s): %w", signatureFile, err)
	}

	cmd.Printf("✅ Artifact key created successfully.\n")
	cmd.Printf("%s\n", artifactKey.String())
	return nil
}

func handleBundlePubKeys(cmd *cobra.Command, rootPrivKeyFile string, artifactPubKeyFiles []string, bundlePubKeysFile string) error {
	cmd.Println("📦 Bundling public keys into signed package...")

	privKeyPEM, err := os.ReadFile(rootPrivKeyFile)
	if err != nil {
		return fmt.Errorf("read root private key file: %w", err)
	}

	privateRootKey, err := reposign.ParseRootKey(privKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private root key: %w", err)
	}

	publicKeys := make([]reposign.PublicKey, 0, len(artifactPubKeyFiles))
	for _, pubFile := range artifactPubKeyFiles {
		pubPem, err := os.ReadFile(pubFile)
		if err != nil {
			return fmt.Errorf("read public key file: %w", err)
		}

		pk, err := reposign.ParseArtifactPubKey(pubPem)
		if err != nil {
			return fmt.Errorf("failed to parse artifact key: %w", err)
		}
		publicKeys = append(publicKeys, pk)
	}

	parsedKeys, signature, err := reposign.BundleArtifactKeys(privateRootKey, publicKeys)
	if err != nil {
		return fmt.Errorf("bundle artifact keys: %w", err)
	}

	if err := os.WriteFile(bundlePubKeysFile, parsedKeys, 0o600); err != nil {
		return fmt.Errorf("write public keys file (%s): %w", bundlePubKeysFile, err)
	}

	signatureFile := bundlePubKeysFile + ".sig"
	if err := os.WriteFile(signatureFile, signature, 0o600); err != nil {
		return fmt.Errorf("write signature file (%s): %w", signatureFile, err)
	}

	cmd.Printf("✅ Bundle created with %d public keys.\n", len(artifactPubKeyFiles))
	return nil
}
