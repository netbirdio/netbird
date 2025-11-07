package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/updatemanager/reposign"
)

var (
	signArtifactRootPrivKeyFile string
	signArtifactArtifactFile    string
)

var signArtifactCmd = &cobra.Command{
	Use:   "sign-artifact",
	Short: "Sign an artifact using an artifact private key",
	Long: `Sign a software artifact (e.g., update bundle or binary) using the artifact's private key.
This command produces a detached signature that can be verified using the corresponding artifact public key.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := handleSignArtifact(signArtifactRootPrivKeyFile, signArtifactArtifactFile); err != nil {
			return fmt.Errorf("failed to sign artifact: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(signArtifactCmd)

	signArtifactCmd.Flags().StringVar(&signArtifactRootPrivKeyFile, "artifact-key-file", "", "Path to the artifact private key file used for signing")
	signArtifactCmd.Flags().StringVar(&signArtifactArtifactFile, "artifact-file", "", "Path to the artifact to be signed")

	// Enforce required flags and panic if registration fails
	if err := signArtifactCmd.MarkFlagRequired("artifact-key-file"); err != nil {
		panic(fmt.Errorf("mark artifact-key-file as required: %w", err))
	}
	if err := signArtifactCmd.MarkFlagRequired("artifact-file"); err != nil {
		panic(fmt.Errorf("mark artifact-file as required: %w", err))
	}
}

func handleSignArtifact(privKeyFile, artifactFile string) error {
	fmt.Println("🖋️  Signing artifact...")

	privKeyPEM, err := os.ReadFile(privKeyFile)
	if err != nil {
		return fmt.Errorf("read private key file: %w", err)
	}

	privateKey, err := reposign.ParseArtifactKey(privKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse artifact private key: %w", err)
	}

	artifactData, err := os.ReadFile(artifactFile)
	if err != nil {
		return fmt.Errorf("read artifact file: %w", err)
	}

	signature, err := reposign.SignData(privateKey, artifactData)
	if err != nil {
		return fmt.Errorf("sign artifact: %w", err)
	}

	sigFile := artifactFile + ".sig"
	if err := os.WriteFile(artifactFile+".sig", signature, 0o600); err != nil {
		return fmt.Errorf("write signature file (%s): %w", sigFile, err)
	}

	fmt.Printf("✅ Artifact signed successfully.\n")
	fmt.Printf("Signature file: %s\n", sigFile)
	return nil
}
