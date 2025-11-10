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

	verifyArtifactPubKeyFile    string
	verifyArtifactFile          string
	verifyArtifactSignatureFile string
)

var signArtifactCmd = &cobra.Command{
	Use:   "sign-artifact",
	Short: "Sign an artifact using an artifact private key",
	Long: `Sign a software artifact (e.g., update bundle or binary) using the artifact's private key.
This command produces a detached signature that can be verified using the corresponding artifact public key.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := handleSignArtifact(cmd, signArtifactRootPrivKeyFile, signArtifactArtifactFile); err != nil {
			return fmt.Errorf("failed to sign artifact: %w", err)
		}
		return nil
	},
}

var verifyArtifactCmd = &cobra.Command{
	Use:          "verify-artifact",
	Short:        "Verify an artifact signature using an artifact public key",
	Long:         `Verify a software artifact signature using the artifact's public key.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := handleVerifyArtifact(cmd, verifyArtifactPubKeyFile, verifyArtifactFile, verifyArtifactSignatureFile); err != nil {
			return fmt.Errorf("failed to verify artifact: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(signArtifactCmd)
	rootCmd.AddCommand(verifyArtifactCmd)

	signArtifactCmd.Flags().StringVar(&signArtifactRootPrivKeyFile, "artifact-key-file", "", "Path to the artifact private key file used for signing")
	signArtifactCmd.Flags().StringVar(&signArtifactArtifactFile, "artifact-file", "", "Path to the artifact to be signed")

	// Enforce required flags and panic if registration fails
	if err := signArtifactCmd.MarkFlagRequired("artifact-key-file"); err != nil {
		panic(fmt.Errorf("mark artifact-key-file as required: %w", err))
	}
	if err := signArtifactCmd.MarkFlagRequired("artifact-file"); err != nil {
		panic(fmt.Errorf("mark artifact-file as required: %w", err))
	}

	verifyArtifactCmd.Flags().StringVar(&verifyArtifactPubKeyFile, "artifact-public-key-file", "", "Path to the artifact public key file")
	verifyArtifactCmd.Flags().StringVar(&verifyArtifactFile, "artifact-file", "", "Path to the artifact to be verified")
	verifyArtifactCmd.Flags().StringVar(&verifyArtifactSignatureFile, "signature-file", "", "Path to the signature file")

	if err := verifyArtifactCmd.MarkFlagRequired("artifact-public-key-file"); err != nil {
		panic(fmt.Errorf("mark artifact-public-key-file as required: %w", err))
	}
	if err := verifyArtifactCmd.MarkFlagRequired("artifact-file"); err != nil {
		panic(fmt.Errorf("mark artifact-file as required: %w", err))
	}
	if err := verifyArtifactCmd.MarkFlagRequired("signature-file"); err != nil {
		panic(fmt.Errorf("mark signature-file as required: %w", err))
	}
}

func handleSignArtifact(cmd *cobra.Command, privKeyFile, artifactFile string) error {
	cmd.Println("🖋️  Signing artifact...")

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

	cmd.Printf("✅ Artifact signed successfully.\n")
	cmd.Printf("Signature file: %s\n", sigFile)
	return nil
}

func handleVerifyArtifact(cmd *cobra.Command, pubKeyFile, artifactFile, signatureFile string) error {
	cmd.Println("🔍 Verifying artifact...")

	// Read artifact public key
	pubKeyPEM, err := os.ReadFile(pubKeyFile)
	if err != nil {
		return fmt.Errorf("read public key file: %w", err)
	}

	publicKey, err := reposign.ParseArtifactPubKey(pubKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse artifact public key: %w", err)
	}

	// Read artifact data
	artifactData, err := os.ReadFile(artifactFile)
	if err != nil {
		return fmt.Errorf("read artifact file: %w", err)
	}

	// Read signature
	sigBytes, err := os.ReadFile(signatureFile)
	if err != nil {
		return fmt.Errorf("read signature file: %w", err)
	}

	signature, err := reposign.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	// Validate artifact
	if err := reposign.ValidateArtifact([]reposign.PublicKey{publicKey}, artifactData, *signature); err != nil {
		return fmt.Errorf("artifact verification failed: %w", err)
	}

	cmd.Println("✅ Artifact signature is valid")
	cmd.Printf("Artifact: %s\n", artifactFile)
	cmd.Printf("Signed by key: %s\n", signature.KeyID)
	cmd.Printf("Signature timestamp: %s\n", signature.Timestamp.Format("2006-01-02 15:04:05 MST"))
	return nil
}
