package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/updatemanager/reposign"
)

const (
	envArtifactPrivateKey = "NB_ARTIFACT_PRIV_KEY"
)

var (
	signArtifactPrivKeyFile  string
	signArtifactArtifactFile string

	verifyArtifactPubKeyFile    string
	verifyArtifactFile          string
	verifyArtifactSignatureFile string

	verifyArtifactKeyPubKeyFile     string
	verifyArtifactKeyRootPubKeyFile string
	verifyArtifactKeySignatureFile  string
	verifyArtifactKeyRevocationFile string
)

var signArtifactCmd = &cobra.Command{
	Use:   "sign-artifact",
	Short: "Sign an artifact using an artifact private key",
	Long: `Sign a software artifact (e.g., update bundle or binary) using the artifact's private key.
This command produces a detached signature that can be verified using the corresponding artifact public key.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := handleSignArtifact(cmd, signArtifactPrivKeyFile, signArtifactArtifactFile); err != nil {
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

var verifyArtifactKeyCmd = &cobra.Command{
	Use:   "verify-artifact-key",
	Short: "Verify an artifact public key was signed by a root key",
	Long: `Verify that an artifact public key (or bundle) was properly signed by a root key.
This validates the chain of trust from the root key to the artifact key.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := handleVerifyArtifactKey(cmd, verifyArtifactKeyPubKeyFile, verifyArtifactKeyRootPubKeyFile, verifyArtifactKeySignatureFile, verifyArtifactKeyRevocationFile); err != nil {
			return fmt.Errorf("failed to verify artifact key: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(signArtifactCmd)
	rootCmd.AddCommand(verifyArtifactCmd)
	rootCmd.AddCommand(verifyArtifactKeyCmd)

	signArtifactCmd.Flags().StringVar(&signArtifactPrivKeyFile, "artifact-key-file", "", fmt.Sprintf("Path to the artifact private key file used for signing (or set %s env var)", envArtifactPrivateKey))
	signArtifactCmd.Flags().StringVar(&signArtifactArtifactFile, "artifact-file", "", "Path to the artifact to be signed")

	// artifact-file is required, but artifact-key-file can come from env var
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

	verifyArtifactKeyCmd.Flags().StringVar(&verifyArtifactKeyPubKeyFile, "artifact-key-file", "", "Path to the artifact public key file or bundle")
	verifyArtifactKeyCmd.Flags().StringVar(&verifyArtifactKeyRootPubKeyFile, "root-key-file", "", "Path to the root public key file or bundle")
	verifyArtifactKeyCmd.Flags().StringVar(&verifyArtifactKeySignatureFile, "signature-file", "", "Path to the signature file")
	verifyArtifactKeyCmd.Flags().StringVar(&verifyArtifactKeyRevocationFile, "revocation-file", "", "Path to the revocation list file (optional)")

	if err := verifyArtifactKeyCmd.MarkFlagRequired("artifact-key-file"); err != nil {
		panic(fmt.Errorf("mark artifact-key-file as required: %w", err))
	}
	if err := verifyArtifactKeyCmd.MarkFlagRequired("root-key-file"); err != nil {
		panic(fmt.Errorf("mark root-key-file as required: %w", err))
	}
	if err := verifyArtifactKeyCmd.MarkFlagRequired("signature-file"); err != nil {
		panic(fmt.Errorf("mark signature-file as required: %w", err))
	}
}

func handleSignArtifact(cmd *cobra.Command, privKeyFile, artifactFile string) error {
	cmd.Println("🖋️  Signing artifact...")

	// Load private key from env var or file
	var privKeyPEM []byte
	var err error

	if envKey := os.Getenv(envArtifactPrivateKey); envKey != "" {
		// Use key from environment variable
		privKeyPEM = []byte(envKey)
	} else if privKeyFile != "" {
		// Fall back to file
		privKeyPEM, err = os.ReadFile(privKeyFile)
		if err != nil {
			return fmt.Errorf("read private key file: %w", err)
		}
	} else {
		return fmt.Errorf("artifact private key must be provided via %s environment variable or --artifact-key-file flag", envArtifactPrivateKey)
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

func handleVerifyArtifactKey(cmd *cobra.Command, artifactKeyFile, rootKeyFile, signatureFile, revocationFile string) error {
	cmd.Println("🔍 Verifying artifact key...")

	// Read artifact key data
	artifactKeyData, err := os.ReadFile(artifactKeyFile)
	if err != nil {
		return fmt.Errorf("read artifact key file: %w", err)
	}

	// Read root public key(s)
	rootKeyData, err := os.ReadFile(rootKeyFile)
	if err != nil {
		return fmt.Errorf("read root key file: %w", err)
	}

	rootPublicKeys, err := parseRootPublicKeys(rootKeyData)
	if err != nil {
		return fmt.Errorf("failed to parse root public key(s): %w", err)
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

	// Read optional revocation list
	var revocationList *reposign.RevocationList
	if revocationFile != "" {
		revData, err := os.ReadFile(revocationFile)
		if err != nil {
			return fmt.Errorf("read revocation file: %w", err)
		}

		revocationList, err = reposign.ParseRevocationList(revData)
		if err != nil {
			return fmt.Errorf("failed to parse revocation list: %w", err)
		}
	}

	// Validate artifact key(s)
	validKeys, err := reposign.ValidateArtifactKeys(rootPublicKeys, artifactKeyData, *signature, revocationList)
	if err != nil {
		return fmt.Errorf("artifact key verification failed: %w", err)
	}

	cmd.Println("✅ Artifact key(s) verified successfully")
	cmd.Printf("Signed by root key: %s\n", signature.KeyID)
	cmd.Printf("Signature timestamp: %s\n", signature.Timestamp.Format("2006-01-02 15:04:05 MST"))
	cmd.Printf("\nValid artifact keys (%d):\n", len(validKeys))
	for i, key := range validKeys {
		cmd.Printf("  [%d] Key ID: %s\n", i+1, key.Metadata.ID)
		cmd.Printf("      Created: %s\n", key.Metadata.CreatedAt.Format("2006-01-02 15:04:05 MST"))
		if !key.Metadata.ExpiresAt.IsZero() {
			cmd.Printf("      Expires: %s\n", key.Metadata.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
		} else {
			cmd.Printf("      Expires: Never\n")
		}
	}
	return nil
}

// parseRootPublicKeys parses a root public key from PEM data
func parseRootPublicKeys(data []byte) ([]reposign.PublicKey, error) {
	key, err := reposign.ParseRootPublicKey(data)
	if err != nil {
		return nil, err
	}
	return []reposign.PublicKey{key}, nil
}
