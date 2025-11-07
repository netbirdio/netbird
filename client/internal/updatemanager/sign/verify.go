package sign

import (
	"context"
	"crypto/ed25519"
	"embed"
	"encoding/binary"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/updatemanager/downloader"
)

const (
	defaultBaseURL         = "https://127.0.0.1:1234"
	defaultArtifactBaseURL = "https://github.com/netbirdio/netbird/releases/download/"

	artifactPubKeysFileName    = "artifact-key.pub"
	artifactPubKeysSigFileName = "artifact-key.pub.sig"
	revocationFileName         = "revocation.list"
	revocationSignFileName     = "revocation.list.sig"

	keySizeLimit    = 5 * 1024 * 1024 //5MB
	signatureLimit  = 1024
	revocationLimit = 10 * 1024 * 1024
)

//go:embed certs
var embeddedCerts embed.FS

type ArtifactVerify struct {
	rootKeys         []PublicKey
	keysBaseURL      *url.URL
	artifactsBaseURL *url.URL

	revocationList *RevocationList
}

func NewArtifactVerify(keysBaseURL, artifactsBaseURL string) (*ArtifactVerify, error) {
	allKeys, err := loadEmbeddedPublicKeys()
	if err != nil {
		return nil, err
	}

	ku, err := url.Parse(keysBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid keys base URL %q: %v", keysBaseURL, err)
	}

	au, err := url.Parse(artifactsBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid artifacts base URL %q: %v", artifactsBaseURL, err)
	}

	a := &ArtifactVerify{
		rootKeys:         allKeys,
		keysBaseURL:      ku,
		artifactsBaseURL: au,
	}
	return a, nil
}

func (a *ArtifactVerify) Verify(ctx context.Context, version string, artifactFile string) error {
	revocationList, err := a.loadRevocationList(ctx)
	if err != nil {
		return fmt.Errorf("failed to load revocation list: %v", err)
	}
	a.revocationList = revocationList

	artifactPubKeys, err := a.loadArtifactKeys(ctx)
	if err != nil {
		return fmt.Errorf("failed to load artifact keys: %v", err)
	}

	signature, err := a.loadArtifactSignature(ctx, version, artifactFile)
	if err != nil {
		return fmt.Errorf("failed to download signature file for: %s, %v", filepath.Base(artifactFile), err)
	}

	artifactData, err := os.ReadFile(artifactFile)
	if err != nil {
		log.Errorf("failed to read artifact file: %v", err)
		return fmt.Errorf("failed to read artifact file: %w", err)
	}

	if err := ValidateArtifact(artifactPubKeys, artifactData, *signature); err != nil {
		return fmt.Errorf("failed to validate artifact: %v", err)
	}

	return nil
}

func (a *ArtifactVerify) loadRevocationList(ctx context.Context) (*RevocationList, error) {
	downloadURL := a.keysBaseURL.JoinPath(revocationFileName).String()
	data, err := downloader.DownloadToMemory(ctx, downloadURL, revocationLimit)
	if err != nil {
		log.Debugf("failed to download revocation list for: %s", err)
		return nil, err
	}

	downloadURL = a.keysBaseURL.JoinPath(revocationSignFileName).String()
	sigData, err := downloader.DownloadToMemory(ctx, downloadURL, signatureLimit)
	if err != nil {
		log.Debugf("failed to download revocation list for: %s", err)
		return nil, err
	}

	signature, err := ParseSignature(sigData)
	if err != nil {
		log.Debugf("failed to parse revocation list signature: %s", err)
		return nil, err
	}

	return ValidateRevocationList(a.rootKeys, data, *signature)
}

func (a *ArtifactVerify) loadArtifactKeys(ctx context.Context) ([]PublicKey, error) {
	downloadURL := a.keysBaseURL.JoinPath(artifactPubKeysFileName).String()
	log.Debugf("starting downloading artifact keys from: %s", downloadURL)
	data, err := downloader.DownloadToMemory(ctx, downloadURL, keySizeLimit)
	if err != nil {
		log.Debugf("failed to download artifact keys: %s", err)
		return nil, err
	}

	downloadURL = a.keysBaseURL.JoinPath(artifactPubKeysSigFileName).String()
	log.Debugf("start downloading signature of artifact pub key from: %s", downloadURL)
	sigData, err := downloader.DownloadToMemory(ctx, downloadURL, signatureLimit)
	if err != nil {
		log.Debugf("failed to download signature of public keys: %s", err)
		return nil, err
	}

	signature, err := ParseSignature(sigData)
	if err != nil {
		log.Debugf("failed to parse signature of public keys: %s", err)
		return nil, err
	}

	return ValidateArtifactKeys(a.rootKeys, data, *signature, a.revocationList)
}

func (a *ArtifactVerify) loadArtifactSignature(ctx context.Context, version string, artifactFile string) (*Signature, error) {
	downloadURL := a.artifactsBaseURL.JoinPath(version, artifactFile+".sig").String()
	log.Debugf("starting downloading artifact signature from: %s", downloadURL)
	data, err := downloader.DownloadToMemory(ctx, downloadURL, signatureLimit)
	if err != nil {
		log.Debugf("failed to download artifact signature: %s", err)
		return nil, err
	}

	signature, err := ParseSignature(data)
	if err != nil {
		log.Debugf("failed to parse artifact signature: %s", err)
		return nil, err
	}

	return signature, nil

}

func (a *ArtifactVerify) validateArtifact(artifactPubKeys []PublicKey, artifactFile string, signature *Signature) error {
	// Validate signature timestamp
	now := time.Now().UTC()
	if signature.Timestamp.After(now.Add(maxClockSkew)) {
		err := fmt.Errorf("artifact signature timestamp is in the future: %v", signature.Timestamp)
		log.Debugf("failed to verify signature of artifact: %s", err)
		return err
	}
	if now.Sub(signature.Timestamp) > maxSignatureAge {
		return fmt.Errorf("artifact signature is too old: %v (created %v)",
			now.Sub(signature.Timestamp), signature.Timestamp)
	}

	// Read and hash the artifact file
	artifactData, err := os.ReadFile(artifactFile)
	if err != nil {
		log.Errorf("failed to read artifact file: %v", err)
		return fmt.Errorf("failed to read artifact file: %w", err)
	}

	h := NewArtifactHash()
	if _, err := h.Write(artifactData); err != nil {
		return fmt.Errorf("failed to hash artifact: %w", err)
	}
	hash := h.Sum(nil)

	// Reconstruct the signed message: hash || length || timestamp
	msg := make([]byte, 0, len(hash)+8+8)
	msg = append(msg, hash...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(len(artifactData)))
	msg = binary.LittleEndian.AppendUint64(msg, uint64(signature.Timestamp.Unix()))

	// Find matching Key and verify
	for _, keyInfo := range artifactPubKeys {
		if keyInfo.Metadata.ID == signature.KeyID {
			// Check Key expiration
			if !keyInfo.Metadata.ExpiresAt.IsZero() &&
				signature.Timestamp.After(keyInfo.Metadata.ExpiresAt) {
				return fmt.Errorf("signing Key %s expired at %v, signature from %v",
					signature.KeyID, keyInfo.Metadata.ExpiresAt, signature.Timestamp)
			}

			if ed25519.Verify(keyInfo.Key, msg, signature.Signature) {
				log.Infof("artifact %s verified successfully with Key %s",
					filepath.Base(artifactFile), signature.KeyID)
				return nil
			}
			return fmt.Errorf("signature verification failed for Key %s", signature.KeyID)
		}
	}

	return fmt.Errorf("no signing Key found with ID %s", signature.KeyID)
}

func loadEmbeddedPublicKeys() ([]PublicKey, error) {
	files, err := embeddedCerts.ReadDir("certs")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded certs: %w", err)
	}

	var allKeys []PublicKey
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		data, err := embeddedCerts.ReadFile("certs/" + file.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read cert file %s: %w", file.Name(), err)
		}

		keys, err := parsePublicKeyBundle(data, tagRootPublic)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cert %s: %w", file.Name(), err)
		}

		allKeys = append(allKeys, keys...)
	}

	if len(allKeys) == 0 {
		return nil, fmt.Errorf("no valid public keys found in embedded certs")
	}

	return allKeys, nil
}
