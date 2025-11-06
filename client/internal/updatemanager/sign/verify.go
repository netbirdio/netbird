package sign

import (
	"context"
	"crypto/ed25519"
	"embed"
	"encoding/binary"
	"errors"
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

	maxClockSkew    = 5 * time.Minute
	maxSignatureAge = 365 * 24 * time.Hour
)

//go:embed certs/*.pem
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

	if err := a.validateArtifact(artifactPubKeys, artifactFile, signature); err != nil {
		return fmt.Errorf("failed to validate artifact: %v", err)
	}

	return nil
}

func (a *ArtifactVerify) loadRevocationList(ctx context.Context) (*RevocationList, error) {
	url := a.keysBaseURL.JoinPath(revocationFileName).String()
	data, err := downloader.DownloadToMemory(ctx, url, revocationLimit)
	if err != nil {
		log.Debugf("failed to download revocation list for: %s", err)
		return nil, err
	}

	url = a.keysBaseURL.JoinPath(revocationSignFileName).String()
	sigData, err := downloader.DownloadToMemory(ctx, url, signatureLimit)
	if err != nil {
		log.Debugf("failed to download revocation list for: %s", err)
		return nil, err
	}

	signature, err := ParseSignature(sigData)
	if err != nil {
		log.Debugf("failed to parse revocation list signature: %s", err)
		return nil, err
	}

	now := time.Now().UTC()
	if signature.Timestamp.After(now.Add(maxClockSkew)) {
		err := fmt.Errorf("revocation signature timestamp is in the future: %v", signature.Timestamp)
		log.Debugf("revocation list signature error: %v", err)
		return nil, err
	}
	if now.Sub(signature.Timestamp) > maxSignatureAge {
		err := fmt.Errorf("revocation list signature is too old: %v (created %v)", now.Sub(signature.Timestamp), signature.Timestamp)
		log.Debugf("revocation list signature error: %v", err)
		return nil, err
	}

	// Verify with root keys
	var rootKeys []ed25519.PublicKey
	for _, r := range a.rootKeys {
		rootKeys = append(rootKeys, r.Key)
	}

	if !verifyAny(rootKeys, data, signature.Signature) {
		return nil, errors.New("revocation list verification failed")
	}

	revoList, err := ParseRevocationList(data)
	if err != nil {
		log.Debugf("failed to parse revocation list signature: %s", err)
		return nil, err
	}

	return revoList, nil
}

func (a *ArtifactVerify) loadArtifactKeys(ctx context.Context) ([]PublicKey, error) {
	url := a.keysBaseURL.JoinPath(artifactPubKeysFileName).String()
	log.Debugf("starting downloading artifact keys from: %s", url)
	data, err := downloader.DownloadToMemory(ctx, url, keySizeLimit)
	if err != nil {
		log.Debugf("failed to download artifact keys: %s", err)
		return nil, err
	}

	url = a.keysBaseURL.JoinPath(artifactPubKeysSigFileName).String()
	log.Debugf("start downloading signature of artifact pub key from: %s", url)
	sigData, err := downloader.DownloadToMemory(ctx, url, signatureLimit)
	if err != nil {
		log.Debugf("failed to download signature of public keys: %s", err)
		return nil, err
	}

	signature, err := ParseSignature(sigData)
	if err != nil {
		log.Debugf("failed to parse signature of public keys: %s", err)
		return nil, err
	}

	now := time.Now().UTC()
	if signature.Timestamp.After(now.Add(maxClockSkew)) {
		err := fmt.Errorf("signature timestamp is in the future: %v", signature.Timestamp)
		log.Debugf("artifact signature error: %v", err)
		return nil, err
	}
	if now.Sub(signature.Timestamp) > maxSignatureAge {
		err := fmt.Errorf("signature is too old: %v (created %v)", now.Sub(signature.Timestamp), signature.Timestamp)
		log.Debugf("artifact signature error: %v", err)
		return nil, err
	}

	// Verify with root keys
	var rootKeys []ed25519.PublicKey
	for _, r := range a.rootKeys {
		rootKeys = append(rootKeys, r.Key)
	}

	if !verifyAny(rootKeys, data, signature.Signature) {
		return nil, errors.New("failed to verify signature of artifact keys")
	}

	pubKeys, err := parsePublicKeyBundle(data, tagArtifactPublic)
	if err != nil {
		log.Debugf("failed to parse public keys for: %s", err)
		return nil, err
	}

	validKeys := make([]PublicKey, 0, len(pubKeys))
	for _, pubKey := range pubKeys {
		if revTime, revoked := a.revocationList.Revoked[pubKey.Metadata.ID]; revoked {
			log.Debugf("Key %s is revoked as of %v (created %v)",
				pubKey.Metadata.ID, revTime, pubKey.Metadata.CreatedAt)
			continue
		}
		validKeys = append(validKeys, pubKey)
	}

	if len(validKeys) == 0 {
		log.Debugf("no valid public keys found for artifact keys")
		return nil, fmt.Errorf("all %d artifact keys are revoked", len(pubKeys))
	}

	return validKeys, nil
}

func (a *ArtifactVerify) loadArtifactSignature(ctx context.Context, version string, artifactFile string) (*Signature, error) {
	url := a.artifactsBaseURL.JoinPath(version, artifactFile+".sig").String()
	log.Debugf("starting downloading artifact signature from: %s", url)
	data, err := downloader.DownloadToMemory(ctx, url, signatureLimit)
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

	// Check if signing Key is revoked
	if a.revocationList != nil {
		if revTime, ok := a.revocationList.Revoked[signature.KeyID]; ok {
			if signature.Timestamp.After(revTime) {
				return fmt.Errorf("signature Key %s was revoked at %v, but signature is from %v",
					signature.KeyID, revTime, signature.Timestamp)
			}
		}
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

func verifyAny(keys []ed25519.PublicKey, msg, sig []byte) bool {
	for _, k := range keys {
		if ed25519.Verify(k, msg, sig) {
			return true
		}
	}
	return false
}
