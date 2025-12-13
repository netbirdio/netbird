package reposign

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/updatemanager/downloader"
)

const (
	artifactPubKeysFileName    = "artifact-key-pub.pem"
	artifactPubKeysSigFileName = "artifact-key-pub.pem.sig"
	revocationFileName         = "revocation-list.json"
	revocationSignFileName     = "revocation-list.json.sig"

	keySizeLimit    = 5 * 1024 * 1024 //5MB
	signatureLimit  = 1024
	revocationLimit = 10 * 1024 * 1024
)

type ArtifactVerify struct {
	rootKeys    []PublicKey
	keysBaseURL *url.URL

	revocationList *RevocationList
}

func NewArtifactVerify(keysBaseURL string) (*ArtifactVerify, error) {
	allKeys, err := loadEmbeddedPublicKeys()
	if err != nil {
		return nil, err
	}

	return newArtifactVerify(keysBaseURL, allKeys)
}

func newArtifactVerify(keysBaseURL string, allKeys []PublicKey) (*ArtifactVerify, error) {
	ku, err := url.Parse(keysBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid keys base URL %q: %v", keysBaseURL, err)
	}

	a := &ArtifactVerify{
		rootKeys:    allKeys,
		keysBaseURL: ku,
	}
	return a, nil
}

func (a *ArtifactVerify) Verify(ctx context.Context, version string, artifactFile string) error {
	version = strings.TrimPrefix(version, "v")

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
	downloadURL := a.keysBaseURL.JoinPath("keys", revocationFileName).String()
	data, err := downloader.DownloadToMemory(ctx, downloadURL, revocationLimit)
	if err != nil {
		log.Debugf("failed to download revocation list '%s': %s", downloadURL, err)
		return nil, err
	}

	downloadURL = a.keysBaseURL.JoinPath("keys", revocationSignFileName).String()
	sigData, err := downloader.DownloadToMemory(ctx, downloadURL, signatureLimit)
	if err != nil {
		log.Debugf("failed to download revocation list '%s': %s", downloadURL, err)
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
	downloadURL := a.keysBaseURL.JoinPath("keys", artifactPubKeysFileName).String()
	log.Debugf("starting downloading artifact keys from: %s", downloadURL)
	data, err := downloader.DownloadToMemory(ctx, downloadURL, keySizeLimit)
	if err != nil {
		log.Debugf("failed to download artifact keys: %s", err)
		return nil, err
	}

	downloadURL = a.keysBaseURL.JoinPath("keys", artifactPubKeysSigFileName).String()
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
	artifactFile = filepath.Base(artifactFile)
	downloadURL := a.keysBaseURL.JoinPath("tag", "v"+version, artifactFile+".sig").String()
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

func loadEmbeddedPublicKeys() ([]PublicKey, error) {
	files, err := embeddedCerts.ReadDir(embeddedCertsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded certs: %w", err)
	}

	var allKeys []PublicKey
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		data, err := embeddedCerts.ReadFile(embeddedCertsDir + "/" + file.Name())
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
