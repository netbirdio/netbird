package rosenpass

import (
	"context"
	"fmt"
	"os"

	rp "cunicu.li/go-rosenpass"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util"
)

const (
	// keypairFileName is the file, relative to the state directory, that holds
	// the persisted local Rosenpass static keypair.
	keypairFileName = "rosenpass_key.json"

	// rpStaticPublicKeySize is the byte length of a Rosenpass (Classic McEliece)
	// static public key as produced by the pinned go-rosenpass version. Used as a
	// version-compatibility guard: a persisted key of any other size is treated as
	// stale and regenerated instead of being fed to go-rosenpass (which would fail).
	rpStaticPublicKeySize = 524160

	// keypairFormatVersion is bumped whenever the on-disk representation changes so
	// old files are discarded and regenerated rather than misparsed.
	keypairFormatVersion = 1
)

// persistedKeypair is the on-disk representation of the local Rosenpass static
// keypair. Keys are stored raw (base64 via JSON) with the same restricted 0600
// permission as the WireGuard private key and other client secrets.
type persistedKeypair struct {
	Version   int    `json:"version"`
	PublicKey []byte `json:"public_key"`
	SecretKey []byte `json:"secret_key"`
}

// loadOrGenerateKeypair returns a Rosenpass static keypair. When keyPath is set
// and holds a valid persisted keypair it is reused, so the local public key —
// and therefore the fingerprint advertised to remote peers over signalling —
// stays stable across restarts. Otherwise a fresh keypair is generated and, when
// keyPath is set, persisted for subsequent runs. A missing or corrupt file is not
// fatal: it degrades to generating an ephemeral keypair, matching the pre-persistence
// behaviour.
func loadOrGenerateKeypair(keyPath string) (public []byte, secret []byte, err error) {
	if keyPath != "" {
		public, secret, err = loadKeypair(keyPath)
		switch {
		case err == nil:
			return public, secret, nil
		case os.IsNotExist(err):
			// first run for this state dir; fall through to generate
		default:
			log.Warnf("failed to load persisted rosenpass keypair, generating a new one: %v", err)
		}
	}

	pub, sec, err := rp.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generate rosenpass key pair: %w", err)
	}

	if keyPath != "" {
		if err := saveKeypair(keyPath, pub, sec); err != nil {
			log.Warnf("failed to persist rosenpass keypair, key will be regenerated on next restart: %v", err)
		}
	}

	return pub, sec, nil
}

func loadKeypair(keyPath string) ([]byte, []byte, error) {
	var kp persistedKeypair
	if _, err := util.ReadJson(keyPath, &kp); err != nil {
		return nil, nil, err
	}

	if kp.Version != keypairFormatVersion || len(kp.PublicKey) != rpStaticPublicKeySize || len(kp.SecretKey) == 0 {
		return nil, nil, fmt.Errorf("persisted rosenpass keypair is incompatible (version %d, public %d bytes, secret %d bytes)", kp.Version, len(kp.PublicKey), len(kp.SecretKey))
	}

	return kp.PublicKey, kp.SecretKey, nil
}

func saveKeypair(keyPath string, public, secret []byte) error {
	return util.WriteJsonWithRestrictedPermission(context.Background(), keyPath, persistedKeypair{
		Version:   keypairFormatVersion,
		PublicKey: public,
		SecretKey: secret,
	})
}
