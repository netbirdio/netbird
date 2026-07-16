package rosenpass

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadOrGenerateKeypair_EphemeralWhenNoPath(t *testing.T) {
	pub, sec, err := loadOrGenerateKeypair("")
	require.NoError(t, err)
	require.Len(t, pub, rpStaticPublicKeySize)
	require.NotEmpty(t, sec)
}

func TestLoadOrGenerateKeypair_PersistsAndReloads(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), keypairFileName)

	pub1, sec1, err := loadOrGenerateKeypair(keyPath)
	require.NoError(t, err)

	info, err := os.Stat(keyPath)
	require.NoError(t, err, "keypair file must be written")
	require.Equal(t, os.FileMode(0600), info.Mode().Perm(), "keypair file must be 0600")

	pub2, sec2, err := loadOrGenerateKeypair(keyPath)
	require.NoError(t, err)
	require.True(t, bytes.Equal(pub1, pub2), "public key must be stable across reloads")
	require.True(t, bytes.Equal(sec1, sec2), "secret key must be stable across reloads")
}

func TestLoadOrGenerateKeypair_RegeneratesOnCorruptFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), keypairFileName)
	require.NoError(t, os.WriteFile(keyPath, []byte("not json"), 0600))

	pub, sec, err := loadOrGenerateKeypair(keyPath)
	require.NoError(t, err)
	require.Len(t, pub, rpStaticPublicKeySize)
	require.NotEmpty(t, sec)

	// the corrupt file must have been overwritten with a valid, reloadable keypair
	pub2, _, err := loadOrGenerateKeypair(keyPath)
	require.NoError(t, err)
	require.True(t, bytes.Equal(pub, pub2))
}

func TestLoadOrGenerateKeypair_RegeneratesOnVersionMismatch(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), keypairFileName)

	pub1, _, err := loadOrGenerateKeypair(keyPath)
	require.NoError(t, err)

	// rewrite with a bumped/unknown format version -> must be discarded
	bs, err := json.Marshal(persistedKeypair{Version: keypairFormatVersion + 1, PublicKey: pub1, SecretKey: []byte{0x01}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath, bs, 0600))

	pub2, sec2, err := loadOrGenerateKeypair(keyPath)
	require.NoError(t, err)
	require.Len(t, pub2, rpStaticPublicKeySize)
	require.NotEmpty(t, sec2)
}
