//go:build unix

package certproof

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
)

// devicePair writes a certificate and its key as separate files into dir.
func devicePair(t *testing.T, dir string) {
	t.Helper()
	ca := certtest.NewCA(t, "corp-root")
	key := certtest.ECDSAKey(t)
	writeFile(t, dir, "device.crt", certtest.CertPEM(ca.Issue(t, key, "device")))
	writeFile(t, dir, "device.key", certtest.KeyPEM(t, key))
}

func candidates(t *testing.T, dir string) ([]Candidate, error) {
	t.Helper()
	return NewFileStore(dir).Candidates(context.Background())
}

func TestFileStore_AcceptsAPrivatePair(t *testing.T) {
	dir := storeDir(t)
	devicePair(t, dir)

	got, err := candidates(t, dir)
	require.NoError(t, err)
	assert.Len(t, got, 1, "a certificate and key only their owner can write are used")
}

func TestFileStore_RefusesASymlinkedKey(t *testing.T) {
	dir := storeDir(t)
	devicePair(t, dir)

	// The real key moves elsewhere and the directory only links to it, as a user able
	// to write the directory would do to point the daemon at a key it should not use.
	elsewhere := filepath.Join(storeDir(t), "other.key")
	require.NoError(t, os.Rename(filepath.Join(dir, "device.key"), elsewhere))
	require.NoError(t, os.Symlink(elsewhere, filepath.Join(dir, "device.key")))

	got, err := candidates(t, dir)
	require.NoError(t, err)
	assert.Empty(t, got, "a key reached through a symlink is never used")
}

func TestFileStore_RefusesASymlinkedCertificateFile(t *testing.T) {
	dir := storeDir(t)
	other := storeDir(t)
	devicePair(t, other)
	require.NoError(t, os.Symlink(filepath.Join(other, "device.crt"), filepath.Join(dir, "device.crt")))
	require.NoError(t, os.Symlink(filepath.Join(other, "device.key"), filepath.Join(dir, "device.key")))

	got, err := candidates(t, dir)
	require.NoError(t, err)
	assert.Empty(t, got, "a certificate file that is a symlink is skipped")
}

func TestFileStore_RefusesFilesOthersCanWrite(t *testing.T) {
	for name, mode := range map[string]os.FileMode{"world-writable": 0o602, "group-writable": 0o620} {
		t.Run(name, func(t *testing.T) {
			dir := storeDir(t)
			devicePair(t, dir)
			require.NoError(t, os.Chmod(filepath.Join(dir, "device.key"), mode))

			got, err := candidates(t, dir)
			require.NoError(t, err)
			assert.Empty(t, got, "a key %s may have been replaced by someone else, even when the group is root's", name)
		})
	}
}

func TestFileStore_RefusesADirectoryOthersCanWrite(t *testing.T) {
	dir := storeDir(t)
	devicePair(t, dir)
	require.NoError(t, os.Chmod(dir, 0o777))

	_, err := candidates(t, dir)
	assert.ErrorContains(t, err, "refusing certificate store", "files in a directory anyone can write are not trusted")
}

func TestFileStore_SkipsAFIFOWithoutBlocking(t *testing.T) {
	dir := storeDir(t)
	require.NoError(t, syscall.Mkfifo(filepath.Join(dir, "trap.pem"), 0o600))
	devicePair(t, dir)

	got, err := candidates(t, dir)
	require.NoError(t, err)
	assert.Len(t, got, 1, "a FIFO is skipped and the real pair still loads")
}

func TestReadStoreFile_RefusesOversizedFiles(t *testing.T) {
	dir := storeDir(t)
	path := filepath.Join(dir, "huge.pem")
	require.NoError(t, os.WriteFile(path, make([]byte, maxStoreFileSize+1), 0o600))

	_, err := readStoreFile(path)
	assert.ErrorContains(t, err, "limit")
}

func TestFileStore_AcceptsASymlinkedDirectoryItsOwnerControls(t *testing.T) {
	target := storeDir(t)
	devicePair(t, target)
	link := filepath.Join(storeDir(t), "certs")
	require.NoError(t, os.Symlink(target, link))

	// The link belongs to this process's user, as one root creates belongs to root.
	got, err := candidates(t, link)
	require.NoError(t, err)
	assert.Len(t, got, 1, "a certificate directory behind a symlink the owner controls is read")
}

func TestFileStore_ChecksTheDirectoryBeforeListingIt(t *testing.T) {
	dir := storeDir(t)
	devicePair(t, dir)
	require.NoError(t, os.Chmod(dir, 0o777))

	paths, err := certFiles(dir)
	assert.ErrorContains(t, err, "refusing certificate store")
	assert.Nil(t, paths, "nothing in a directory anyone can write to is listed")
}

func TestFileStore_MissingDirectoryIsEmpty(t *testing.T) {
	paths, err := certFiles(filepath.Join(storeDir(t), "missing"))
	assert.NoError(t, err, "a store directory that does not exist yet is not an error")
	assert.Empty(t, paths)
}
