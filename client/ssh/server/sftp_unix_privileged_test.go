//go:build unix && privileged

package server

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/netbirdio/netbird/client/ssh"
)

// TestSSHServer_SFTPRefusedForNologinAccount verifies that an account the host has closed to
// logins (login shell nologin/false) gets no SFTP access, just as it gets no shell or command
// session: the SFTP server must be started through the same user switching path as commands.
func TestSSHServer_SFTPRefusedForNologinAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("user switching requires root")
	}

	username := findNologinUser()
	if username == "" {
		t.Skip("no account without a login shell on this system")
	}

	hostKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	clientPrivKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)

	server := New(&Config{HostKeyPEM: hostKey})
	server.SetAllowSFTP(true)

	serverAddr := StartTestServer(t, server)
	defer func() {
		require.NoError(t, server.Stop())
	}()

	signer, err := cryptossh.ParsePrivateKey(clientPrivKey)
	require.NoError(t, err)

	conn, err := cryptossh.Dial("tcp", serverAddr, &cryptossh.ClientConfig{
		User:            username,
		Auth:            []cryptossh.AuthMethod{cryptossh.PublicKeys(signer)},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         5 * time.Second,
	})
	require.NoError(t, err, "SSH connection should succeed")
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("connection close error: %v", err)
		}
	}()

	sftpClient, err := sftp.NewClient(conn)
	if err == nil {
		_ = sftpClient.Close()
	}
	require.Error(t, err, "SFTP must be refused for %s, whose shell is not a login shell", username)
}

// findNologinUser returns a system account whose login shell refuses logins, or "".
func findNologinUser() string {
	for _, candidate := range []string{"nobody", "daemon", "www-data"} {
		u, err := user.Lookup(candidate)
		if err != nil {
			continue
		}
		switch filepath.Base(getUserShell(u.Uid)) {
		case "nologin", "false":
			return candidate
		}
	}
	return ""
}
