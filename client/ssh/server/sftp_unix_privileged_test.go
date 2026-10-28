//go:build unix && privileged

package server

import (
	"os"
	"os/exec"
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
// A control connects as an ordinary account with a real shell through the same path, so a
// refusal here is attributable to the account's login shell and not to an unrelated SFTP
// subprocess failure.
func TestSSHServer_SFTPRefusedForNologinAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("user switching requires root")
	}

	nologinUser := findNologinUser()
	if nologinUser == "" {
		t.Skip("no account without a login shell on this system")
	}

	// A control dialed as the invoking user (root, under the privileged harness) would need no
	// user switching and take the direct in-process path, never the su/executor path this test
	// means to exercise. Use a separate, non-root account with a real shell instead.
	loginUser := createLoginTestUser(t)

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

	dial := func(username string) (*cryptossh.Client, error) {
		return cryptossh.Dial("tcp", serverAddr, &cryptossh.ClientConfig{
			User:            username,
			Auth:            []cryptossh.AuthMethod{cryptossh.PublicKeys(signer)},
			HostKeyCallback: cryptossh.InsecureIgnoreHostKey(), //nolint:gosec
			Timeout:         5 * time.Second,
		})
	}

	t.Run("control_account_with_real_shell_is_served", func(t *testing.T) {
		conn, err := dial(loginUser)
		require.NoError(t, err, "SSH connection should succeed")
		defer func() {
			if err := conn.Close(); err != nil {
				t.Logf("connection close error: %v", err)
			}
		}()

		sftpClient, err := sftp.NewClient(conn)
		require.NoError(t, err, "SFTP must be served for %s, which has a real login shell", loginUser)
		require.NoError(t, sftpClient.Close())
	})

	t.Run("nologin_account_is_refused", func(t *testing.T) {
		conn, err := dial(nologinUser)
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
		require.Error(t, err, "SFTP must be refused for %s, whose shell is not a login shell", nologinUser)
	})
}

// createLoginTestUser returns a non-root account with a real login shell, creating a throwaway
// one if needed so the su/executor privilege-drop path has somewhere to switch to. It supports
// both shadow-utils (useradd/userdel) and busybox (adduser/deluser, Alpine's default), since the
// privileged suite runs on both a glibc CI container and Alpine locally.
func createLoginTestUser(t *testing.T) string {
	t.Helper()

	const username = "nb-sftp-control-test"

	if _, err := user.Lookup(username); err == nil {
		return username
	}

	shell := "/bin/sh"

	if _, err := exec.LookPath("useradd"); err == nil {
		out, err := exec.Command("useradd", "-M", "-s", shell, username).CombinedOutput()
		if err != nil {
			t.Skipf("create login test user with useradd: %v: %s", err, out)
		}
		t.Cleanup(func() {
			if out, err := exec.Command("userdel", username).CombinedOutput(); err != nil {
				t.Logf("remove login test user: %v: %s", err, out)
			}
		})
		return username
	}

	if _, err := exec.LookPath("adduser"); err == nil {
		out, err := exec.Command("adduser", "-D", "-H", "-s", shell, username).CombinedOutput()
		if err != nil {
			t.Skipf("create login test user with adduser: %v: %s", err, out)
		}
		t.Cleanup(func() {
			if out, err := exec.Command("deluser", username).CombinedOutput(); err != nil {
				t.Logf("remove login test user: %v: %s", err, out)
			}
		})
		return username
	}

	t.Skip("no useradd or adduser available to create a login test user")
	return ""
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
