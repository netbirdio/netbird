package server

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
)

const (
	defaultUnixShell = "/bin/sh"

	pwshExe       = "pwsh.exe" // #nosec G101 - This is not a credential, just executable name
	powershellExe = "powershell.exe"
)

// getUserShell returns the appropriate shell for the given user ID
// Handles all platform-specific logic and fallbacks consistently
func getUserShell(userID string) string {
	switch runtime.GOOS {
	case "windows":
		return getWindowsUserShell()
	default:
		return getUnixUserShell(userID)
	}
}

// getWindowsUserShell returns the best shell for Windows users.
// We intentionally do not support cmd.exe or COMSPEC fallbacks to avoid command injection
// vulnerabilities that arise from cmd.exe's complex command line parsing and special characters.
// PowerShell provides safer argument handling and is available on all modern Windows systems.
// Order: pwsh.exe -> powershell.exe
func getWindowsUserShell() string {
	if path, err := exec.LookPath(pwshExe); err == nil {
		return path
	}
	if path, err := exec.LookPath(powershellExe); err == nil {
		return path
	}

	return `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
}

// getUnixUserShell returns the shell for Unix-like systems
func getUnixUserShell(userID string) string {
	shell := getShellFromPasswd(userID)
	if shell != "" {
		return shell
	}

	if shell := os.Getenv("SHELL"); shell != "" {
		return shell
	}

	return defaultUnixShell
}

// getShellFromPasswd reads the shell from /etc/passwd for the given user ID
func getShellFromPasswd(userID string) string {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Warnf("close /etc/passwd file: %v", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}

		// field 2 is UID
		if fields[2] == userID {
			shell := strings.TrimSpace(fields[6])
			return shell
		}
	}

	if err := scanner.Err(); err != nil {
		log.Warnf("error reading /etc/passwd: %v", err)
	}

	return ""
}

// prepareUserEnv prepares environment variables for user execution
func prepareUserEnv(user *user.User, shell string) []string {
	pathValue := "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
	if runtime.GOOS == "windows" {
		pathValue = `C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0`
	}

	return []string{
		fmt.Sprint("SHELL=" + shell),
		fmt.Sprint("USER=" + user.Username),
		fmt.Sprint("LOGNAME=" + user.Username),
		fmt.Sprint("HOME=" + user.HomeDir),
		"PATH=" + pathValue,
	}
}

// acceptEnv checks if environment variable from SSH client should be accepted
// This is a whitelist of variables that SSH clients can send to the server
func acceptEnv(envVar string) bool {
	varName := envVar
	if idx := strings.Index(envVar, "="); idx != -1 {
		varName = envVar[:idx]
	}

	exactMatches := []string{
		"LANG",
		"LANGUAGE",
		"TERM",
		"COLORTERM",
		"EDITOR",
		"VISUAL",
		"PAGER",
		"LESS",
		"LESSCHARSET",
		"TZ",
	}

	prefixMatches := []string{
		"LC_",
	}

	for _, exact := range exactMatches {
		if varName == exact {
			return true
		}
	}

	for _, prefix := range prefixMatches {
		if strings.HasPrefix(varName, prefix) {
			return true
		}
	}

	return false
}

// prepareSSHEnv prepares SSH protocol-specific environment variables
// These variables provide information about the SSH connection itself
func prepareSSHEnv(session ssh.Session) []string {
	remoteAddr := session.RemoteAddr()
	localAddr := session.LocalAddr()

	remoteHost, remotePort, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		remoteHost = remoteAddr.String()
		remotePort = "0"
	}

	localHost, localPort, err := net.SplitHostPort(localAddr.String())
	if err != nil {
		localHost = localAddr.String()
		localPort = strconv.Itoa(InternalSSHPort)
	}

	return []string{
		// SSH_CLIENT format: "client_ip client_port server_port"
		fmt.Sprintf("SSH_CLIENT=%s %s %s", remoteHost, remotePort, localPort),
		// SSH_CONNECTION format: "client_ip client_port server_ip server_port"
		fmt.Sprintf("SSH_CONNECTION=%s %s %s %s", remoteHost, remotePort, localHost, localPort),
	}
}
