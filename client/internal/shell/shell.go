package shell

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	defaultUnixShell = "/bin/sh"

	pwshExe       = "pwsh.exe" // #nosec G101 - This is not a credential, just executable name
	powershellExe = "powershell.exe"
)

// GetUserShell returns the appropriate shell for the given user ID.
// Handles all platform-specific logic and fallbacks consistently.
func GetUserShell(userID string) string {
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

// getUnixUserShell returns the shell for Unix-like systems.
// Tries /etc/passwd first (fast, no subprocess), falls back to getent for NSS users.
func getUnixUserShell(userID string) string {
	if shell := getShellFromPasswd(userID); shell != "" {
		return shell
	}

	if shell := GetShellFromGetent(userID); shell != "" {
		return shell
	}

	if shell := os.Getenv("SHELL"); shell != "" {
		return shell
	}

	return defaultUnixShell
}

// getShellFromPasswd reads the shell from /etc/passwd for the given user ID.
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

// PrepareUserEnv prepares environment variables for user execution.
func PrepareUserEnv(user *user.User, shell string) []string {
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

// AcceptEnv checks if an environment variable from an SSH client should be accepted.
// This is a whitelist of variables that SSH clients can send to the server.
func AcceptEnv(envVar string) bool {
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
