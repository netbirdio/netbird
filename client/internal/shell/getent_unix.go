//go:build !windows

package shell

import (
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
)

const getentTimeout = 5 * time.Second

// GetShellFromGetent gets a user's login shell via getent by UID.
// This is needed even with CGO because getShellFromPasswd reads /etc/passwd
// directly and won't find NSS-provided users there.
func GetShellFromGetent(userID string) string {
	_, shell, err := runGetentPasswd(userID)
	if err != nil {
		return ""
	}
	return shell
}

// GetUserFromGetent returns the resolved user from either a uid or username,
// going through the host's NSS stack.
func GetUserFromGetent(query string) (*user.User, error) {
	u, _, err := runGetentPasswd(query)
	return u, err
}

// runGetentPasswd executes `getent passwd <query>` and returns the user and login shell.
func runGetentPasswd(query string) (*user.User, string, error) {
	if !validateGetentInput(query) {
		return nil, "", fmt.Errorf("invalid getent input: %q", query)
	}

	ctx, cancel := context.WithTimeout(context.Background(), getentTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "getent", "passwd", query).Output()
	if err != nil {
		return nil, "", fmt.Errorf("getent passwd %s: %w", query, err)
	}

	return parseGetentPasswd(string(out))
}

// runGetentGroup executes `getent group <query>` and returns the group.
func runGetentGroup(query string) (*user.Group, error) {
	if !validateGetentInput(query) {
		return nil, fmt.Errorf("invalid getent input: %q", query)
	}

	ctx, cancel := context.WithTimeout(context.Background(), getentTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "getent", "group", query).Output()
	if err != nil {
		return nil, fmt.Errorf("getent group %s: %w", query, err)
	}

	return parseGetentGroup(string(out))
}

// parseGetentPasswd parses getent passwd output: "name:x:uid:gid:gecos:home:shell".
func parseGetentPasswd(output string) (*user.User, string, error) {
	fields := strings.SplitN(strings.TrimSpace(output), ":", 8)
	if len(fields) < 6 {
		return nil, "", fmt.Errorf("unexpected getent output (need 6+ fields): %q", output)
	}

	if fields[0] == "" || fields[2] == "" || fields[3] == "" {
		return nil, "", fmt.Errorf("missing required fields in getent output: %q", output)
	}

	var shell string
	if len(fields) >= 7 {
		shell = fields[6]
	}

	return &user.User{
		Username: fields[0],
		Uid:      fields[2],
		Gid:      fields[3],
		Name:     fields[4],
		HomeDir:  fields[5],
	}, shell, nil
}

// parseGetentGroup parses getent group output: "group:x:gid:members".
func parseGetentGroup(output string) (*user.Group, error) {
	fields := strings.SplitN(strings.TrimSpace(output), ":", 8)
	if len(fields) < 4 {
		return nil, fmt.Errorf("unexpected getent output (need 4+ fields): %q", output)
	}

	if fields[0] == "" || fields[2] == "" {
		return nil, fmt.Errorf("missing required fields in getent output: %q", output)
	}

	return &user.Group{Gid: fields[2], Name: fields[0]}, nil
}

// validateGetentInput checks that the input is safe to pass to getent or id.
// Allows POSIX usernames, numeric UIDs, and common NSS extensions
// (@ for Kerberos, $ for Samba, + for NIS compat). A leading hyphen is
// rejected so the input can never be parsed as a command-line flag.
func validateGetentInput(input string) bool {
	maxLen := 32
	if runtime.GOOS == "linux" {
		maxLen = 256
	}

	if len(input) == 0 || len(input) > maxLen {
		return false
	}

	if input[0] == '-' {
		return false
	}

	for _, r := range input {
		if isAllowedGetentChar(r) {
			continue
		}
		return false
	}
	return true
}

func isAllowedGetentChar(r rune) bool {
	if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
		return true
	}
	switch r {
	case '.', '_', '-', '@', '+', '$':
		return true
	}
	return false
}

// runIdGroups runs `id -G <username>` and returns the space-separated group IDs.
func runIdGroups(username string) ([]string, error) {
	if !validateGetentInput(username) {
		return nil, fmt.Errorf("invalid username for id command: %q", username)
	}

	ctx, cancel := context.WithTimeout(context.Background(), getentTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "id", "-G", username).Output()
	if err != nil {
		return nil, fmt.Errorf("id -G %s: %w", username, err)
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, fmt.Errorf("id -G %s: empty output", username)
	}
	return strings.Fields(trimmed), nil
}
