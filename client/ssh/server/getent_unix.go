//go:build !windows

package server

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

// getShellFromGetent gets a user's login shell via getent by UID.
// This is needed even with CGO because getShellFromPasswd reads /etc/passwd
// directly and won't find NSS-provided users there.
func getShellFromGetent(userID string) string {
	_, shell, err := runGetent(userID)
	if err != nil {
		return ""
	}
	return shell
}

// runGetent executes `getent passwd <query>` and returns the user and login shell.
func runGetent(query string) (*user.User, string, error) {
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

// parseGetentPasswd parses getent passwd output: "name:x:uid:gid:gecos:home:shell"
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

// validateGetentInput checks that the input is safe to pass to getent or id.
// Allows POSIX usernames, numeric UIDs, and common NSS extensions
// (@ for Kerberos, $ for Samba, + for NIS compat).
func validateGetentInput(input string) bool {
	maxLen := 32
	if runtime.GOOS == "linux" {
		maxLen = 256
	}

	if len(input) == 0 || len(input) > maxLen {
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
