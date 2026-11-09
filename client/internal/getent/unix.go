//go:build !windows

package getent

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const commandTimeout = 5 * time.Second

// groupFile lists which accounts are in which group, for hosts where the
// getent command is not available (macOS ships without it).
const groupFile = "/etc/group"

// UserShell returns the login shell getent reports for the user with this UID.
// It reaches shells that /etc/passwd does not list, because getent resolves
// through the host's NSS stack.
func UserShell(uid string) (string, error) {
	_, shell, err := passwdLookup(uid)
	if err != nil {
		return "", err
	}
	return shell, nil
}

// GroupMembers returns the names of the group's members: from getent, which
// resolves through NSS, or from /etc/group where getent is not available. A
// group neither source describes is an error; an empty member list is not,
// since accounts with the group as their primary one are not listed in it.
func GroupMembers(name string) ([]string, error) {
	_, members, err := groupLookup(name)
	if err == nil {
		return members, nil
	}
	log.Debugf("getent cannot list group %q, reading %s: %v", name, groupFile, err)
	return groupMembersFromFile(groupFile, name)
}

// passwdLookup executes `getent passwd <query>`, where query is a username or
// UID, and returns the user and login shell.
func passwdLookup(query string) (*user.User, string, error) {
	out, err := run("passwd", query)
	if err != nil {
		return nil, "", err
	}
	return parsePasswd(string(out))
}

// groupLookup executes `getent group <query>`, where query is a group name or
// GID, and returns the group and its member names.
func groupLookup(query string) (*user.Group, []string, error) {
	out, err := run("group", query)
	if err != nil {
		return nil, nil, err
	}
	return parseGroup(string(out))
}

// run executes `getent <database> <key>` with a timeout.
func run(database, key string) ([]byte, error) {
	if !validateInput(key) {
		return nil, fmt.Errorf("invalid getent input: %q", key)
	}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "getent", database, key).Output()
	if err != nil {
		return nil, fmt.Errorf("getent %s %s: %w", database, key, err)
	}
	return out, nil
}

// parsePasswd parses getent passwd output: "name:x:uid:gid:gecos:home:shell"
func parsePasswd(output string) (*user.User, string, error) {
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

// parseGroup parses getent group output: "name:x:gid:member,member"
func parseGroup(output string) (*user.Group, []string, error) {
	fields := strings.SplitN(strings.TrimSpace(output), ":", 4)
	if len(fields) < 3 {
		return nil, nil, fmt.Errorf("unexpected getent output (need 3+ fields): %q", output)
	}

	if fields[0] == "" || fields[2] == "" {
		return nil, nil, fmt.Errorf("missing required fields in getent output: %q", output)
	}

	var members []string
	if len(fields) >= 4 {
		members = splitMembers(fields[3])
	}
	return &user.Group{Name: fields[0], Gid: fields[2]}, members, nil
}

func splitMembers(list string) []string {
	var members []string
	for member := range strings.SplitSeq(list, ",") {
		if member != "" {
			members = append(members, member)
		}
	}
	return members
}

// groupMembersFromFile finds the group's member list in a file of /etc/group's
// format. A group the file does not describe, because it comes from LDAP or
// another NSS source, is an error rather than an empty list.
func groupMembersFromFile(path, name string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Debugf("close %s: %v", path, err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// name:password:gid:member,member
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 4 || fields[0] != name {
			continue
		}
		return splitMembers(fields[3]), nil
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return nil, fmt.Errorf("%s does not describe group %q", path, name)
}

// validateInput checks that the input is safe to pass to getent or id.
// Allows POSIX usernames, numeric IDs, and common NSS extensions
// (@ for Kerberos, $ for Samba, + for NIS compat). A leading hyphen is
// rejected so the input can never be parsed as a command-line flag.
func validateInput(input string) bool {
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
		if isAllowedChar(r) {
			continue
		}
		return false
	}
	return true
}

func isAllowedChar(r rune) bool {
	if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
		return true
	}
	switch r {
	case '.', '_', '-', '@', '+', '$':
		return true
	}
	return false
}

// idGroups runs `id -G <username>` and returns the space-separated group IDs.
func idGroups(username string) ([]string, error) {
	if !validateInput(username) {
		return nil, fmt.Errorf("invalid username for id command: %q", username)
	}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
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
