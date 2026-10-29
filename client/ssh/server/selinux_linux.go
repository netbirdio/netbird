//go:build linux

package server

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/netbirdio/netbird/client/internal/getent"
	log "github.com/sirupsen/logrus"
)

const (
	selinuxEnforcePath = "/sys/fs/selinux/enforce"
	selinuxUserPath    = "/sys/fs/selinux/user"
	selinuxConfigPath  = "/etc/selinux/config"
	selinuxRootDir     = "/etc/selinux"
	selinuxExecAttr    = "/proc/thread-self/attr/exec"

	defaultSELinuxType = "targeted"
	defaultSEUser      = "__default__"
	unconfinedSEUser   = "unconfined_u"

	// sshdRoleType is the role and type sshd logs users in from. The default login contexts
	// are looked up as if sshd had accepted the session, so a NetBird session gets what an
	// sshd session of the same user would.
	sshdRoleType = "system_r:sshd_t"

	// maxContextReply bounds the reply read from the kernel's compute_user interface.
	maxContextReply = 64 * 1024
)

// selinuxLookup resolves the context a user's session runs in from the loaded policy
// and its configuration files.
type selinuxLookup struct {
	rootDir string
	// reachable returns the contexts the policy lets the SELinux user be logged in as
	// when starting from the given context.
	reachable func(from, seuser string) ([]string, error)
}

func newSELinuxLookup() *selinuxLookup {
	return &selinuxLookup{rootDir: selinuxRootDir, reachable: kernelReachableContexts}
}

// selinuxEnabled reports whether the running kernel has SELinux enabled.
func selinuxEnabled() bool {
	_, err := os.Stat(selinuxEnforcePath)
	return err == nil
}

// sessionExecContext returns the context a session of username has to start in, or an
// empty string when there is nothing to set: SELinux is disabled, the host has no policy
// files (a container on an SELinux host), or the lookup failed while SELinux is permissive,
// where sshd also lets the login continue. While enforcing, a failed lookup is an error.
func sessionExecContext(username string, groups []string) (string, error) {
	if !selinuxEnabled() {
		return "", nil
	}

	l := newSELinuxLookup()
	if !l.hasPolicy() {
		log.Debugf("SELinux is enabled but %s has no policy files, not setting a session context", l.rootDir)
		return "", nil
	}

	ctx, err := l.defaultContext(username, groups)
	if err != nil && !selinuxEnforcing() {
		log.Warnf("resolve SELinux session context of %s, continuing as SELinux is permissive: %v", username, err)
		return "", nil
	}
	return ctx, err
}

// needsSessionContext reports whether sessions of username must be started through the
// helper that sets their SELinux context. su cannot do it, because its PAM stack carries no
// pam_selinux, so it is only left in place for users mapped to the unconfined SELinux user,
// where the daemon's own transition gives the same result. A user that cannot be mapped is
// treated as needing the helper, which refuses the session if the context cannot be resolved.
func needsSessionContext(username string, groups []string) bool {
	if !selinuxEnabled() {
		return false
	}
	l := newSELinuxLookup()
	return l.hasPolicy() && l.isConfined(username, groups)
}

// isConfined reports whether username maps to a SELinux user other than the unconfined one,
// or to none that can be determined.
func (l *selinuxLookup) isConfined(username string, groups []string) bool {
	seuser, _, err := l.seuser(username, groups)
	return err != nil || seuser != unconfinedSEUser
}

// localGroupNames returns the names of the groups u belongs to, for the group entries in
// seusers. Groups that cannot be resolved are left out.
func localGroupNames(u *user.User) []string {
	ids, err := getent.GroupIDs(u)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		if g, err := user.LookupGroupId(id); err == nil {
			names = append(names, g.Name)
		}
	}
	return names
}

// ExecInSessionContext drops privileges and replaces the current process with argv, started
// in the SELinux context of the target user. It reports false without doing anything when
// there is no context to set, and returns only if the context cannot be resolved or the exec
// fails. Serving in process after the drop would leave the session in the helper's own
// domain, which has none of the user's file access.
func (pd *PrivilegeDropper) ExecInSessionContext(config ExecutorConfig, argv []string) (bool, error) {
	// The exec attribute is per thread; the process is replaced, so the lock is not released.
	runtime.LockOSThread()

	sessionContext, err := sessionExecContext(config.Username, groupNames(config.Groups))
	if err != nil {
		return false, fmt.Errorf("resolve session context: %w", err)
	}
	if sessionContext == "" {
		runtime.UnlockOSThread()
		return false, nil
	}

	if err := pd.DropPrivileges(config.UID, config.GID, config.Groups); err != nil {
		return false, fmt.Errorf("drop privileges: %w", err)
	}
	if err := setExecContext(sessionContext); err != nil {
		return false, fmt.Errorf("set session context: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("find executable: %w", err)
	}
	return true, syscall.Exec(exe, argv, os.Environ())
}

// selinuxEnforcing reports whether SELinux denies, rather than only logs. An enforce file
// that cannot be read counts as enforcing, so a failure never loosens the check.
func selinuxEnforcing() bool {
	return readEnforcing(selinuxEnforcePath)
}

func readEnforcing(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(data)) != "0"
}

// setExecContext sets the context the next exec of the calling thread starts in. The
// attribute is per thread, so the caller must stay on one locked OS thread from this call
// to the fork that starts the session.
func setExecContext(ctx string) error {
	return writeExecContext(selinuxExecAttr, ctx)
}

func writeExecContext(path, ctx string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open exec context attribute: %w", err)
	}
	if _, err := f.WriteString(ctx); err != nil {
		_ = f.Close()
		return fmt.Errorf("write exec context %q: %w", ctx, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close exec context attribute: %w", err)
	}
	return nil
}

// hasPolicy reports whether the policy files that map users to SELinux users exist.
func (l *selinuxLookup) hasPolicy() bool {
	_, err := os.Stat(filepath.Join(l.policyDir(), "seusers"))
	return err == nil
}

func (l *selinuxLookup) policyDir() string {
	return filepath.Join(l.rootDir, policyType(l.rootDir))
}

// policyType reads SELINUXTYPE from the SELinux config, defaulting to targeted.
func policyType(rootDir string) string {
	f, err := os.Open(filepath.Join(rootDir, "config"))
	if err != nil {
		return defaultSELinuxType
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if ok && strings.TrimSpace(key) == "SELINUXTYPE" && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return defaultSELinuxType
}

// defaultContext picks the context a login of username gets: the first context in the
// preference order that the policy lets the user's SELinux identity reach.
func (l *selinuxLookup) defaultContext(username string, groups []string) (string, error) {
	seuser, level, err := l.seuser(username, groups)
	if err != nil {
		return "", fmt.Errorf("look up SELinux user of %q: %w", username, err)
	}

	from := "system_u:" + sshdRoleType
	if level != "" {
		from += ":" + level
	}

	reachable, err := l.reachable(from, seuser)
	if err != nil {
		return "", fmt.Errorf("compute contexts of SELinux user %q: %w", seuser, err)
	}

	for _, pref := range l.preferences(seuser) {
		for _, candidate := range reachable {
			if roleType(candidate) == pref {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("no default context for SELinux user %q among %d reachable", seuser, len(reachable))
}

// seuser maps a login name to its SELinux user and level: an exact entry first, then an
// entry for one of the user's groups, then the default.
func (l *selinuxLookup) seuser(username string, groups []string) (string, string, error) {
	entries, err := readColonFile(filepath.Join(l.policyDir(), "seusers"))
	if err != nil {
		return "", "", err
	}

	var groupHit, defaultHit []string
	for _, e := range entries {
		if len(e) < 2 {
			continue
		}
		switch {
		case e[0] == username:
			return e[1], levelOf(e), nil
		case strings.HasPrefix(e[0], "%") && groupHit == nil && slices.Contains(groups, e[0][1:]):
			groupHit = e
		case e[0] == defaultSEUser:
			defaultHit = e
		}
	}
	if groupHit != nil {
		return groupHit[1], levelOf(groupHit), nil
	}
	if defaultHit != nil {
		return defaultHit[1], levelOf(defaultHit), nil
	}
	return "", "", errors.New("no matching entry in seusers")
}

// preferences returns the role:type pairs a login may start in, most preferred first. The
// per-user file takes precedence over the default contexts.
func (l *selinuxLookup) preferences(seuser string) []string {
	var prefs []string
	for _, path := range []string{
		filepath.Join(l.policyDir(), "contexts", "users", seuser),
		filepath.Join(l.policyDir(), "contexts", "default_contexts"),
	} {
		prefs = append(prefs, loginPreferences(path)...)
	}
	return prefs
}

// loginPreferences reads the preferred role:type pairs listed for logins from sshd in a
// default_contexts style file. Each line starts with the originating role:type, followed
// by the contexts to try.
func loginPreferences(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var prefs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if roleType(fields[0]) != sshdRoleType {
			continue
		}
		for _, entry := range fields[1:] {
			prefs = append(prefs, roleType(entry))
		}
	}
	return prefs
}

// roleType returns the role:type pair of a context, or of a role:type[:level] entry.
func roleType(ctx string) string {
	parts := strings.Split(ctx, ":")
	switch {
	case len(parts) >= 4:
		return parts[1] + ":" + parts[2]
	case len(parts) >= 2:
		return parts[0] + ":" + parts[1]
	default:
		return ctx
	}
}

func levelOf(entry []string) string {
	if len(entry) < 3 {
		return ""
	}
	return strings.Join(entry[2:], ":")
}

// readColonFile reads a file of colon separated records, skipping comments and blank lines.
func readColonFile(path string) ([][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var records [][]string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		records = append(records, strings.Split(line, ":"))
	}
	return records, scanner.Err()
}

// kernelReachableContexts asks the kernel which contexts the policy allows the SELinux user
// to be logged in as from the given context. The reply is a NUL separated count followed
// by that many contexts.
func kernelReachableContexts(from, seuser string) ([]string, error) {
	f, err := os.OpenFile(selinuxUserPath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open compute_user interface: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.WriteString(from + " " + seuser + "\x00"); err != nil {
		return nil, fmt.Errorf("query compute_user interface: %w", err)
	}

	buf := make([]byte, maxContextReply)
	n, err := f.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read compute_user reply: %w", err)
	}
	return parseContextReply(buf[:n])
}

func parseContextReply(reply []byte) ([]string, error) {
	fields := strings.Split(strings.TrimRight(string(reply), "\x00"), "\x00")
	if len(fields) == 0 || fields[0] == "" {
		return nil, errors.New("empty compute_user reply")
	}

	var count int
	if _, err := fmt.Sscanf(fields[0], "%d", &count); err != nil {
		return nil, fmt.Errorf("parse compute_user count %q: %w", fields[0], err)
	}
	contexts := fields[1:]
	if count != len(contexts) {
		return nil, fmt.Errorf("compute_user returned %d contexts, expected %d", len(contexts), count)
	}
	return contexts, nil
}
