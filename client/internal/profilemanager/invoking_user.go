package profilemanager

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	log "github.com/sirupsen/logrus"
)

const envSudoUser = "SUDO_USER"

var (
	geteuid    = os.Geteuid
	lookupUser = user.Lookup
)

// InvokingUser returns the user a CLI invocation acts for. Under sudo that is
// the user who ran sudo, not root: privileged flags force commands through
// sudo, and resolving profiles as root would silently switch the daemon to
// root's (default) profile instead of the invoking user's. Privilege decisions
// are not made here — those stay on the kernel credentials of the daemon
// connection, which SUDO_USER (a plain environment variable) can never
// influence; a forged value only selects a profile root could select anyway.
func InvokingUser() (*user.User, error) {
	if u, ok := sudoInvokingUser(); ok {
		return u, nil
	}
	return user.Current()
}

// IsPlainRoot reports that the process runs as root with no usable sudo
// context: there is no invoking user to act for, so per-user resolution falls
// back to root's own (empty) state. Callers use it to refuse ambiguous
// operations instead of silently acting on the wrong profile.
func IsPlainRoot() bool {
	if geteuid() != 0 {
		return false
	}
	_, ok := sudoInvokingUser()
	return !ok
}

// sudoInvokingUser resolves SUDO_USER when the process runs as root under
// sudo. Returns false whenever the sudo context is absent or unusable, in
// which case callers fall back to the process user.
func sudoInvokingUser() (*user.User, bool) {
	if !sudoActive() {
		return nil, false
	}
	name := os.Getenv(envSudoUser)
	u, err := lookupUser(name)
	if err != nil {
		log.Warnf("sudo invoking user %q lookup: %v; acting as root", name, err)
		return nil, false
	}
	return u, true
}

// sudoActive reports a sudo context from the environment alone: write-skip
// decisions key off it so a transient user lookup failure can never flip a
// run from read-only to writing root-owned files into the user's directory.
func sudoActive() bool {
	if geteuid() != 0 {
		return false
	}
	name := os.Getenv(envSudoUser)
	return name != "" && name != "root"
}

// userBaseConfigDir mirrors os.UserConfigDir for a user other than the process
// owner. Environment overrides (XDG_CONFIG_HOME) cannot be honoured here: under
// sudo the environment is root's, not the invoking user's.
func userBaseConfigDir(u *user.User) (string, error) {
	if u.HomeDir == "" {
		return "", fmt.Errorf("user %s has no home directory", u.Username)
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(u.HomeDir, "Library", "Application Support"), nil
	}
	return filepath.Join(u.HomeDir, ".config"), nil
}
