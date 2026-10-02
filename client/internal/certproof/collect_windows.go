package certproof

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const helperTimeout = 30 * time.Second

// CollectProofs answers the certificate challenges in checks from every store this
// machine can reach. The service reads the local machine store itself, where AD and
// Intune enrol device certificates, and reaches the signed-in user's store by launching
// a helper with that session's token. A machine at the sign-in screen therefore proves
// device certificates alone.
func CollectProofs(ctx context.Context, checks []*proto.Checks, peerKey []byte, cfg Config) []certposture.Proof {
	challenges := certificateChallenges(checks)
	if len(challenges) == 0 {
		logNoChallenges(checks)
		return nil
	}

	proofs := CollectChallenges(ctx, DefaultStore(), challenges, peerKey)

	// The helper already runs as the signed-in user, and an ordinary process has no
	// right to a session token, so only the service goes looking for one.
	if !runningAsLocalSystem() {
		return proofs
	}

	userProofs, err := collectAsDesktopUser(ctx, cfg.ProfileOwner, challenges, peerKey)
	if err != nil {
		log.Debugf("certificate posture: user certificate store unavailable: %v", err)
	}
	return mergeProofs(proofs, userProofs)
}

// UserContext identifies the session whose store a collection would include: a session
// of the profile owner, or empty when no user store would be asked. A change means a
// collection made earlier no longer reflects what this machine can prove.
func UserContext(cfg Config) string {
	if !runningAsLocalSystem() {
		return ""
	}
	user, ok := CurrentDesktopUser(cfg.ProfileOwner)
	if !ok {
		return ""
	}
	defer user.Close()
	return fmt.Sprintf("%d:%s", user.Session, user.Name)
}

// helperStore is the store the helper reads. It runs as the signed-in user, so it wants
// that user's store rather than the machine store the service already read.
func helperStore() Store {
	return NewUserStore()
}

// collectAsDesktopUser runs the helper inside the interactive session of the signed-in
// user. Unlike a keychain on macOS, a Windows service can assume a user identity
// directly, so the session token goes straight into the child process.
func collectAsDesktopUser(ctx context.Context, owner string, challenges []*proto.CertificateChallenge, peerKey []byte) ([]certposture.Proof, error) {
	user, ok := CurrentDesktopUser(owner)
	if !ok {
		return nil, nil
	}
	defer user.Close()

	binary, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve own binary: %w", err)
	}

	// The user's own environment, not the service's: the service environment may carry
	// secrets such as a setup key that the signed-in user must not be able to read.
	env, err := user.Token.Environ(false)
	if err != nil {
		return nil, fmt.Errorf("build environment of %s: %w", user.Name, err)
	}

	ctx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, "posture", "cert-proof")
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:         syscall.Token(user.Token),
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}

	log.Debugf("certificate posture: asking session %d to answer %d challenges", user.Session, len(challenges))
	proofs, err := runHelperCmd(cmd, helperRequest(challenges, peerKey))
	if err != nil {
		return nil, fmt.Errorf("run helper in session %d: %w", user.Session, err)
	}
	log.Debugf("certificate posture: session %d returned %d proofs", user.Session, len(proofs))
	return proofs, nil
}
