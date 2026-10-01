package certproof

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const helperTimeout = 30 * time.Second

// CollectProofs answers the certificate challenges in checks from every store this Mac
// can reach. The root daemon reads the System keychain itself, which is where MDM
// installs device identities, and reaches the console user's login keychain only by
// launching a helper into that user's session. A Mac sitting at the login window
// therefore yields device proofs alone.
func CollectProofs(ctx context.Context, checks []*proto.Checks, peerKey []byte, _ Config) []certposture.Proof {
	challenges := certificateChallenges(checks)
	if len(challenges) == 0 {
		logNoChallenges(checks)
		return nil
	}

	// A helper already runs inside the user's session, so it reads its own keychain
	// directly and must never launch another one.
	if os.Geteuid() != 0 {
		return CollectChallenges(ctx, DefaultStore(), challenges, peerKey)
	}

	proofs := CollectChallenges(ctx, DefaultStore(), challenges, peerKey)

	userProofs, err := collectAsConsoleUser(ctx, challenges, peerKey)
	if err != nil {
		log.Infof("certificate posture: console user keychain unavailable: %v", err)
	}
	return mergeProofs(proofs, userProofs)
}

// collectAsConsoleUser runs the helper inside the desktop session of the logged-in
// user. Dropping to their uid is not enough: keychain access is an XPC call to a
// per-session securityd, so the helper has to enter their Mach bootstrap namespace,
// which is what launchctl asuser does.
func collectAsConsoleUser(ctx context.Context, challenges []*proto.CertificateChallenge, peerKey []byte) ([]certposture.Proof, error) {
	user, ok := CurrentConsoleUser()
	if !ok {
		return nil, nil
	}

	binary, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve own binary: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()

	// Absolute paths, because the daemon's PATH is configurable through the service
	// environment, and sudo selects the user by uid so the name never has to round-trip.
	uid := strconv.FormatUint(uint64(user.UID), 10)
	cmd := exec.CommandContext(ctx, "/bin/launchctl", "asuser", uid, "/usr/bin/sudo", "-u", "#"+uid, "-H", binary, "posture", "cert-proof")

	log.Debugf("certificate posture: asking the desktop session of uid %s to answer %d challenges", uid, len(challenges))
	proofs, err := runHelperCmd(cmd, helperRequest(challenges, peerKey))
	if err != nil {
		return nil, fmt.Errorf("run helper as uid %s: %w", uid, err)
	}
	log.Debugf("certificate posture: desktop session of uid %s returned %d proofs", uid, len(proofs))
	return proofs, nil
}

// helperStore is the store the helper reads. On macOS the keychain search list of the
// user's own session already is that user's keychain, so the platform default is right.
func helperStore() Store {
	return DefaultStore()
}
