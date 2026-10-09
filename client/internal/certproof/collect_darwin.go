package certproof

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

	payload, err := json.Marshal(helperRequest(challenges, peerKey))
	if err != nil {
		return nil, fmt.Errorf("encode helper request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()

	uid := strconv.FormatUint(uint64(user.UID), 10)
	cmd := exec.CommandContext(ctx, "launchctl", "asuser", uid, "sudo", "-u", user.Name, "-H", binary, "posture", "cert-proof")
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Infof("certificate posture: asking the desktop session of %q (uid %s) to answer %d challenges", user.Name, uid, len(challenges))
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run helper as %s: %w: %s", user.Name, err, strings.TrimSpace(stderr.String()))
	}

	var resp HelperResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("decode helper response: %w", err)
	}
	log.Infof("certificate posture: desktop session of %q returned %d proofs", user.Name, len(resp.Proofs))
	return resp.Proofs, nil
}

// helperStore is the store the helper reads. On macOS the keychain search list of the
// user's own session already is that user's keychain, so the platform default is right.
func helperStore() Store {
	return DefaultStore()
}
