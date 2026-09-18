package certproof

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
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
func CollectProofs(ctx context.Context, checks []*proto.Checks, peerKey []byte) []certposture.Proof {
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

	userProofs, err := collectAsDesktopUser(ctx, challenges, peerKey)
	if err != nil {
		log.Infof("certificate posture: user certificate store unavailable: %v", err)
	}
	return mergeProofs(proofs, userProofs)
}

// helperStore is the store the helper reads. It runs as the signed-in user, so it wants
// that user's store rather than the machine store the service already read.
func helperStore() Store {
	return NewUserStore()
}

// collectAsDesktopUser runs the helper inside the interactive session of the signed-in
// user. Unlike a keychain on macOS, a Windows service can assume a user identity
// directly, so the session token goes straight into the child process.
func collectAsDesktopUser(ctx context.Context, challenges []*proto.CertificateChallenge, peerKey []byte) ([]certposture.Proof, error) {
	user, ok := CurrentDesktopUser()
	if !ok {
		return nil, nil
	}
	defer user.Close()

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

	cmd := exec.CommandContext(ctx, binary, "posture", "cert-proof")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:         syscall.Token(user.Token),
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Infof("certificate posture: asking the session of %q (session %d) to answer %d challenges", user.Name, user.Session, len(challenges))
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run helper as %s: %w: %s", user.Name, err, strings.TrimSpace(stderr.String()))
	}

	var resp HelperResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("decode helper response: %w", err)
	}
	log.Infof("certificate posture: session of %q returned %d proofs", user.Name, len(resp.Proofs))
	return resp.Proofs, nil
}
