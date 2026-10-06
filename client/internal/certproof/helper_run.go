package certproof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/management/certposture"
)

const (
	maxHelperStdout = 1 << 20
	maxHelperStderr = 4 << 10
)

var errHelperOutputTooLarge = errors.New("helper output exceeds the size limit")

// runHelperCmd feeds req to the helper process cmd and returns the proofs it answered.
// The helper runs as an unprivileged user who can control its output, so both streams
// are capped and only proofs for a nonce req asked about are kept, one per challenge.
func runHelperCmd(cmd *exec.Cmd, req HelperRequest) ([]certposture.Proof, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode helper request: %w", err)
	}

	stdout := &cappedBuffer{limit: maxHelperStdout}
	stderr := &cappedBuffer{limit: maxHelperStderr}
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	logHelperStderr(stderr.String())
	if stdout.truncated {
		return nil, errHelperOutputTooLarge
	}

	var resp HelperResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("decode helper response: %w", err)
	}
	return requestedProofs(req, resp.Proofs), nil
}

// logHelperStderr records what a helper that succeeded wrote to stderr, such as a user
// certificate it could not sign with, which is otherwise only visible in the user's
// session. Each line is quoted because the helper's user controls its content.
func logHelperStderr(stderr string) {
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			log.Debugf("certificate posture helper: %q", line)
		}
	}
}

// requestedProofs keeps the proofs whose nonce belongs to one of req's challenges, at
// most as many as req has challenges.
func requestedProofs(req HelperRequest, proofs []certposture.Proof) []certposture.Proof {
	var kept []certposture.Proof
	for _, proof := range proofs {
		if len(kept) == len(req.Challenges) {
			break
		}
		if !req.asked(proof.Nonce) {
			log.Debugf("certificate posture: dropping helper proof for a nonce that was not requested")
			continue
		}
		kept = append(kept, proof)
	}
	return kept
}

func (r HelperRequest) asked(nonce []byte) bool {
	for _, challenge := range r.Challenges {
		if len(challenge.Nonce) > 0 && bytes.Equal(challenge.Nonce, nonce) {
			return true
		}
	}
	return false
}

// cappedBuffer keeps the first limit bytes written to it and discards the rest, so a
// misbehaving child cannot grow the parent's memory without bound. The buffer is a
// named field rather than embedded: an embedded bytes.Buffer would promote ReadFrom,
// which io.Copy prefers over Write, bypassing the cap.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.buf.Len(); room < len(p) {
		b.truncated = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *cappedBuffer) Bytes() []byte {
	return b.buf.Bytes()
}

func (b *cappedBuffer) String() string {
	return b.buf.String()
}
