package certproof

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// HelperRequest is the work the daemon hands to a helper running in a user session. The
// peer key binds every signature to this machine, so a proof cannot be replayed onto
// another peer.
type HelperRequest struct {
	PeerKey    []byte            `json:"peerKey"`
	Challenges []HelperChallenge `json:"challenges"`
}

// HelperChallenge is one certificate challenge in the form the helper needs.
type HelperChallenge struct {
	Nonce          []byte   `json:"nonce"`
	CACertificates []string `json:"caCertificates"`
}

// HelperResponse carries the proofs the helper produced from its own keychain.
type HelperResponse struct {
	Proofs []certposture.Proof `json:"proofs"`
}

// RunHelper answers the challenges on in from the store of the user running this
// process and writes the proofs to out. It is the child half of the console user
// lookup: the daemon cannot read a login keychain, so it launches this in the user's
// session instead. Only the signature crosses back, never the private key.
func RunHelper(ctx context.Context, in io.Reader, out io.Writer) error {
	return runHelper(ctx, helperStore(), in, out)
}

func runHelper(ctx context.Context, store Store, in io.Reader, out io.Writer) error {
	var req HelperRequest
	if err := json.NewDecoder(in).Decode(&req); err != nil {
		return fmt.Errorf("decode helper request: %w", err)
	}

	challenges := make([]*proto.CertificateChallenge, 0, len(req.Challenges))
	for _, challenge := range req.Challenges {
		challenges = append(challenges, &proto.CertificateChallenge{
			Nonce:          challenge.Nonce,
			CaCertificates: challenge.CACertificates,
		})
	}

	var proofs []certposture.Proof
	if len(challenges) > 0 {
		proofs = CollectChallenges(ctx, store, challenges, req.PeerKey)
	}
	log.Infof("certificate posture helper: answering %d challenges with %d proofs", len(challenges), len(proofs))

	if err := json.NewEncoder(out).Encode(HelperResponse{Proofs: proofs}); err != nil {
		return fmt.Errorf("encode helper response: %w", err)
	}
	return nil
}
