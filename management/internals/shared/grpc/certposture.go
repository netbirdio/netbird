package grpc

import (
	"context"
	"crypto/sha256"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const certChallengeKeyDomain = "netbird-cert-challenge-key"

// certChallenger derives the nonce secret from the management WireGuard key so every
// instance sharing that key issues and verifies the same nonces without extra state.
func certChallenger(serverKey wgtypes.Key) *certposture.Challenger {
	h := sha256.New()
	h.Write([]byte(certChallengeKeyDomain))
	h.Write(serverKey[:])
	return certposture.NewChallenger(h.Sum(nil))
}

// stampCertificateChallenges fills the per-peer nonce into every certificate challenge
// right before the response is encrypted for that peer.
func stampCertificateChallenges(checks []*proto.Checks, peerKey, serverKey wgtypes.Key) {
	var nonce []byte
	for _, check := range checks {
		challenge := check.GetCertificateChallenge()
		if challenge == nil {
			continue
		}
		if nonce == nil {
			nonce = certChallenger(serverKey).Nonce(peerKey[:], time.Now())
		}
		challenge.Nonce = nonce
	}
}

// verifiedCertificates turns the peer's proofs into PEM chains for its meta. Possession
// (nonce + signature) is verified here; trust against a check's CAs is evaluated by the
// posture check itself. Any invalid proof rejects the whole set.
func (s *Server) verifiedCertificates(ctx context.Context, peerKey wgtypes.Key, proofs []*proto.CertificateProof) []string {
	if len(proofs) == 0 {
		return nil
	}
	serverKey, err := s.secretsManager.GetWGKey()
	if err != nil {
		log.WithContext(ctx).Warnf("skipping certificate proofs of peer %s: %v", peerKey, err)
		return nil
	}

	challenger := certChallenger(serverKey)
	now := time.Now()
	chains := make([]string, 0, len(proofs))
	for _, p := range proofs {
		chain, err := challenger.Verify(certposture.Proof{
			Nonce:     p.GetNonce(),
			Chain:     p.GetChain(),
			SigAlg:    p.GetSigAlg(),
			Signature: p.GetSignature(),
		}, peerKey[:], now)
		if err != nil {
			log.WithContext(ctx).Warnf("rejecting certificate proofs of peer %s: %v", peerKey, err)
			return nil
		}
		chains = append(chains, certposture.EncodeChainPEM(chain))
	}
	return chains
}
