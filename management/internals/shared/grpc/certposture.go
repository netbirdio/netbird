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

// newCertChallenger derives the nonce secret from the data store encryption key, which
// is generated once and written back to the configuration, so the same secret survives
// a restart and is shared by every instance reading that configuration. A nonce carries
// no state of its own, so one instance can only verify what another issued if both
// derive the same secret.
//
// The server's WireGuard key cannot be used for this: it is generated afresh in every
// process, so it would invalidate every outstanding nonce on restart and make each
// instance reject the others'. A peer meeting that rejects its whole proof set and
// loses the policies the certificate check gates until it signs again.
//
// Without an encryption key the secret falls back to the WireGuard key, which is still
// unpredictable but no longer persisted. It must stay unpredictable above all else: a
// peer that could guess it would mint the nonces of future windows, sign them while its
// key is present, and keep passing long after the key is gone.
func newCertChallenger(encryptionKey string, serverKey wgtypes.Key) *certposture.Challenger {
	secret := []byte(encryptionKey)
	if len(secret) == 0 {
		log.Warnf("no data store encryption key, deriving certificate challenges from the ephemeral server key: peers will be rejected once per restart and across instances")
		secret = serverKey[:]
	}

	h := sha256.New()
	h.Write([]byte(certChallengeKeyDomain))
	h.Write(secret)
	return certposture.NewChallenger(h.Sum(nil))
}

// stampCertificateChallenges fills the per-peer nonce into every certificate challenge
// right before the response is encrypted for that peer.
func stampCertificateChallenges(checks []*proto.Checks, challenger *certposture.Challenger, peerKey wgtypes.Key) {
	var nonce []byte
	for _, check := range checks {
		challenge := check.GetCertificateChallenge()
		if challenge == nil {
			continue
		}
		if nonce == nil {
			nonce = challenger.Nonce(peerKey[:], time.Now())
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

	now := time.Now()
	chains := make([]string, 0, len(proofs))
	for _, p := range proofs {
		chain, err := s.challenger.Verify(certposture.Proof{
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
