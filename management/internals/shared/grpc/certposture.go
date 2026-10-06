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

// newCertChallenger derives the nonce secret from the data store encryption key:
// generated once, written back to the configuration, and read by every instance, so a
// nonce stays verifiable across a restart and between instances.
//
// Where none is configured it falls back to the server's WireGuard key, which is
// regenerated per process. Unpredictable is the property that has to hold either way: a
// peer that could guess the secret would mint future windows' nonces, sign them while
// its key is present, and keep passing after it is gone.
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
// right before the response is encrypted for that peer, reporting whether it issued one.
//
// The answer is what registers the account for renewal. A nonce is stateless, but the
// renewal that keeps it fresh is local: only the instance that served a peer can push
// to it, so an instance renews exactly the accounts it has issued nonces for.
func stampCertificateChallenges(checks []*proto.Checks, challenger *certposture.Challenger, peerKey wgtypes.Key) bool {
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
	return nonce != nil
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
