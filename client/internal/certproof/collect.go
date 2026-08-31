package certproof

import (
	"context"
	"crypto/sha256"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// Collect answers the certificate challenges in checks: for each challenge it picks a
// stored certificate that chains to the challenge's CAs and signs the nonce with its
// key. The same certificate is proven once even if several checks accept it.
func Collect(ctx context.Context, store Store, checks []*proto.Checks, peerKey []byte) []certposture.Proof {
	challenges := certificateChallenges(checks)
	if len(challenges) == 0 {
		return nil
	}

	candidates, err := store.Candidates(ctx)
	if err != nil {
		log.Warnf("failed loading certificates for posture checks: %v", err)
		return nil
	}

	now := time.Now()
	proven := make(map[[sha256.Size]byte]struct{})
	var proofs []certposture.Proof
	for _, challenge := range challenges {
		roots, err := certposture.ParseCAs(challenge.GetCaCertificates())
		if err != nil {
			log.Warnf("skipping certificate challenge with invalid CA certificates: %v", err)
			continue
		}
		for _, candidate := range candidates {
			if certposture.VerifyChain(candidate.Chain, roots, now) != nil {
				continue
			}
			fingerprint := sha256.Sum256(candidate.Chain[0].Raw)
			if _, done := proven[fingerprint]; done {
				break
			}
			proof, err := prove(candidate, challenge.GetNonce(), peerKey)
			if err != nil {
				log.Warnf("failed signing certificate proof for %s: %v", candidate.Chain[0].Subject, err)
				continue
			}
			proven[fingerprint] = struct{}{}
			proofs = append(proofs, proof)
			break
		}
	}
	return proofs
}

func certificateChallenges(checks []*proto.Checks) []*proto.CertificateChallenge {
	var challenges []*proto.CertificateChallenge
	for _, check := range checks {
		if challenge := check.GetCertificateChallenge(); challenge != nil && len(challenge.GetNonce()) > 0 {
			challenges = append(challenges, challenge)
		}
	}
	return challenges
}

func prove(candidate Candidate, nonce, peerKey []byte) (certposture.Proof, error) {
	sigAlg, sig, err := certposture.Sign(candidate.Signer, nonce, peerKey)
	if err != nil {
		return certposture.Proof{}, err
	}
	chain := make([][]byte, 0, len(candidate.Chain))
	for _, cert := range candidate.Chain {
		chain = append(chain, cert.Raw)
	}
	return certposture.Proof{Nonce: nonce, Chain: chain, SigAlg: sigAlg, Signature: sig}, nil
}
