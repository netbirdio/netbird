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
		logNoChallenges(checks)
		return nil
	}
	return CollectChallenges(ctx, store, challenges, peerKey)
}

func logNoChallenges(checks []*proto.Checks) {
	if len(checks) > 0 {
		log.Infof("certificate posture: %d posture checks received, none carries a certificate challenge", len(checks))
	}
}

// CollectChallenges answers challenges already extracted from the posture checks, so a
// caller that ships them across a process boundary reuses the same matching and signing.
func CollectChallenges(ctx context.Context, store Store, challenges []*proto.CertificateChallenge, peerKey []byte) []certposture.Proof {
	log.Infof("certificate posture: answering %d certificate challenges from store %T", len(challenges), store)

	candidates, err := store.Candidates(ctx)
	if err != nil {
		log.Warnf("failed loading certificates for posture checks: %v", err)
		return nil
	}
	if len(candidates) == 0 {
		log.Info("certificate posture: certificate store holds no candidates, no proof will be sent")
		return nil
	}
	log.Infof("certificate posture: store holds %d candidate certificates", len(candidates))

	now := time.Now()
	proven := make(map[[sha256.Size]byte]struct{})
	var proofs []certposture.Proof
	for i, challenge := range challenges {
		roots, err := certposture.ParseCAs(challenge.GetCaCertificates())
		if err != nil {
			log.Warnf("skipping certificate challenge with invalid CA certificates: %v", err)
			continue
		}
		log.Infof("certificate posture: challenge %d accepts %d CA certificates, nonce is %d bytes", i, len(challenge.GetCaCertificates()), len(challenge.GetNonce()))

		matched := false
		for _, candidate := range candidates {
			if len(candidate.Chain) == 0 {
				continue
			}
			leaf := candidate.Chain[0]
			if err := certposture.VerifyChain(candidate.Chain, roots, now); err != nil {
				log.Infof("certificate posture: challenge %d rejected %q issued by %q, chain of %d: %v", i, leaf.Subject, leaf.Issuer, len(candidate.Chain), err)
				continue
			}
			matched = true

			fingerprint := sha256.Sum256(leaf.Raw)
			if _, done := proven[fingerprint]; done {
				log.Infof("certificate posture: challenge %d matched %q, already proven for an earlier challenge", i, leaf.Subject)
				break
			}
			proof, err := prove(candidate, challenge.GetNonce(), peerKey)
			if err != nil {
				log.Warnf("failed signing certificate proof for %s: %v", leaf.Subject, err)
				continue
			}
			log.Infof("certificate posture: challenge %d proven by %q with %s, signature %d bytes, chain of %d", i, leaf.Subject, proof.SigAlg, len(proof.Signature), len(proof.Chain))
			proven[fingerprint] = struct{}{}
			proofs = append(proofs, proof)
			break
		}
		if !matched {
			log.Infof("certificate posture: challenge %d matched none of the %d candidates", i, len(candidates))
		}
	}
	log.Infof("certificate posture: %d challenges produced %d proofs", len(challenges), len(proofs))
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
