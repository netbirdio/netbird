package certproof

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

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
		log.Debugf("certificate posture: %d posture checks received, none carries a certificate challenge", len(checks))
	}
}

// CollectChallenges answers challenges already extracted from the posture checks, so a
// caller that ships them across a process boundary reuses the same matching and signing.
// Only nonces of the size management issues are signed, for a peer key of the size of
// ours, so the keys behind the store never sign arbitrary caller-chosen data.
func CollectChallenges(ctx context.Context, store Store, challenges []*proto.CertificateChallenge, peerKey []byte) []certposture.Proof {
	if len(peerKey) != wgtypes.KeyLen {
		log.Warnf("certificate posture: refusing to sign for a %d byte peer key", len(peerKey))
		return nil
	}
	challenges = wellFormed(challenges)
	if len(challenges) == 0 {
		return nil
	}
	log.Debugf("certificate posture: answering %d certificate challenges from store %T", len(challenges), store)

	candidates, err := store.Candidates(ctx)
	if err != nil {
		log.Warnf("failed loading certificates for posture checks: %v", err)
		return nil
	}
	if len(candidates) == 0 {
		log.Debug("certificate posture: certificate store holds no candidates, no proof will be sent")
		return nil
	}
	log.Debugf("certificate posture: store holds %d candidate certificates", len(candidates))

	now := time.Now()
	proven := make(map[[sha256.Size]byte]struct{})
	var proofs []certposture.Proof
	for i, challenge := range challenges {
		roots, err := certposture.ParseCAs(challenge.GetCaCertificates())
		if err != nil {
			log.Warnf("skipping certificate challenge with invalid CA certificates: %v", err)
			continue
		}
		log.Debugf("certificate posture: challenge %d accepts %d CA certificates, nonce is %d bytes", i, len(challenge.GetCaCertificates()), len(challenge.GetNonce()))

		matched := false
		for _, candidate := range candidates {
			if len(candidate.Chain) == 0 {
				continue
			}
			leaf := candidate.Chain[0]
			chain, err := certposture.VerifiedChain(leaf, candidate.issuers(), roots, now)
			if err != nil {
				log.Debugf("certificate posture: challenge %d rejected %q issued by %q: %v", i, leaf.Subject, leaf.Issuer, err)
				continue
			}
			matched = true

			// The same leaf can chain to different CAs for different challenges, and
			// management checks each chain against each check's CAs, so a proof is
			// deduplicated by its whole chain rather than by its leaf.
			fingerprint := chainFingerprint(chain)
			if _, done := proven[fingerprint]; done {
				log.Debugf("certificate posture: challenge %d matched %q, already proven for an earlier challenge", i, leaf.Subject)
				break
			}
			proof, err := prove(candidate.Signer, chain, challenge.GetNonce(), peerKey)
			if err != nil {
				log.Warnf("failed signing certificate proof for %s: %v", leaf.Subject, err)
				continue
			}
			log.Debugf("certificate posture: challenge %d proven by %q with %s, signature %d bytes, chain of %d", i, leaf.Subject, proof.SigAlg, len(proof.Signature), len(proof.Chain))
			proven[fingerprint] = struct{}{}
			proofs = append(proofs, proof)
			break
		}
		if !matched {
			log.Debugf("certificate posture: challenge %d matched none of the %d candidates", i, len(candidates))
		}
	}
	log.Debugf("certificate posture: %d challenges produced %d proofs", len(challenges), len(proofs))
	return proofs
}

// HasChallenges reports whether any of checks asks for a certificate proof.
func HasChallenges(checks []*proto.Checks) bool {
	return len(certificateChallenges(checks)) > 0
}

func certificateChallenges(checks []*proto.Checks) []*proto.CertificateChallenge {
	var challenges []*proto.CertificateChallenge
	for _, check := range checks {
		if challenge := check.GetCertificateChallenge(); challenge != nil {
			challenges = append(challenges, challenge)
		}
	}
	return wellFormed(challenges)
}

// wellFormed drops challenges whose nonce is not one management could have issued.
func wellFormed(challenges []*proto.CertificateChallenge) []*proto.CertificateChallenge {
	var kept []*proto.CertificateChallenge
	for _, challenge := range challenges {
		if len(challenge.GetNonce()) != certposture.NonceSize {
			log.Debugf("certificate posture: skipping challenge with a %d byte nonce", len(challenge.GetNonce()))
			continue
		}
		kept = append(kept, challenge)
	}
	return kept
}

func prove(signer crypto.Signer, chain []*x509.Certificate, nonce, peerKey []byte) (certposture.Proof, error) {
	sigAlg, sig, err := certposture.Sign(signer, nonce, peerKey)
	if err != nil {
		return certposture.Proof{}, err
	}
	der := make([][]byte, 0, len(chain))
	for _, cert := range chain {
		der = append(der, cert.Raw)
	}
	return certposture.Proof{Nonce: nonce, Chain: der, SigAlg: sigAlg, Signature: sig}, nil
}

func chainFingerprint(chain []*x509.Certificate) [sha256.Size]byte {
	buf := make([]byte, 0, len(chain)*sha256.Size)
	for _, cert := range chain {
		certHash := sha256.Sum256(cert.Raw)
		buf = append(buf, certHash[:]...)
	}
	return sha256.Sum256(buf)
}
