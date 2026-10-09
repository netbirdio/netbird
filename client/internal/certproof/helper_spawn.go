//go:build darwin || windows

package certproof

import (
	"crypto/sha256"
	"crypto/x509"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func helperRequest(challenges []*proto.CertificateChallenge, peerKey []byte) HelperRequest {
	req := HelperRequest{PeerKey: peerKey, Challenges: make([]HelperChallenge, 0, len(challenges))}
	for _, challenge := range challenges {
		req.Challenges = append(req.Challenges, HelperChallenge{
			Nonce:          challenge.GetNonce(),
			CACertificates: challenge.GetCaCertificates(),
		})
	}
	return req
}

// mergeProofs appends the user session proofs to the device proofs, dropping a leaf that
// both stores hold so the same certificate is proven once.
func mergeProofs(device, user []certposture.Proof) []certposture.Proof {
	if len(user) == 0 {
		return device
	}

	seen := make(map[[sha256.Size]byte]struct{}, len(device))
	for _, proof := range device {
		if len(proof.Chain) > 0 {
			seen[sha256.Sum256(proof.Chain[0])] = struct{}{}
		}
	}

	merged := device
	for _, proof := range user {
		if len(proof.Chain) == 0 {
			continue
		}
		fingerprint := sha256.Sum256(proof.Chain[0])
		if _, done := seen[fingerprint]; done {
			continue
		}
		seen[fingerprint] = struct{}{}
		merged = append(merged, proof)
		logUserProof(proof)
	}
	return merged
}

func logUserProof(proof certposture.Proof) {
	leaf, err := x509.ParseCertificate(proof.Chain[0])
	if err != nil {
		log.Infof("certificate posture: user proof carries an unparsable leaf: %v", err)
		return
	}
	log.Infof("certificate posture: signed-in user proved %q issued by %q", leaf.Subject, leaf.Issuer)
}
