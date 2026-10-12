package certproof

import (
	"crypto/sha256"
	"crypto/x509"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/management/certposture"
)

// mergeProofs appends the user session proofs to the device proofs, dropping one whose
// chain the device already proved. Management checks each chain against each check's CAs,
// so the same leaf proven through another chain is kept.
func mergeProofs(device, user []certposture.Proof) []certposture.Proof {
	if len(user) == 0 {
		return device
	}

	seen := make(map[[sha256.Size]byte]struct{}, len(device)+len(user))
	for _, proof := range device {
		if len(proof.Chain) > 0 {
			seen[chainDERFingerprint(proof.Chain)] = struct{}{}
		}
	}

	merged := device
	for _, proof := range user {
		if len(proof.Chain) == 0 {
			continue
		}
		fingerprint := chainDERFingerprint(proof.Chain)
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
		log.Debugf("certificate posture: user proof carries an unparsable leaf: %v", err)
		return
	}
	log.Debugf("certificate posture: signed-in user proved %q issued by %q", leaf.Subject, leaf.Issuer)
}
