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
			seen[derChainFingerprint(proof.Chain)] = struct{}{}
		}
	}

	merged := device
	for _, proof := range user {
		if len(proof.Chain) == 0 {
			continue
		}
		fingerprint := derChainFingerprint(proof.Chain)
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

// derChainFingerprint identifies a chain of DER certificates by the hashes of all of them,
// in order. It matches chainFingerprint for the same chain.
func derChainFingerprint(chain [][]byte) [sha256.Size]byte {
	buf := make([]byte, 0, len(chain)*sha256.Size)
	for _, der := range chain {
		certHash := sha256.Sum256(der)
		buf = append(buf, certHash[:]...)
	}
	return sha256.Sum256(buf)
}
