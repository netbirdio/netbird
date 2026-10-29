//go:build !js

package certproof

import (
	"crypto"

	"github.com/netbirdio/netbird/client/internal/tpm"
)

// tss2KeyPEMType is the PEM block type of a TPM 2.0 key file.
const tss2KeyPEMType = tpm.KeyPEMType

// parseTSS2Key returns a signer for a TPM-held key file that signs inside the TPM.
func parseTSS2Key(der []byte) (crypto.Signer, error) {
	return tpm.ParseKey(der)
}
