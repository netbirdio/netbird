//go:build js

package certproof

import (
	"crypto"
	"errors"
)

// tss2KeyPEMType is the PEM block type of a TPM 2.0 key file. A browser has no TPM, so
// the TPM library stays out of the WebAssembly build and such a key is refused.
const tss2KeyPEMType = "TSS2 PRIVATE KEY"

func parseTSS2Key([]byte) (crypto.Signer, error) {
	return nil, errors.New("TPM keys are not supported in this build")
}
