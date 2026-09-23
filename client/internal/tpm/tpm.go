// Package tpm is the client's one door to the platform TPM 2.0. It opens the device
// and turns TPM-held key files into signers; every operation opens the TPM, runs and
// closes it, so no handle outlives a call.
package tpm

import (
	"errors"
	"io"
)

// DeviceEnv overrides the TPM device path, which also lets tests point at a swtpm socket.
const DeviceEnv = "NB_TPM_DEVICE"

var ErrUnsupported = errors.New("TPM is not supported on this platform")

// Open connects to the platform TPM 2.0. The caller closes it after one operation.
func Open() (io.ReadWriteCloser, error) {
	return open()
}
