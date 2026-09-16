//go:build !(pkcs11 && linux && (amd64 || arm64))

package pkcs11

import "encoding/binary"

func load(string) (driver, error) {
	return nil, ErrUnsupported
}

// ULong encodes an integer attribute value; no module ever reads it in this build.
func ULong(v uint) []byte {
	return binary.NativeEndian.AppendUint64(nil, uint64(v))
}
