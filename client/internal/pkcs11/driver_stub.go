//go:build !(pkcs11 && linux && !android && (amd64 || arm64))

package pkcs11

// Supported reports whether this build can load PKCS#11 modules.
func Supported() bool {
	return false
}

func load(string) (driver, error) {
	return nil, ErrUnsupported
}
