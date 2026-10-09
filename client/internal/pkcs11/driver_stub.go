//go:build !(pkcs11 && linux && (amd64 || arm64))

package pkcs11

func load(string) (driver, error) {
	return nil, ErrUnsupported
}
