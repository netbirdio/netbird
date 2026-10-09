package pkcs11

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// DefaultModule is p11-kit's proxy, which exposes every module the system has registered,
// tpm2-pkcs11 included, so a URI without module-path works on a stock p11-kit setup.
const DefaultModule = "p11-kit-proxy.so"

// URI is the subset of an RFC 7512 PKCS#11 URI this client understands: the token label,
// the module to load and where the user PIN comes from. Unknown attributes are ignored.
type URI struct {
	Token      string
	ModulePath string
	pinValue   *string
	pinSource  string
}

func ParseURI(raw string) (*URI, error) {
	rest, ok := strings.CutPrefix(raw, "pkcs11:")
	if !ok {
		return nil, errors.New("PKCS#11 URI must start with pkcs11:")
	}
	path, query, _ := strings.Cut(rest, "?")

	u := &URI{}
	if err := eachAttribute(path, ";", func(name, value string) {
		if name == "token" {
			u.Token = value
		}
	}); err != nil {
		return nil, err
	}
	err := eachAttribute(query, "&", func(name, value string) {
		switch name {
		case "module-path":
			u.ModulePath = value
		case "module-name":
			u.ModulePath = "lib" + value + ".so"
		case "pin-value":
			u.pinValue = &value
		case "pin-source":
			u.pinSource = value
		}
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

func eachAttribute(list, sep string, fn func(name, value string)) error {
	if list == "" {
		return nil
	}
	for _, pair := range strings.Split(list, sep) {
		name, value, ok := strings.Cut(pair, "=")
		if !ok {
			return fmt.Errorf("PKCS#11 URI attribute %q has no value", pair)
		}
		value, err := url.PathUnescape(value)
		if err != nil {
			return fmt.Errorf("PKCS#11 URI attribute %s: %w", name, err)
		}
		fn(name, value)
	}
	return nil
}

// Module is the library to load, DefaultModule when the URI names none.
func (u *URI) Module() string {
	if u.ModulePath == "" {
		return DefaultModule
	}
	return u.ModulePath
}

// PIN returns the user PIN, or nil when the URI carries none and no login should happen.
// A pin-source names a file whose single line is the PIN.
func (u *URI) PIN() ([]byte, error) {
	if u.pinValue != nil {
		return []byte(*u.pinValue), nil
	}
	if u.pinSource == "" {
		return nil, nil
	}
	path := strings.TrimPrefix(strings.TrimPrefix(u.pinSource, "file://"), "file:")
	pin, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read PIN: %w", err)
	}
	return []byte(strings.TrimRight(string(pin), "\r\n")), nil
}
