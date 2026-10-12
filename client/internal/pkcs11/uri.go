package pkcs11

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// DefaultModule is p11-kit's proxy, which exposes every module the system has registered,
// tpm2-pkcs11 included, so a URI without module-path works on a stock p11-kit setup.
const DefaultModule = "p11-kit-proxy.so"

// URI is the subset of an RFC 7512 PKCS#11 URI this client understands: the token label,
// the module to load and where the user PIN comes from.
type URI struct {
	Token      string
	ModulePath string
	pinValue   *string
	pinSource  string
}

// ParseURI parses raw following RFC 7512 section 2.3. A path attribute other than token
// is refused rather than ignored: the path narrows which token is used, and ignoring a
// constraint such as serial would widen the match to whichever token is listed first,
// where the RFC calls for no match at all. Duplicate attributes are refused, a
// module-path must be absolute and a module-name must be a bare name. Unknown query
// attributes are ignored, as the RFC asks.
func ParseURI(raw string) (*URI, error) {
	rest, ok := cutPrefixFold(raw, "pkcs11:")
	if !ok {
		return nil, errors.New("PKCS#11 URI does not start with the pkcs11 scheme")
	}
	path, query, _ := strings.Cut(rest, "?")

	u := &URI{}
	if err := eachAttribute(path, ";", u.setPathAttribute); err != nil {
		return nil, err
	}
	if err := eachAttribute(query, "&", u.setQueryAttribute); err != nil {
		return nil, err
	}
	// RFC 7512 section 2.4: a URI with both pin-value and pin-source should be refused.
	if u.pinValue != nil && u.pinSource != "" {
		return nil, errors.New("PKCS#11 URI carries both pin-value and pin-source")
	}
	return u, nil
}

func (u *URI) setPathAttribute(name, value string) error {
	if name != "token" {
		return fmt.Errorf("PKCS#11 URI path attribute %q is not supported, only token selects a token", name)
	}
	u.Token = value
	return nil
}

func (u *URI) setQueryAttribute(name, value string) error {
	switch name {
	case "module-path":
		if !filepath.IsAbs(value) {
			return fmt.Errorf("PKCS#11 URI module-path %q must be absolute", value)
		}
		u.ModulePath = value
	case "module-name":
		if value == "" || strings.ContainsAny(value, `/\`) || strings.Contains(value, "..") {
			return fmt.Errorf("PKCS#11 URI module-name %q must be a module name, not a path", value)
		}
		u.ModulePath = "lib" + value + ".so"
	case "pin-value":
		u.pinValue = &value
	case "pin-source":
		path, err := pinSourcePath(value)
		if err != nil {
			return err
		}
		u.pinSource = path
	}
	return nil
}

// pinSourcePath turns a pin-source value into the file to read. A plain path is used as
// it is; a file URI must name a local absolute path, with no host or localhost (RFC 8089
// section 2), so a PIN is never read from somewhere the URI only appears to point to.
func pinSourcePath(value string) (string, error) {
	if value == "" {
		return "", errors.New("PKCS#11 URI pin-source is empty")
	}
	rest, isFile := cutPrefixFold(value, "file:")
	if !isFile {
		return value, nil
	}
	authorityAndPath, hasAuthority := strings.CutPrefix(rest, "//")
	if !hasAuthority {
		if !isAbsolutePath(rest) {
			return "", fmt.Errorf("PKCS#11 URI pin-source %q must be an absolute path", value)
		}
		return rest, nil
	}
	if isAbsolutePath(authorityAndPath) {
		return authorityAndPath, nil
	}
	host, path, _ := strings.Cut(authorityAndPath, "/")
	if host != "" && !strings.EqualFold(host, "localhost") {
		return "", fmt.Errorf("PKCS#11 URI pin-source host %q is not the local machine", host)
	}
	if path == "" {
		return "", fmt.Errorf("PKCS#11 URI pin-source %q names no file", value)
	}
	return "/" + path, nil
}

// isAbsolutePath reports whether p is absolute in a file URI. A path starting with a slash
// is absolute there on every platform, including Windows, where filepath.IsAbs wants a
// drive letter.
func isAbsolutePath(p string) bool {
	return strings.HasPrefix(p, "/") || filepath.IsAbs(p)
}

// cutPrefixFold is strings.CutPrefix with the prefix matched without regard to case.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return s, false
	}
	return s[len(prefix):], true
}

// Module is the library to load, DefaultModule when the URI names none.
func (u *URI) Module() string {
	if u.ModulePath == "" {
		return DefaultModule
	}
	return u.ModulePath
}

// HasPIN reports whether the URI carries a PIN, inline or as a pin-source.
func (u *URI) HasPIN() bool {
	return u.pinValue != nil || u.pinSource != ""
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
	pin, err := os.ReadFile(u.pinSource)
	if err != nil {
		return nil, fmt.Errorf("read PIN: %w", err)
	}
	return []byte(strings.TrimRight(string(pin), "\r\n")), nil
}

// eachAttribute splits list on sep and calls fn for every name=value pair, refusing a
// name that appears twice.
func eachAttribute(list, sep string, fn func(name, value string) error) error {
	if list == "" {
		return nil
	}
	seen := make(map[string]struct{})
	for _, pair := range strings.Split(list, sep) {
		name, value, ok := strings.Cut(pair, "=")
		if !ok {
			return fmt.Errorf("PKCS#11 URI attribute %q has no value", pair)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("PKCS#11 URI attribute %s appears more than once", name)
		}
		seen[name] = struct{}{}
		value, err := url.PathUnescape(value)
		if err != nil {
			return fmt.Errorf("PKCS#11 URI attribute %s: %w", name, err)
		}
		if err := fn(name, value); err != nil {
			return err
		}
	}
	return nil
}
