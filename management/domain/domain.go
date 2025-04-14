package domain

import (
	"golang.org/x/net/idna"
)

// Domain represents a punycode-encoded domain string.
// This should only be converted from a string when the string already is in punycode, otherwise use FromString.
type Domain string

// String converts the Domain to a non-punycode string.
// For an infallible conversion, use SafeString.
func (d Domain) String() (string, error) {
	unicode, err := idna.ToUnicode(string(d))
	if err != nil {
		return "", err
	}
	return unicode, nil
}

// SafeString converts the Domain to a non-punycode string, falling back to the punycode string if conversion fails.
func (d Domain) SafeString() string {
	str, err := d.String()
	if err != nil {
		return string(d)
	}
	return str
}

// PunycodeString returns the punycode representation of the Domain.
// This should only be used if a punycode domain is expected but only a string is supported.
func (d Domain) PunycodeString() string {
	return string(d)
}

// FromString creates a Domain from a string, converting it to punycode.
func FromString(s string) (Domain, error) {
	ascii, err := idna.ToASCII(s)
	if err != nil {
		return "", err
	}
	return Domain(ascii), nil
}
