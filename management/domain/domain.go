package domain

import (
	"golang.org/x/net/idna"
)

type Domain string

// String converts the Domain to a non-punycode string.
func (d Domain) String() (string, error) {
	unicode, err := idna.ToUnicode(string(d))
	if err != nil {
		return "", err
	}
	return unicode, nil
}

// SafeString converts the Domain to a non-punycode string, falling back to the original string if conversion fails.
func (d Domain) SafeString() string {
	str, err := d.String()
	if err != nil {
		str = string(d)
	}
	return str
}

// FromString creates a Domain from a string, converting it to punycode.
func FromString(s string) (Domain, error) {
	ascii, err := idna.ToASCII(s)
	if err != nil {
		return "", err
	}
	return Domain(ascii), nil
}
