package domain

import (
	"sort"
	"strings"
)

// List is a slice of punycode-encoded domain strings.
type List []Domain

// ToStringList converts a List to a slice of string.
func (d List) ToStringList() ([]string, error) {
	var list []string
	for _, domain := range d {
		s, err := domain.String()
		if err != nil {
			return nil, err
		}
		list = append(list, s)
	}
	return list, nil
}

// ToPunycodeList converts the List to a slice of Punycode-encoded domain strings.
func (d List) ToPunycodeList() []string {
	var list []string
	for _, domain := range d {
		list = append(list, string(domain))
	}
	return list
}

// ToSafeStringList converts the List to a slice of non-punycode strings.
// If a domain cannot be converted, the original string is used.
func (d List) ToSafeStringList() []string {
	var list []string
	for _, domain := range d {
		list = append(list, domain.SafeString())
	}
	return list
}

// String converts List to a comma-separated string.
func (d List) String() (string, error) {
	list, err := d.ToStringList()
	if err != nil {
		return "", err
	}
	return strings.Join(list, ", "), nil
}

// SafeString converts List to a comma-separated non-punycode string.
// If a domain cannot be converted, the original string is used.
func (d List) SafeString() string {
	str, err := d.String()
	if err != nil {
		return d.PunycodeString()
	}
	return str
}

// PunycodeString converts the List to a comma-separated string of Punycode-encoded domains.
func (d List) PunycodeString() string {
	return strings.Join(d.ToPunycodeList(), ", ")
}

func (d List) Equal(domains List) bool {
	if len(d) != len(domains) {
		return false
	}

	sort.Slice(d, func(i, j int) bool {
		return d[i] < d[j]
	})

	sort.Slice(domains, func(i, j int) bool {
		return domains[i] < domains[j]
	})

	for i, domain := range d {
		if domain != domains[i] {
			return false
		}
	}
	return true
}

// FromStringList creates a DomainList from a slice of string.
func FromStringList(s []string) (List, error) {
	var dl List
	for _, domain := range s {
		d, err := FromString(domain)
		if err != nil {
			return nil, err
		}
		dl = append(dl, d)
	}
	return dl, nil
}

// FromPunycodeList creates a List from a slice of Punycode-encoded domain strings.
func FromPunycodeList(s []string) List {
	var dl List
	for _, domain := range s {
		dl = append(dl, Domain(domain))
	}
	return dl
}
