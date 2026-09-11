package wgaddr

// MustParseWGAddress parses and returns a WG Address, panicking on error.
func MustParseWGAddress(address string) Address {
	a, err := ParseWGAddress(address)
	if err != nil {
		panic(err)
	}
	return a
}
