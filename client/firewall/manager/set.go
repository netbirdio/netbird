package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/domain"
)

type Set struct {
	hash    [4]byte
	comment string
}

// String returns the string representation of the set: hashed name and comment
func (h Set) String() string {
	if h.comment == "" {
		return h.HashedName()
	}
	return h.HashedName() + ": " + h.comment
}

// HashedName returns the string representation of the hash
func (h Set) HashedName() string {
	return fmt.Sprintf(
		"nb-%s",
		hex.EncodeToString(h.hash[:]),
	)
}

// Comment returns the comment of the set
func (h Set) Comment() string {
	return h.comment
}

// NewPrefixSet generates a unique name for an ipset based on the given prefixes.
func NewPrefixSet(prefixes []netip.Prefix) Set {
	// sort for consistent naming
	SortPrefixes(prefixes)

	hash := sha256.New()
	for _, src := range prefixes {
		bytes, err := src.MarshalBinary()
		if err != nil {
			log.Warnf("failed to marshal prefix %s: %v", src, err)
		}
		hash.Write(bytes)
	}
	var set Set
	copy(set.hash[:], hash.Sum(nil)[:4])

	return set
}

// NewDomainSet generates a unique name for an ipset based on the given domains.
func NewDomainSet(domains domain.List) Set {
	slices.Sort(domains)

	hash := sha256.New()
	for _, d := range domains {
		hash.Write([]byte(d.PunycodeString()))
	}
	set := Set{
		comment: domains.SafeString(),
	}
	copy(set.hash[:], hash.Sum(nil)[:4])

	return set
}
