package types

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

// GenerateSetName generates a unique name for an ipset based on the given sources.
func GenerateSetName(sources []netip.Prefix) string {
	// sort for consistent naming
	SortPrefixes(sources)

	var sourcesStr strings.Builder
	for _, src := range sources {
		sourcesStr.WriteString(src.String())
	}

	hash := sha256.Sum256([]byte(sourcesStr.String()))
	shortHash := hex.EncodeToString(hash[:])[:8]

	return fmt.Sprintf("nb-%s", shortHash)
}
