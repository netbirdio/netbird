package dns

import (
	"fmt"
	"testing"
)

func Test_mergeSearchDomains(t *testing.T) {
	searchDomains := []string{"a", "b"}
	originDomains := []string{"a", "b"}
	mergedDomains := mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 4 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 4)
	}
}

func Test_mergeSearchTooMuchDomains(t *testing.T) {
	searchDomains := []string{"a", "b", "c", "d", "e", "f", "g"}
	originDomains := []string{"h", "i"}
	mergedDomains := mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 6 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 6)
	}
}

func Test_mergeSearchTooMuchDomainsInOrigin(t *testing.T) {
	searchDomains := []string{"a", "b"}
	originDomains := []string{"c", "d", "e", "f", "g"}
	mergedDomains := mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 6 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 6)
	}
}

func Test_mergeSearchTooLongDomain(t *testing.T) {
	searchDomains := []string{getLongLine()}
	originDomains := []string{"b"}
	mergedDomains := mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 1 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 1)
	}

	searchDomains = []string{"b"}
	originDomains = []string{getLongLine()}

	mergedDomains = mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 1 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 1)
	}
}

func getLongLine() string {
	x := "search "
	for {
		for i := 0; i <= 9; i++ {
			if len(x) > fileMaxLineCharsLimit {
				return x
			}
			x = fmt.Sprintf("%s%d", x, i)
		}
	}
}
