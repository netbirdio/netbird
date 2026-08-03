// Package labelgen produces DNS-safe Agent Network subdomain labels.
package labelgen

import (
	"math/rand"
	"sort"
	"sync"
)

var (
	dedupOnce sync.Once
	uniqWords []string
)

// uniqueWords returns the wordlist deduplicated and sorted for
// deterministic exhaustion behaviour. Lazy-built once per process.
func uniqueWords() []string {
	dedupOnce.Do(func() {
		seen := make(map[string]struct{}, len(words))
		uniqWords = make([]string, 0, len(words))
		for _, w := range words {
			if _, ok := seen[w]; ok {
				continue
			}
			seen[w] = struct{}{}
			uniqWords = append(uniqWords, w)
		}
		sort.Strings(uniqWords)
	})
	return uniqWords
}

// PickTuple returns an adjective-noun label such as "brave-otter". It is still
// a single DNS label.
//
// It takes no `taken` set and has no fallback suffix. The noun pool holds 857
// entries, which is ample per cluster but a hard ceiling once labels must be
// unique across one shared zone; pairing an adjective with a noun spans
// len(adjectives) * 857 instead. Uniqueness is enforced by a database
// constraint and retried by the caller, rather than guessed from a pre-read
// set that a concurrent allocation can invalidate.
func PickTuple(rng *rand.Rand) string {
	nouns := uniqueWords()
	if len(nouns) == 0 || len(adjectives) == 0 {
		return ""
	}
	return adjectives[rng.Intn(len(adjectives))] + "-" + nouns[rng.Intn(len(nouns))]
}
