// Package labelgen produces DNS-safe Agent Network subdomain labels.
package labelgen

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
)

// pickAttempts caps the random retries before falling back to the
// suffixed form. Eight is a soft compromise: with a near-empty taken
// set the very first pick almost always succeeds; when the wordlist is
// densely populated the fallback eventually fires anyway.
const pickAttempts = 8

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

// PickUnique selects a label not already in `taken`. It tries up to
// pickAttempts random picks; on exhaustion it scans the deduplicated
// wordlist for any remaining free entry, and if none is left appends
// `-<fallbackSuffix>` to a deterministic word and returns. The caller
// is responsible for seeding rng (math/rand).
func PickUnique(rng *rand.Rand, taken map[string]struct{}, fallbackSuffix string) string {
	pool := uniqueWords()
	if len(pool) == 0 {
		return fallbackSuffix
	}

	for i := 0; i < pickAttempts; i++ {
		w := pool[rng.Intn(len(pool))]
		if _, ok := taken[w]; !ok {
			return w
		}
	}

	for _, w := range pool {
		if _, ok := taken[w]; !ok {
			return w
		}
	}

	w := pool[rng.Intn(len(pool))]
	return fmt.Sprintf("%s-%s", w, fallbackSuffix)
}
