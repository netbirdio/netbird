// Package labelgen produces DNS-safe Agent Network subdomain labels.
package labelgen

import (
	"fmt"
	"sort"
	"sync"

	"github.com/netbirdio/netbird/management/server/util"
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
// `-<fallbackSuffix>` to a random word and returns.
func PickUnique(taken map[string]struct{}, fallbackSuffix string) string {
	pool := uniqueWords()
	if len(pool) == 0 {
		return fallbackSuffix
	}

	for i := 0; i < pickAttempts; i++ {
		w := pool[util.RandIntn(len(pool))]
		if _, ok := taken[w]; !ok {
			return w
		}
	}

	for _, w := range pool {
		if _, ok := taken[w]; !ok {
			return w
		}
	}

	w := pool[util.RandIntn(len(pool))]
	return fmt.Sprintf("%s-%s", w, fallbackSuffix)
}

// PickTuple returns an adjective-noun label such as "brave-otter". It is still
// a single DNS label.
//
// Unlike PickUnique it takes no `taken` set and has no fallback suffix. The
// noun pool holds 857 entries, which is ample per cluster but a hard ceiling
// once labels must be unique across one shared zone; pairing an adjective with
// a noun spans len(adjectives) * 857 instead. Uniqueness is enforced by a
// database constraint and retried by the caller, rather than guessed from a
// pre-read set that a concurrent allocation can invalidate.
func PickTuple() string {
	nouns := uniqueWords()
	if len(nouns) == 0 || len(adjectives) == 0 {
		return ""
	}
	return adjectives[util.RandIntn(len(adjectives))] + "-" + nouns[util.RandIntn(len(nouns))]
}
