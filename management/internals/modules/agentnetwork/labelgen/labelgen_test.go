package labelgen

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPickUnique_DeterministicWithSeededRng locks the property the
// caller relies on: same seed + same taken set → same pick. Without
// that, the bootstrap flow can't reproduce a label across retries.
func TestPickUnique_DeterministicWithSeededRng(t *testing.T) {
	taken := map[string]struct{}{}

	rngA := rand.New(rand.NewSource(42))
	rngB := rand.New(rand.NewSource(42))

	a := PickUnique(rngA, taken, "abcd")
	b := PickUnique(rngB, taken, "abcd")

	assert.Equal(t, a, b, "Same seed and taken set must produce identical pick")
}

// TestPickUnique_AvoidsTakenWordsWhenMostAreReserved seeds taken with
// every word in the pool except a handful and confirms PickUnique
// finds one of the remaining free entries instead of returning the
// fallback form.
func TestPickUnique_AvoidsTakenWordsWhenMostAreReserved(t *testing.T) {
	pool := uniqueWords()
	require.NotEmpty(t, pool, "wordlist must be populated for the test to mean anything")

	free := map[string]struct{}{
		pool[0]:           {},
		pool[len(pool)/2]: {},
		pool[len(pool)-1]: {},
	}

	taken := make(map[string]struct{}, len(pool))
	for _, w := range pool {
		if _, ok := free[w]; ok {
			continue
		}
		taken[w] = struct{}{}
	}

	rng := rand.New(rand.NewSource(7))
	got := PickUnique(rng, taken, "abcd")

	_, isFree := free[got]
	assert.True(t, isFree, "PickUnique must return one of the free words; got %q", got)
	assert.NotContains(t, got, "-", "Free pick must not be the suffix fallback form")
}

// TestPickUnique_FallsBackWhenAllReserved exhausts the pool and
// confirms PickUnique appends the supplied suffix instead of
// returning a duplicate.
func TestPickUnique_FallsBackWhenAllReserved(t *testing.T) {
	pool := uniqueWords()

	taken := make(map[string]struct{}, len(pool))
	for _, w := range pool {
		taken[w] = struct{}{}
	}

	rng := rand.New(rand.NewSource(99))
	got := PickUnique(rng, taken, "abcd")

	assert.True(t, strings.HasSuffix(got, "-abcd"), "Exhausted pool must produce <word>-<suffix>; got %q", got)

	prefix := strings.TrimSuffix(got, "-abcd")
	found := false
	for _, w := range pool {
		if w == prefix {
			found = true
			break
		}
	}
	assert.True(t, found, "Fallback prefix must be drawn from the wordlist; got %q", prefix)
}

// TestUniqueWords_DropsDuplicates guards against authoring slips in
// words.go: every entry must be unique and DNS-safe.
func TestUniqueWords_DropsDuplicates(t *testing.T) {
	pool := uniqueWords()
	seen := make(map[string]struct{}, len(pool))
	for _, w := range pool {
		_, dup := seen[w]
		assert.False(t, dup, "Duplicate entry %q in deduplicated pool", w)
		seen[w] = struct{}{}
		assert.GreaterOrEqual(t, len(w), 4, "Word %q is shorter than 4 chars", w)
		assert.LessOrEqual(t, len(w), 12, "Word %q is longer than 12 chars", w)
		for _, r := range w {
			ok := r >= 'a' && r <= 'z'
			assert.True(t, ok, "Word %q contains non-lowercase-ASCII rune %q", w, r)
		}
	}
	assert.GreaterOrEqual(t, len(pool), 500, "Pool must contain at least 500 unique words")
}
