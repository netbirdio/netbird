package labelgen

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPickUnique_ReturnsWordFromPool confirms a pick against an empty
// taken set is always drawn verbatim from the wordlist.
func TestPickUnique_ReturnsWordFromPool(t *testing.T) {
	got := PickUnique(map[string]struct{}{}, "abcd")

	assert.True(t, slices.Contains(uniqueWords(), got), "Pick %q must be drawn from the wordlist", got)
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

	got := PickUnique(taken, "abcd")

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

	got := PickUnique(taken, "abcd")

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

// TestPickTuple_ShapeAndPoolMembership locks the wire-visible shape: an
// adjective and a noun, each from its own pool, joined by a single hyphen so
// the result stays one DNS label.
func TestPickTuple_ShapeAndPoolMembership(t *testing.T) {
	nouns := uniqueWords()
	inNouns := make(map[string]struct{}, len(nouns))
	for _, w := range nouns {
		inNouns[w] = struct{}{}
	}
	inAdjectives := make(map[string]struct{}, len(adjectives))
	for _, a := range adjectives {
		inAdjectives[a] = struct{}{}
	}

	for i := 0; i < 200; i++ {
		got := PickTuple()

		parts := strings.Split(got, "-")
		require.Len(t, parts, 2, "PickTuple must produce exactly two hyphen-joined words; got %q", got)

		_, adjOK := inAdjectives[parts[0]]
		assert.True(t, adjOK, "First half must be an adjective; %q not in adjectives (from %q)", parts[0], got)
		_, nounOK := inNouns[parts[1]]
		assert.True(t, nounOK, "Second half must be a noun; %q not in words (from %q)", parts[1], got)

		assert.LessOrEqual(t, len(got), 63, "Label must fit a DNS label; got %q (%d chars)", got, len(got))
	}
}

// TestAdjectives_AreDisjointFromNouns keeps the namespace a clean product and
// prevents nonsense like "azure-azure": a handful of the noun pool's entries
// are adjectival, and any overlap would let the same word land on both sides.
func TestAdjectives_AreDisjointFromNouns(t *testing.T) {
	nouns := make(map[string]struct{}, len(uniqueWords()))
	for _, w := range uniqueWords() {
		nouns[w] = struct{}{}
	}
	for _, a := range adjectives {
		_, clash := nouns[a]
		assert.False(t, clash, "Adjective %q also appears in the noun pool; remove it from one list", a)
	}
}

// TestAdjectives_AreDNSSafeAndDeduplicated mirrors the curation contract stated
// in words.go: lowercase ASCII, 4-12 chars, no digits or hyphens, no repeats.
func TestAdjectives_AreDNSSafeAndDeduplicated(t *testing.T) {
	seen := make(map[string]struct{}, len(adjectives))
	for _, a := range adjectives {
		_, dup := seen[a]
		assert.False(t, dup, "Duplicate adjective %q", a)
		seen[a] = struct{}{}

		assert.Regexp(t, `^[a-z]{4,12}$`, a, "Adjective %q must be 4-12 lowercase ASCII letters", a)
	}
	assert.Greater(t, len(adjectives), 150, "Adjective pool too small to give a useful namespace")
}

// TestPickTuple_SpansALargeNamespace guards the reason we moved to tuples: a
// single-word pool caps the GLOBAL namespace at 857. Drawing many tuples must
// yield overwhelmingly distinct values.
func TestPickTuple_SpansALargeNamespace(t *testing.T) {
	seen := make(map[string]struct{}, 2000)
	for i := 0; i < 2000; i++ {
		seen[PickTuple()] = struct{}{}
	}
	assert.Greater(t, len(seen), 1900,
		"2000 draws should be nearly all distinct across a ~200k namespace; got %d unique", len(seen))
}
