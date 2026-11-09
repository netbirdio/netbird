package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeCountryList(t *testing.T) {
	t.Run("uppercases valid codes in place", func(t *testing.T) {
		codes := []string{"de", "US", "fR"}
		require.NoError(t, normalizeCountryList("allowed_countries", codes))
		assert.Equal(t, []string{"DE", "US", "FR"}, codes, "codes should be uppercased in place")
	})

	t.Run("rejects values that are not two ASCII letters", func(t *testing.T) {
		for _, bad := range []string{"", "D", "DEU", "12", "--", " U", "U ", "D1", "é", "ÀB", "a\x00"} {
			err := normalizeCountryList("blocked_countries", []string{bad})
			assert.Error(t, err, "%q must be rejected", bad)
		}
	})

	t.Run("reports the failing index and field", func(t *testing.T) {
		err := normalizeCountryList("allowed_countries", []string{"DE", "1X"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "allowed_countries[1]")
	})
}
