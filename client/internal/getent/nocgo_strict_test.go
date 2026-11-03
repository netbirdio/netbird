//go:build (!cgo || osusergo) && !windows

package getent

import (
	"os/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Without cgo the standard library reads only /etc/group, so GroupIDs falls back to it when
// `id -G` fails and may return an incomplete list without an error. GroupIDsStrict must
// surface the failure instead.
func TestGroupIDsStrict_NoFallbackWhenIDFails(t *testing.T) {
	u, err := user.Current()
	require.NoError(t, err)

	t.Setenv("PATH", "")

	_, err = GroupIDsStrict(u)
	assert.Error(t, err, "a failed id lookup must not be hidden behind the /etc/group fallback")

	ids, err := GroupIDs(u)
	require.NoError(t, err, "the lenient lookup keeps falling back to /etc/group")
	assert.NotEmpty(t, ids)
}
