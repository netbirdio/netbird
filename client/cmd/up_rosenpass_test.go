package cmd

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRosenpassFlagsWarnDeprecated(t *testing.T) {
	flags := upCmd.PersistentFlags()
	origEnabled, origPermissive := rosenpassEnabled, rosenpassPermissive

	var out bytes.Buffer
	flags.SetOutput(&out)
	t.Cleanup(func() {
		flags.SetOutput(os.Stderr)
		rosenpassEnabled, rosenpassPermissive = origEnabled, origPermissive
	})

	for _, name := range []string{enableRosenpassFlag, rosenpassPermissiveFlag} {
		out.Reset()
		require.NoError(t, flags.Set(name, "true"))
		assert.Contains(t, out.String(), "Flag --"+name+" has been deprecated", "setting --%s should print the deprecation notice", name)
	}
}
