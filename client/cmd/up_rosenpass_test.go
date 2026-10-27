package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRosenpassFlagsWarnDeprecated(t *testing.T) {
	origEnabled, origPermissive := rosenpassEnabled, rosenpassPermissive
	t.Cleanup(func() {
		rosenpassEnabled, rosenpassPermissive = origEnabled, origPermissive
	})

	for _, name := range []string{enableRosenpassFlag, rosenpassPermissiveFlag} {
		// Copy the production flag into a private set so Set marks only the copy as
		// Changed, leaving upCmd's shared flag set untouched for other tests.
		prod := upCmd.PersistentFlags().Lookup(name)
		require.NotNil(t, prod, "flag --%s must be registered on up", name)
		flagCopy := *prod

		var out bytes.Buffer
		flags := pflag.NewFlagSet("rosenpass-test", pflag.ContinueOnError)
		flags.SetOutput(&out)
		flags.AddFlag(&flagCopy)

		require.NoError(t, flags.Set(name, "true"))
		assert.Contains(t, out.String(), "Flag --"+name+" has been deprecated", "setting --%s should print the deprecation notice", name)
		assert.False(t, prod.Changed, "the shared --%s flag must stay unchanged", name)
	}
}
