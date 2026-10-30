package pqkem

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvFlags(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"", false},
		{"on", true},
		{"ON", true},
		{"  on  ", true},
		{"off", false},
		{"Off", false},
		{"true", true},
		{"TRUE", true},
		{"1", true},
		{"t", true},
		{"false", false},
		{"0", false},
		{" 1 ", true},
		{"yes", false},
		{"garbage", false},
	}

	flags := []struct {
		env string
		get func() bool
	}{
		{EnvEnabled, Enabled},
		{EnvStrict, Strict},
	}

	for _, f := range flags {
		for _, c := range cases {
			t.Run(f.env+"="+c.value, func(t *testing.T) {
				t.Setenv(f.env, c.value)
				assert.Equal(t, c.want, f.get(), "%s=%q", f.env, c.value)
			})
		}
	}
}

func TestEnvFlagsUnset(t *testing.T) {
	for _, env := range []string{EnvEnabled, EnvStrict} {
		t.Setenv(env, "")
		require.NoError(t, os.Unsetenv(env))
	}
	assert.False(t, Enabled(), "an unset %s must leave ML-KEM disabled", EnvEnabled)
	assert.False(t, Strict(), "an unset %s must leave strict mode off", EnvStrict)
}
