package ipcauth

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ValidatePrincipal gates what a user may write. ParsePrincipal gates what is
// read back, and stays lenient so an existing config is never reinterpreted.
func TestValidatePrincipal(t *testing.T) {
	unix := runtime.GOOS != "windows"

	for _, tc := range []struct {
		in    string
		valid bool
	}{
		{"uid:0", unix},
		{"uid:1000", unix},
		{"uid:4294967295", unix},
		{"uid:4294967296", false},
		{"uid:abc", false},
		{"uid:-1", false},
		{"uid:1000:extra", false},
		{"sid:S-1-5-21-1-2-3-1001", !unix},
		{"sid:S-1-5-18", !unix},
		{"sid:S-1", false},
		{"sid:S-1-5-", false},
		{"sid:hello", false},
		{"sid:X-1-5-18", false},
		{"bogus:1000", false},
		{"uid:", false},
		{"1000", false},
		{"", false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ValidatePrincipal(tc.in)
			if !tc.valid {
				require.Error(t, err, "%q must not be accepted as an owner", tc.in)
				assert.Equal(t, Principal{}, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.in, got.String())
		})
	}
}

// The read path must keep accepting what it always did, whatever the write path
// now refuses.
func TestParsePrincipalStaysLenient(t *testing.T) {
	for _, in := range []string{"uid:abc", "uid:-1", "sid:hello", "uid:1000:extra"} {
		t.Run(in, func(t *testing.T) {
			_, ok := ParsePrincipal(in)
			assert.True(t, ok, "ParsePrincipal must still read %q, a stored config may carry it", in)

			_, err := ValidatePrincipal(in)
			assert.Error(t, err, "but it must not be accepted as new input")
		})
	}
}

// ValidatePrincipal cannot reach the unknown kinds, since ParsePrincipal refuses
// them first. A Principal built in code can carry one, and a privileged writer
// validates the value it was handed rather than a string it parsed.
func TestPrincipalValidateRejectsKindsParsingNeverProduces(t *testing.T) {
	for _, p := range []Principal{
		{},
		{Kind: "bogus", Value: "1000"},
		{Kind: KindUID},
		{Kind: KindSID},
	} {
		t.Run(p.String(), func(t *testing.T) {
			assert.Error(t, p.Validate(), "%v must not be accepted as an owner", p)
		})
	}
}
