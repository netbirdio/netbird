package elevate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// A file the test user created under their own profile, which is what a per-user
// install looks like. The whole chain up to the volume root is walked, so this is
// also what says the walk does not refuse an ordinary Windows installation: the
// root of every volume grants BUILTIN\Users rights that are not ours to worry
// about.
func TestCheckOnlyOwnerWritableAcceptsOwnFile(t *testing.T) {
	err := checkOnlyOwnerWritable(writeExecutable(t))
	assert.NoError(t, err, "a file the test user owns, under directories only administrators can write")
}

// Write access held by an account that cannot answer the UAC prompt means that
// account decides what runs behind it, whoever the ACE names. The trustees that
// must not have it cannot be listed, so the check names the ones that may.
func TestCheckOnlyOwnerWritableRejectsUntrustedWriters(t *testing.T) {
	tests := []struct {
		name      string
		wellKnown windows.WELL_KNOWN_SID_TYPE
	}{
		{name: "everyone", wellKnown: windows.WinWorldSid},
		{name: "authenticated users", wellKnown: windows.WinAuthenticatedUserSid},
		{name: "builtin users", wellKnown: windows.WinBuiltinUsersSid},
		// A service account, which no denylist of the obvious groups would name
		// and which cannot elevate any more than Everyone can.
		{name: "local service", wellKnown: windows.WinLocalServiceSid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeExecutable(t)
			grantWrite(t, path, tt.wellKnown)

			assert.Error(t, checkOnlyOwnerWritable(path),
				"write access for %s must be refused", tt.name)
		})
	}
}

// The masks are the policy: on a file any write reaches its contents, while on a
// directory only deleting or taking over an entry reaches something already
// there. Adding an entry does not, which is why the walk survives a volume root.
func TestWriteAccessMasks(t *testing.T) {
	assert.NotZero(t, fileWriteAccess&windows.FILE_WRITE_DATA, "writing a file's data reaches its contents")
	assert.NotZero(t, fileWriteAccess&windows.FILE_APPEND_DATA, "appending to a file reaches its contents")

	assert.Zero(t, dirWriteAccess&windows.FILE_WRITE_DATA, "adding a file to a directory replaces nothing")
	assert.Zero(t, dirWriteAccess&windows.FILE_APPEND_DATA, "adding a subdirectory replaces nothing")
	assert.NotZero(t, dirWriteAccess&fileDeleteChild, "deleting an entry replaces it")
	assert.NotZero(t, dirWriteAccess&windows.DELETE, "deleting the directory takes its entries with it")
}

func TestIsAllowACE(t *testing.T) {
	tests := []struct {
		name    string
		aceType uint8
		want    bool
	}{
		{name: "allowed", aceType: windows.ACCESS_ALLOWED_ACE_TYPE, want: true},
		{name: "allowed callback", aceType: accessAllowedCallbackACEType, want: true},
		{name: "allowed object", aceType: accessAllowedObjectACEType, want: true},
		{name: "allowed callback object", aceType: accessAllowedCallbackObjectACEType, want: true},
		{name: "denied", aceType: windows.ACCESS_DENIED_ACE_TYPE},
		// SYSTEM_AUDIT_ACE_TYPE, which x/sys does not define: an ACE that records
		// access rather than granting it.
		{name: "audit", aceType: 0x2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAllowACE(tt.aceType), "ACE type %#x", tt.aceType)
		})
	}
}

// writeExecutable creates a plain file under the test's own directory, the shape
// trustedSelf checks.
func writeExecutable(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "netbird-ui.exe")
	require.NoError(t, os.WriteFile(path, []byte("MZ"), 0o755), "write the executable")
	return path
}

// grantWrite replaces the file's DACL with one that grants a well-known trustee
// everything, keeping the test user's own access so the file stays deletable.
func grantWrite(t *testing.T, path string, wellKnown windows.WELL_KNOWN_SID_TYPE) {
	t.Helper()

	trustee, err := windows.CreateWellKnownSid(wellKnown)
	require.NoError(t, err, "build the trustee SID")
	self, err := currentUserSID()
	require.NoError(t, err, "read the test user's SID")

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		fullControl(self, windows.TRUSTEE_IS_USER),
		fullControl(trustee, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	}, nil)
	require.NoError(t, err, "build the ACL")

	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil), "set the DACL")
}

func fullControl(sid *windows.SID, trusteeType uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_TYPE(trusteeType),
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
