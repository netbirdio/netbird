//go:build pkcs11 && linux && !android && (amd64 || arm64)

package pkcs11

import (
	"crypto/x509"
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStructLayoutsMatchTheCABI(t *testing.T) {
	assert.Equal(t, uintptr(24), unsafe.Sizeof(attribute{}), "CK_ATTRIBUTE")
	assert.Equal(t, uintptr(24), unsafe.Sizeof(mechanism{}), "CK_MECHANISM")
	assert.Equal(t, uintptr(24), unsafe.Sizeof(pssParams{}), "CK_RSA_PKCS_PSS_PARAMS")
	assert.Equal(t, uintptr(208), unsafe.Sizeof(tokenInfo{}), "CK_TOKEN_INFO")
	assert.Equal(t, uintptr(48), unsafe.Sizeof(initializeArgs{}), "CK_C_INITIALIZE_ARGS")
	assert.Equal(t, uintptr(8), unsafe.Offsetof(functionList{}.fn), "entry points follow the padded CK_VERSION")
	assert.Equal(t, uintptr(8+68*8), unsafe.Sizeof(functionList{}), "CK_FUNCTION_LIST v2.40")
}

// TestTrustModule_ListsSystemCertificates drives a real module through the binding:
// p11-kit's trust module exposes the system CA store as certificate objects with no login.
func TestTrustModule_ListsSystemCertificates(t *testing.T) {
	module := loadFirst(t,
		"/usr/lib/pkcs11/p11-kit-trust.so",
		"/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so",
		"/usr/lib/aarch64-linux-gnu/pkcs11/p11-kit-trust.so",
		"/usr/lib64/pkcs11/p11-kit-trust.so",
	)

	tokens, err := module.Tokens()
	require.NoError(t, err)
	require.NotEmpty(t, tokens, "the trust module must present at least one token")

	parsed := 0
	for _, token := range tokens {
		session, err := module.OpenSession(token.Label, nil)
		require.NoError(t, err, token.Label)
		objects, err := session.FindObjects(
			Attribute{Type: AttrClass, Value: ULong(ClassCertificate)},
			Attribute{Type: AttrCertificateType, Value: ULong(CertificateX509)},
		)
		require.NoError(t, err, token.Label)
		for _, object := range objects {
			der, err := session.Attribute(object, AttrValue)
			require.NoError(t, err)
			_, err = x509.ParseCertificate(der)
			require.NoError(t, err, "CKA_VALUE must be a DER certificate")
			parsed++
		}
		session.Close()
	}
	assert.Positive(t, parsed, "system trust anchors must be readable through the binding")
}

func loadFirst(t *testing.T, paths ...string) *Module {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		module, err := Load(path)
		require.NoError(t, err, path)
		return module
	}
	t.Skip("p11-kit trust module not installed")
	return nil
}

// TestSlotList_RetriesWhenTheListGrows: a token plugged in between the size query and the
// fill makes the module answer CKR_BUFFER_TOO_SMALL; the list has to be asked for again.
func TestSlotList_RetriesWhenTheListGrows(t *testing.T) {
	calls := 0
	m := &module{cGetSlotList: func(_ byte, slots *ulong, count *ulong) ulong {
		calls++
		switch {
		case slots == nil && calls == 1:
			*count = 1
		case slots != nil && calls == 2:
			*count = 2
			return rvBufferTooSmall
		case slots == nil:
			*count = 2
		default:
			*count = 2
			backing := unsafe.Slice(slots, 2)
			backing[0], backing[1] = 7, 9
		}
		return rvOK
	}}

	slots, err := m.slotList()

	require.NoError(t, err)
	assert.Equal(t, []ulong{7, 9}, slots, "the list is read again at its new size")
}

func TestSlotList_GivesUpOnAListThatKeepsGrowing(t *testing.T) {
	m := &module{cGetSlotList: func(_ byte, slots *ulong, count *ulong) ulong {
		if slots == nil {
			*count = 1
			return rvOK
		}
		return rvBufferTooSmall
	}}

	_, err := m.slotList()

	assert.Error(t, err, "a module that never settles on a size is an error, not a loop")
}

func TestCheckFunctionListVersion(t *testing.T) {
	assert.NoError(t, checkFunctionListVersion(version{major: 2, minor: 40}))
	assert.NoError(t, checkFunctionListVersion(version{major: 3, minor: 0}))
	assert.Error(t, checkFunctionListVersion(version{major: 1, minor: 0}), "a pre-2.0 list has no entry points to index")
	assert.Error(t, checkFunctionListVersion(version{}), "an empty version is not a function list")
}

// fakeFindModule answers C_FindObjects from batches, a handle per entry, and reports how
// the search was torn down.
func fakeFindModule(batches [][]ulong, finalized *int) *module {
	next := 0
	return &module{
		cFindObjectsInit:  func(ulong, *attribute, ulong) ulong { return rvOK },
		cFindObjectsFinal: func(ulong) ulong { *finalized++; return rvOK },
		cFindObjects: func(_ ulong, objects *ulong, max ulong, count *ulong) ulong {
			if next >= len(batches) {
				*count = 0
				return rvOK
			}
			batch := batches[next]
			next++
			copy(unsafe.Slice(objects, max), batch)
			*count = ulong(len(batch))
			return rvOK
		},
	}
}

var findTemplate = []Attribute{{Type: AttrClass, Value: ULong(ClassPrivateKey)}}

// TestFindObjects_ReadsPastAShortBatch: PKCS#11 ends a search with an empty batch, not with
// one shorter than asked for, so a module that hands out its handles in small batches must
// still have all of them returned.
func TestFindObjects_ReadsPastAShortBatch(t *testing.T) {
	finalized := 0
	m := fakeFindModule([][]ulong{{1, 2}, {3}, {4, 5, 6}}, &finalized)

	objects, err := m.findObjects(1, findTemplate)

	require.NoError(t, err)
	assert.Equal(t, []Object{1, 2, 3, 4, 5, 6}, objects, "every batch is read until the module returns an empty one")
	assert.Equal(t, 1, finalized, "the search is finished once")
}

func TestFindObjects_StopsAtAnEmptyBatch(t *testing.T) {
	finalized := 0
	m := fakeFindModule(nil, &finalized)

	objects, err := m.findObjects(1, findTemplate)

	require.NoError(t, err)
	assert.Empty(t, objects, "a search that finds nothing returns nothing")
	assert.Equal(t, 1, finalized)
}

// TestFindObjects_BoundsAModuleThatNeverEnds: a module that keeps returning handles must
// not make the daemon allocate without limit.
func TestFindObjects_BoundsAModuleThatNeverEnds(t *testing.T) {
	finalized := 0
	endless := &module{
		cFindObjectsInit:  func(ulong, *attribute, ulong) ulong { return rvOK },
		cFindObjectsFinal: func(ulong) ulong { finalized++; return rvOK },
		cFindObjects: func(_ ulong, _ *ulong, _ ulong, count *ulong) ulong {
			*count = findBatch
			return rvOK
		},
	}

	_, err := endless.findObjects(1, findTemplate)

	assert.Error(t, err, "an endless search is cut off")
	assert.Equal(t, 1, finalized, "and still finished")
}
