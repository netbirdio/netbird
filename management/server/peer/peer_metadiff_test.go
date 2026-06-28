package peer

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// metaDiffExtraEntries accounts for PeerSystemMeta fields that metaDiff does not
// map 1:1 to a single diff entry. Today the only such field is Environment, which
// is exploded into two checks (Cloud, Platform) and therefore yields one extra
// entry beyond its single struct field. If you teach metaDiff to explode another
// field into N entries, bump this by N-1; if you collapse a field, lower it.
const metaDiffExtraEntries = 1

// TestMetaDiff_CoversAllFields fully populates a PeerSystemMeta with non-zero
// values and diffs it against the zero value, then asserts metaDiff emits exactly
// one entry per exported field (plus metaDiffExtraEntries for fields it explodes).
//
// The expected count is derived from the struct via reflection, so adding a field
// to PeerSystemMeta raises the expectation automatically — but the actual diff
// only grows if metaDiff was taught to compare the new field. A mismatch means
// someone changed the struct without updating metaDiff (or this test's
// extra-entry accounting), which is exactly what we want to catch.
func TestMetaDiff_CoversAllFields(t *testing.T) {
	var full PeerSystemMeta
	exported := populateAll(t, reflect.ValueOf(&full).Elem())
	require.NotZero(t, exported, "expected PeerSystemMeta to expose fields")

	diff := metaDiff(PeerSystemMeta{}, full)

	require.Len(t, diff, exported+metaDiffExtraEntries,
		"metaDiff entry count no longer matches PeerSystemMeta's fields: a field was "+
			"likely added or removed without updating metaDiff (or metaDiffExtraEntries). "+
			"diff was: %v", diff)

	require.False(t, full.isEqual(PeerSystemMeta{}),
		"isEqual must report a fully-populated meta as different from the zero value")
}

// TestFlags_isEqualChecksEveryField guards the one field that the count-based
// TestMetaDiff_CoversAllFields cannot: metaDiff collapses all of Flags into a
// single "flags" diff entry, so a new Flags field that Flags.isEqual forgets to
// compare would not change the diff count. This flips each Flags field on its own
// and asserts Flags.isEqual notices, so adding a Flags field without comparing it
// fails here.
func TestFlags_isEqualChecksEveryField(t *testing.T) {
	typ := reflect.TypeOf(Flags{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		require.Equal(t, reflect.Bool, f.Type.Kind(),
			"Flags.%s is not a bool; extend this test to set it non-zero", f.Name)

		var a, b Flags
		reflect.ValueOf(&b).Elem().Field(i).SetBool(true)
		require.False(t, a.isEqual(b), "Flags.isEqual ignores field %s", f.Name)
	}
}

// populateAll sets every exported field of the struct to a deterministic non-zero
// value, recursing into nested structs and the element type of struct slices so
// that each leaf differs from zero. It returns the number of exported fields on
// the top-level struct. netip.Prefix is treated as an opaque leaf (it has no
// settable exported fields and is comparable with ==).
func populateAll(t *testing.T, v reflect.Value) int {
	t.Helper()

	typ := v.Type()
	exported := 0
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		exported++
		setNonZero(t, v.Field(i))
	}
	return exported
}

// setNonZero assigns a deterministic non-zero value to a field based on its kind,
// recursing into nested structs and populating one element of slice fields.
func setNonZero(t *testing.T, field reflect.Value) {
	t.Helper()

	if field.Type() == reflect.TypeOf(netip.Prefix{}) {
		field.Set(reflect.ValueOf(netip.MustParsePrefix("10.0.0.0/24")))
		return
	}

	switch field.Kind() {
	case reflect.String:
		field.SetString("non-zero")
	case reflect.Bool:
		field.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		field.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		field.SetUint(7)
	case reflect.Float32, reflect.Float64:
		field.SetFloat(7)
	case reflect.Struct:
		populateAll(t, field)
	case reflect.Slice:
		s := reflect.MakeSlice(field.Type(), 1, 1)
		setNonZero(t, s.Index(0))
		field.Set(s)
	default:
		t.Fatalf("unhandled field kind %s; extend setNonZero", field.Kind())
	}
}
