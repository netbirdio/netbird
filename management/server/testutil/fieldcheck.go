package testutil

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

// EqualComparesAllFields sets one exported field of T at a time on one of two
// zero values and fails if equal still reports them equal. Fields in ignored
// must keep equal reporting true.
func EqualComparesAllFields[T any](t *testing.T, equal func(a, b *T) bool, ignored ...string) {
	t.Helper()

	typ := reflect.TypeFor[T]()
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}

		var a, b T
		setNonZero(t, reflect.ValueOf(&b).Elem().Field(i))

		if slices.Contains(ignored, field.Name) {
			assert.True(t, equal(&a, &b), "%s.Equal compares %s; remove it from the ignored fields", typ, field.Name)
			continue
		}
		assert.False(t, equal(&a, &b), "%s.Equal does not compare %s", typ, field.Name)
	}
}

// setNonZero assigns a deterministic non-zero value, recursing into structs,
// pointers, and one element of slices and maps.
func setNonZero(t *testing.T, v reflect.Value) {
	t.Helper()

	if v.Type() == reflect.TypeFor[netip.Prefix]() {
		v.Set(reflect.ValueOf(netip.MustParsePrefix("10.0.0.0/24")))
		return
	}

	switch v.Kind() {
	case reflect.String:
		v.SetString("non-zero")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(7)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		setNonZero(t, v.Elem())
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		setNonZero(t, v.Index(0))
	case reflect.Map:
		key, elem := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		setNonZero(t, key)
		setNonZero(t, elem)
		v.Set(reflect.MakeMapWithSize(v.Type(), 1))
		v.SetMapIndex(key, elem)
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				setNonZero(t, v.Field(i))
			}
		}
		if v.IsZero() {
			t.Fatalf("cannot set a non-zero %s; extend setNonZero", v.Type())
		}
	default:
		t.Fatalf("unhandled kind %s for %s; extend setNonZero", v.Kind(), v.Type())
	}
}
