package grpc

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// authTokenField is the only per-proxy field that shallowCloneMapping must NOT
// copy from the source, since callers assign it individually after cloning.
const authTokenField = "AuthToken"

// TestShallowCloneMapping_ClonesAllFields populates every exported field of
// ProxyMapping with a non-zero value and verifies the clone carries each one
// (except AuthToken). It uses reflection so adding a new field to ProxyMapping
// without updating shallowCloneMapping fails this test.
func TestShallowCloneMapping_ClonesAllFields(t *testing.T) {
	src := &proto.ProxyMapping{}
	populated := populateExportedFields(t, reflect.ValueOf(src).Elem())
	require.NotEmpty(t, populated, "ProxyMapping should expose fields to populate")

	clone := shallowCloneMapping(src)
	require.NotNil(t, clone, "clone must not be nil")

	srcVal := reflect.ValueOf(src).Elem()
	cloneVal := reflect.ValueOf(clone).Elem()

	for _, name := range populated {
		srcField := srcVal.FieldByName(name).Interface()
		cloneField := cloneVal.FieldByName(name).Interface()

		if name == authTokenField {
			assert.Zero(t, cloneField, "AuthToken must not be cloned; it is set per proxy after cloning")
			continue
		}

		assert.Equal(t, srcField, cloneField, "field %s must be carried over by shallowCloneMapping", name)
	}
}

// populateExportedFields sets a non-zero value on every settable exported field
// of the struct and returns their names.
func populateExportedFields(t *testing.T, v reflect.Value) []string {
	t.Helper()

	var names []string
	typ := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		structField := typ.Field(i)

		if structField.PkgPath != "" || !field.CanSet() {
			continue
		}

		setNonZero(t, field, structField.Name)
		names = append(names, structField.Name)
	}
	return names
}

// setNonZero assigns a deterministic non-zero value based on the field kind.
func setNonZero(t *testing.T, field reflect.Value, name string) {
	t.Helper()

	switch field.Kind() {
	case reflect.String:
		field.SetString("non-zero-" + name)
	case reflect.Bool:
		field.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		field.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		field.SetUint(7)
	case reflect.Ptr:
		field.Set(reflect.New(field.Type().Elem()))
	case reflect.Slice:
		field.Set(reflect.MakeSlice(field.Type(), 1, 1))
	case reflect.Map:
		field.Set(reflect.MakeMapWithSize(field.Type(), 0))
	default:
		t.Fatalf("unhandled field kind %s for field %s; extend setNonZero", field.Kind(), name)
	}
}
