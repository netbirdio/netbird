package nmdata

import (
	"reflect"
	"testing"
)

// TestGroupCopy_AllFieldsCopied fills every Group field with a unique non-zero
// value derived from its field path, so a field added to Group but forgotten
// in Copy fails here by name without the test needing an update. The unique
// per-path values also catch fields swapped inside Copy.
func TestGroupCopy_AllFieldsCopied(t *testing.T) {
	src := &Group{}
	seed := 0
	fillValue(t, reflect.ValueOf(src).Elem(), "Group", &seed)

	copied := src.Copy()

	srcV := reflect.ValueOf(src).Elem()
	copiedV := reflect.ValueOf(copied).Elem()
	for i := 0; i < srcV.NumField(); i++ {
		name := srcV.Type().Field(i).Name
		if !reflect.DeepEqual(srcV.Field(i).Interface(), copiedV.Field(i).Interface()) {
			t.Errorf("field %s not copied: src=%#v copy=%#v",
				name, srcV.Field(i).Interface(), copiedV.Field(i).Interface())
		}
	}

	for i := 0; i < srcV.NumField(); i++ {
		f := srcV.Field(i)
		if f.Kind() != reflect.Slice || f.Len() == 0 {
			continue
		}
		name := srcV.Type().Field(i).Name
		fillValue(t, f.Index(0), name+"-mutated", &seed)
		if reflect.DeepEqual(f.Interface(), copiedV.Field(i).Interface()) {
			t.Errorf("field %s shares memory with the copy", name)
		}
	}
}

// fillValue sets v to a deterministic non-zero value derived from its field
// path. Kinds it does not handle fail the test loudly, so the filler is
// extended together with the struct instead of silently under-testing new
// fields.
func fillValue(t *testing.T, v reflect.Value, path string, seed *int) {
	t.Helper()

	switch v.Kind() {
	case reflect.String:
		v.SetString(path)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		*seed++
		v.SetInt(int64(*seed))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		*seed++
		v.SetUint(uint64(*seed))
	case reflect.Float32, reflect.Float64:
		*seed++
		v.SetFloat(float64(*seed))
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 2, 2)
		fillValue(t, s.Index(0), path+"[0]", seed)
		fillValue(t, s.Index(1), path+"[1]", seed)
		v.Set(s)
	case reflect.Struct:
		settable := 0
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if !f.CanSet() {
				continue
			}
			settable++
			fillValue(t, f, path+"."+v.Type().Field(i).Name, seed)
		}
		if settable == 0 {
			t.Fatalf("struct %s at %s has no settable fields — extend fillValue to construct it", v.Type(), path)
		}
	default:
		t.Fatalf("unsupported kind %s at %s — extend fillValue", v.Kind(), path)
	}
}
