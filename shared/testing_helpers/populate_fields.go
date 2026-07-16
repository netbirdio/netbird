package testing_helpers

import (
	"fmt"
	"net/netip"
	"reflect"
)

type PopulateFields struct {
	CustomFieldSetters map[reflect.Type]func(this *PopulateFields, field reflect.Value) (int, error)
	TagsToSkip         map[string]string
}

func NewPopulateFields() *PopulateFields {
	return &PopulateFields{CustomFieldSetters: defaultCustomFieldSetters(), TagsToSkip: make(map[string]string)}
}

func (p *PopulateFields) WithCustomFieldSetter(t reflect.Type, f func(this *PopulateFields, field reflect.Value) (int, error)) *PopulateFields {
	p.CustomFieldSetters[t] = f
	return p
}

func (p *PopulateFields) WithSkippedTag(tag, value string) *PopulateFields {
	p.TagsToSkip[tag] = value
	return p
}

func (p *PopulateFields) PopulateAll(v reflect.Value) (int, error) {
	typ := v.Type()
	totalExportedFields := 0
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}

		if p.skippedTagPresent(f.Tag) {
			continue
		}

		numOfExportedFields, err := p.setNonZero(v.Field(i))
		totalExportedFields += numOfExportedFields
		if err != nil {
			return totalExportedFields, err
		}
	}
	return totalExportedFields, nil
}

// setNonZero assigns a deterministic non-zero value to a field based on its kind,
// recursing into nested structs and populating one element of slice fields.
func (p *PopulateFields) setNonZero(field reflect.Value) (int, error) {
	if f, ok := p.CustomFieldSetters[field.Type()]; ok {
		return f(p, field)
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
		n, err := p.PopulateAll(field)
		return n + 1, err
	case reflect.Slice:
		s := reflect.MakeSlice(field.Type(), 1, 1)
		p.setNonZero(s.Index(0))
		field.Set(s)
	default:
		return 0, fmt.Errorf("unhandled field kind %s; extend setNonZero", field.Kind())
	}

	return 1, nil
}

func defaultCustomFieldSetters() map[reflect.Type]func(this *PopulateFields, field reflect.Value) (int, error) {
	return map[reflect.Type]func(this *PopulateFields, field reflect.Value) (int, error){
		reflect.TypeOf(netip.Prefix{}): func(_ *PopulateFields, field reflect.Value) (int, error) {
			field.Set(reflect.ValueOf(netip.MustParsePrefix("10.0.0.0/24")))
			return 1, nil
		},
	}
}

func (p *PopulateFields) skippedTagPresent(t reflect.StructTag) bool {
	for tag, value := range p.TagsToSkip {
		if v := t.Get(tag); v == value {
			return true
		}
	}
	return false
}
