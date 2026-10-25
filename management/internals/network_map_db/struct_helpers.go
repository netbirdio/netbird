package networkmapdb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"

	"github.com/rs/xid"
)

var ErrNoRows = errors.New("no rows in result set")

const (
	NMAP_STRUCT_TAG = "nmap"
	NMAP_SKIP       = "skip"
	NMAP_MAP_TO     = "map_to"
	NMAP_JSON       = "json"
)

type fieldTag struct {
	Key   string
	Value string
}

func tagFromString(t string) fieldTag {
	kv := strings.Split(t, ":")
	if len(kv) == 1 {
		return fieldTag{Key: strings.TrimSpace(kv[0])}
	}
	return fieldTag{Key: strings.TrimSpace(kv[0]), Value: strings.TrimSpace(kv[1])}
}

// FromSqlTypesToSharedTypes copies the fields of the struct src points to into
// the struct dst points to, converting SQL null types and decoding JSON columns.
// The field mapping is worked out once per pair of types and reused.
func FromSqlTypesToSharedTypes(src reflect.Value, dst reflect.Value) error {
	plan, err := conversionPlanFor(src.Elem().Type(), dst.Elem().Type())
	if err != nil {
		return err
	}

	srcStruct, dstStruct := src.Elem(), dst.Elem()
	for _, f := range plan {
		srcField := srcStruct.Field(f.src)
		dstField := dstStruct.FieldByIndex(f.dst)

		switch f.kind {
		case fieldString:
			dstField.SetString(srcField.String())
		case fieldNullString:
			s := srcField.Interface().(sql.NullString)
			if s.Valid {
				dstField.SetString(s.String)
			}
			if f.publicID && s.String == "" {
				dstField.SetString(xid.New().String()) // TODO (dmitri) this needs to be removed to support delta updates
			}
		case fieldNullTime:
			s := srcField.Interface().(sql.NullTime)
			if s.Valid {
				if dstField.Kind() == reflect.Ptr {
					t := reflect.ValueOf(&s.Time).Elem()
					dstField.Set(t.Addr())
				} else {
					dstField.Set(reflect.ValueOf(s.Time))
				}
			}
		case fieldNullBool:
			s := srcField.Interface().(sql.NullBool)
			if s.Valid {
				dstField.SetBool(s.Bool)
			}
		case fieldNullInt64:
			s := srcField.Interface().(sql.NullInt64)
			if s.Valid {
				dstField.SetInt(s.Int64)
			}
		case fieldRawJSON:
			s := srcField.Interface().(json.RawMessage)
			if len(s) == 0 {
				continue
			}
			if err := json.Unmarshal(s, dstField.Addr().Interface()); err != nil {
				return err
			}
		case fieldBytes:
			s := srcField.Bytes()
			if !f.json || len(s) == 0 {
				continue
			}
			if err := json.Unmarshal(s, dstField.Addr().Interface()); err != nil {
				return err
			}
		case fieldStrings:
			if srcField.IsNil() {
				continue
			}
			dstv := reflect.MakeSlice(dstField.Type(), srcField.Len(), srcField.Cap())
			reflect.Copy(dstv, srcField)
			dstField.Set(dstv)
		}
	}

	return nil
}

type fieldKind int

const (
	fieldIgnored fieldKind = iota
	fieldString
	fieldNullString
	fieldNullTime
	fieldNullBool
	fieldNullInt64
	fieldRawJSON
	fieldBytes
	fieldStrings
)

// fieldConversion copies source field src into the destination field at dst.
type fieldConversion struct {
	src      int
	dst      []int
	kind     fieldKind
	json     bool
	publicID bool
}

type conversionTypes struct {
	src, dst reflect.Type
}

type conversionPlan struct {
	fields []fieldConversion
	err    error
}

var conversionPlans sync.Map

func conversionPlanFor(srcType, dstType reflect.Type) ([]fieldConversion, error) {
	key := conversionTypes{src: srcType, dst: dstType}
	if cached, ok := conversionPlans.Load(key); ok {
		plan := cached.(conversionPlan)
		return plan.fields, plan.err
	}

	fields, err := buildConversionPlan(srcType, dstType)
	conversionPlans.Store(key, conversionPlan{fields: fields, err: err})
	return fields, err
}

func buildConversionPlan(srcType, dstType reflect.Type) ([]fieldConversion, error) {
	var fields []fieldConversion
	for i := 0; i < srcType.NumField(); i++ {
		f := srcType.Field(i)

		fieldTags := make(map[string]string)
		if v := f.Tag.Get(NMAP_STRUCT_TAG); v != "" {
			for _, t := range strings.Split(v, ",") {
				kv := tagFromString(t)
				fieldTags[kv.Key] = kv.Value
			}
		}
		if _, ok := fieldTags[NMAP_SKIP]; ok {
			continue
		}
		if f.PkgPath != "" { // skip unexported fields
			continue
		}
		dstFieldName := f.Name
		if override, ok := fieldTags[NMAP_MAP_TO]; ok {
			dstFieldName = override
		}

		dstField, ok := dstType.FieldByName(dstFieldName)
		if !ok {
			return nil, errors.New("unsupported type in destination field: " + dstFieldName)
		}

		_, isJSON := fieldTags[NMAP_JSON]
		fields = append(fields, fieldConversion{
			src:      i,
			dst:      dstField.Index,
			kind:     fieldKindOf(f.Type.String()),
			json:     isJSON,
			publicID: dstFieldName == "PublicId" || dstFieldName == "PublicID",
		})
	}
	return fields, nil
}

func fieldKindOf(typeName string) fieldKind {
	switch typeName {
	case "string":
		return fieldString
	case "sql.NullString":
		return fieldNullString
	case "sql.NullTime":
		return fieldNullTime
	case "sql.NullBool":
		return fieldNullBool
	case "sql.NullInt64":
		return fieldNullInt64
	case "json.RawMessage":
		return fieldRawJSON
	case "[]byte", "[]uint8":
		return fieldBytes
	case "[]string":
		return fieldStrings
	default:
		return fieldIgnored
	}
}

func StructFields(s any) []any {
	src := reflect.ValueOf(s)
	toret := make([]any, 0)
	typ := src.Elem().Type()

	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" { // skip unexported fields
			continue
		}

		srcField := src.Elem().Field(i)
		toret = append(toret, srcField.Addr().Interface())
	}

	return toret
}

func ConvertAllToSharedTypes[T any, T1 any](allsrc []T) ([]T1, error) {
	toret := make([]T1, 0, len(allsrc))
	for _, src := range allsrc {
		var dst T1
		err := FromSqlTypesToSharedTypes(
			reflect.ValueOf(&src), reflect.ValueOf(&dst))
		if err != nil {
			return nil, err
		}
		toret = append(toret, dst)
	}
	return toret, nil
}
