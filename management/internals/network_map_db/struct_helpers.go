package networkmapdb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

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

func FromSqlTypesToSharedTypes(src reflect.Value, dst reflect.Value) error {
	typ := src.Elem().Type()

	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)

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

		dstField := dst.Elem().FieldByName(dstFieldName)
		if !dstField.IsValid() {
			return errors.New("unsupported type in destination field: " + dstFieldName)
		}

		srcField := src.Elem().Field(i)
		srcFieldType := srcField.Type().String()
		switch srcFieldType {
		case "string":
			s := srcField.Interface().(string)
			dstField.SetString(s)
		case "sql.NullString":
			s := srcField.Interface().(sql.NullString)
			if s.Valid {
				dstField.SetString(s.String)
			}
			if (dstFieldName == "PublicId" || dstFieldName == "PublicID") && s.String == "" {
				dstField.SetString(xid.New().String()) // TODO (dmitri) this needs to be removed to support delta updates
			}
		case "sql.NullTime":
			s := srcField.Interface().(sql.NullTime)
			if s.Valid {
				if dstField.Kind() == reflect.Ptr {
					t := reflect.ValueOf(&s.Time).Elem()
					dstField.Set(t.Addr())
				} else {
					dstField.Set(reflect.ValueOf(s.Time))
				}
			}
		case "sql.NullBool":
			s := srcField.Interface().(sql.NullBool)
			if s.Valid {
				dstField.SetBool(s.Bool)
			}
		case "sql.NullInt64":
			s := srcField.Interface().(sql.NullInt64)
			if s.Valid {
				dstField.SetInt(s.Int64)
			}
		case "json.RawMessage":
			s := srcField.Interface().(json.RawMessage)
			if len(s) == 0 {
				continue
			}
			if err := json.Unmarshal(s, dstField.Addr().Interface()); err != nil {
				return err
			}
		case "[]byte", "[]uint8":
			s := srcField.Interface().([]byte)
			if _, ok := fieldTags[NMAP_JSON]; !ok || len(s) == 0 {
				continue
			}
			if err := json.Unmarshal(s, dstField.Addr().Interface()); err != nil {
				return err
			}
		case "[]string":
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
