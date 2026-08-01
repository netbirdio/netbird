package networkmapdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	NMAP_STRUCT_TAG = "nmap"
	NMAP_SKIP       = "skip"
	NMAP_MAP_TO     = "map_to"
)

type NetworkMapDBStore interface {
	GetGroups(ctx context.Context, accountId string) ([]nmdata.Group, map[string][]*nmdata.Group, error)
	GetPeers(ctx context.Context, accountId string) ([]nmdata.Peer, error)
	GetPolicies(ctx context.Context, accountId string) ([]nmdata.Policy, error)
	GetRoutes(ctx context.Context, accountId string) ([]nmdata.Route, error)
	GetNameServerGroups(ctx context.Context, accountId string) ([]nmdata.NameServerGroup, error)
	GetNetworkResources(ctx context.Context, accountId string) ([]nmdata.NetworkResource, error)
	GetNetworkRouters(ctx context.Context, accountId string) (map[string]map[string]*nmdata.NetworkRouter, error)
	GetNetwork(ctx context.Context, accountId string) (nmdata.Network, error)
	GetAccountZones(ctx context.Context, accountId string) ([]nmdata.CustomZone, error)
	GetAccountSettings(ctx context.Context, accountId string) (nmdata.AccountSettingsInfo, error)
	GetPostureChecks(ctx context.Context, accountId string) ([]nmdata.PostureChecks, error)
	GetNetworkMapData(ctx context.Context, accountId string) (*networkmap.NetworkMapData, error)
}

type NetworkMapDBStoreImpl struct {
	store NetworkMapDBStore
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
			json.Unmarshal(s, dstField.Addr().Interface())
		case "[]string":
			if srcField.IsNil() {
				return nil
			}
			dstv := reflect.MakeSlice(dstField.Type(), srcField.Len(), srcField.Cap())
			reflect.Copy(dstv, srcField)
			dstField.Set(dstv)
		}
	}

	return nil
}

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
