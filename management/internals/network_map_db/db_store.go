package networkmapdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/rs/xid"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	NMAP_STRUCT_TAG = "nmap"
	NMAP_SKIP       = "skip"
	NMAP_MAP_TO     = "map_to"
	NMAP_JSON       = "json"
)

type NetworkMapDBStore interface { //nolint:revive // established name across the codebase
	GetNetworkMapData(ctx context.Context, accountId string) (*networkmap.NetworkMapData, error)
}

type NetworkMapDBStoreConn interface { //nolint:revive // established name across the codebase
	GetGroups(ctx context.Context, accountId string) ([]nmdata.Group, map[string]map[string]any, error)
	GetDomains(ctx context.Context, accountId string) ([]Domain, error)
	GetPeers(ctx context.Context, accountId string) ([]nmdata.Peer, map[string][]*nmdata.Peer, error)
	GetPolicies(ctx context.Context, accountId string) ([]nmdata.Policy, map[string]map[string]any, map[string]map[string]any, error)
	GetRoutes(ctx context.Context, accountId string) ([]nmdata.Route, error)
	GetNameServerGroups(ctx context.Context, accountId string) ([]nmdata.NameServerGroup, error)
	GetNetworkResources(ctx context.Context, accountId string) ([]nmdata.NetworkResource, error)
	GetNetworkRouters(ctx context.Context, accountId string) (map[string]map[string]*nmdata.NetworkRouter, error)
	GetNetwork(ctx context.Context, accountId string) (nmdata.Network, error)
	GetAppliedZoneCandidates(ctx context.Context, accountId string) ([]networkmap.AppliedZoneCandidate, error)
	GetAccountSettings(ctx context.Context, accountId string) (nmdata.AccountSettingsInfo, error)
	GetPostureChecks(ctx context.Context, accountId string) ([]nmdata.PostureChecks, map[string]string, error)
	GetAllowedUsers(ctx context.Context, accountId string) (map[string]struct{}, map[string][]string, error)
	GetDnsSettings(ctx context.Context, accountId string) (nmdata.DNSSettings, error)
	GetNetworkXIDToPublicIdMap(ctx context.Context, accountId string) (map[string]string, error)
	GetPrivateServices(ctx context.Context, accountId string) ([]Service, error)
	GetProxyTargetedDomainResourceIDs(ctx context.Context, accountId string) (map[string]struct{}, error)
}

type Domain struct {
	Domain        sql.NullString
	TargetCluster sql.NullString
}

type Service struct {
	Enabled      sql.NullBool
	Private      sql.NullBool
	AccessGroups []string
	ProxyCluster sql.NullString
	Domain       sql.NullString
}

type NetworkMapDBStoreImpl struct { //nolint:revive // established name across the codebase
	store                   NetworkMapDBStore
	integratedPeerValidator integrated_validator.IntegratedValidator
	extraSettingsManager    settings.Manager
}

func NewNetworkMapDBStoreImpl(store NetworkMapDBStore, integratedPeerValidator integrated_validator.IntegratedValidator, extraSettingsManager settings.Manager) *NetworkMapDBStoreImpl {
	return &NetworkMapDBStoreImpl{
		store:                   store,
		integratedPeerValidator: integratedPeerValidator,
		extraSettingsManager:    extraSettingsManager,
	}
}

func (s *NetworkMapDBStoreImpl) GetNetworkMapData(ctx context.Context, accountId string) (*networkmap.NetworkMapData, error) {
	nmdata, err := s.store.GetNetworkMapData(ctx, accountId)
	if err != nil {
		return nil, err
	}

	extraSettings, err := s.extraSettingsManager.GetExtraSettings(ctx, accountId)
	if err != nil {
		return nil, err
	}

	nmdata.ValidatedPeers, err = s.integratedPeerValidator.GetValidatedPeers(ctx, accountId, maps.Values(nmdata.Groups), maps.Values(nmdata.Peers), extraSettings)
	if err != nil {
		return nil, err
	}

	return nmdata, nil
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

func StructFields(src reflect.Value) []any {
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
