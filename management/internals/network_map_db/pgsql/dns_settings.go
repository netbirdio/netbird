package networkmap_pgsql

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetDnsSettingsQuery = `
	select dns_settings_disabled_management_groups
	from accounts
	where id=$1
	`
)

func (pgc *PgStoreConn) GetDnsSettings(ctx context.Context, accountId string) (nmdata.DNSSettings, error) {
	rows, err := pgc.Conn.Query(ctx, GetDnsSettingsQuery, accountId)
	if err != nil {
		return nmdata.DNSSettings{}, err
	}

	return pgx.CollectOneRow(rows, rowToDnsSettings)
}

func rowToDnsSettings(row pgx.CollectableRow) (nmdata.DNSSettings, error) {
	var value nmdata.DNSSettings
	var settings json.RawMessage

	if err := row.Scan(&settings); err != nil {
		return value, err
	}

	if settings == nil {
		return nmdata.DNSSettings{}, nil
	}

	if err := json.Unmarshal(settings, &value.DisabledManagementGroups); err != nil {
		return value, err
	}

	return value, nil
}
