package networkmap_sqlite

import (
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetDnsSettingsQuery = `
	select dns_settings_disabled_management_groups
	from accounts
	where id=?
	`
)

func (sc *SqliteStoreConn) GetDnsSettings(ctx context.Context, accountId string) (nmdata.DNSSettings, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetDnsSettingsQuery, accountId)
	if err != nil {
		return nmdata.DNSSettings{}, err
	}
	defer rows.Close()

	var value nmdata.DNSSettings
	var settings []byte

	rows.Next()
	if err := rows.Scan(&settings); err != nil {
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
