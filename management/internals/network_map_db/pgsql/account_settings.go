package networkmap_pgsql

import (
	"context"
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetAccountSettingsQuery = `
	select settings_peer_login_expiration_enabled as peer_login_expiration_enabled,
	settings_peer_login_expiration as peer_login_expiration,
	settings_peer_inactivity_expiration_enabled as peer_inactivity_expiration_enabled,
	settings_peer_inactivity_expiration as peer_inactivity_expiration
	from accounts
	where id=$1
	`
)

func (pg *PgStore) GetAccountSettings(ctx context.Context, accountId string) (nmdata.AccountSettingsInfo, error) {
	rows, err := pg.Pool.Query(ctx, GetAccountSettingsQuery, accountId)
	if err != nil {
		return nmdata.AccountSettingsInfo{}, err
	}

	settings, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[account])
	if err != nil {
		return nmdata.AccountSettingsInfo{}, err
	}

	return nmdata.AccountSettingsInfo{
		PeerLoginExpirationEnabled:      settings.PeerLoginExpirationEnabled.Bool,
		PeerLoginExpiration:             time.Duration(settings.PeerLoginExpiration.Int64),
		PeerInactivityExpirationEnabled: settings.PeerLoginExpirationEnabled.Bool,
		PeerInactivityExpiration:        time.Duration(settings.PeerInactivityExpiration.Int64),
	}, nil
}

type account struct {
	PeerLoginExpirationEnabled      sql.NullBool
	PeerLoginExpiration             sql.NullInt64
	PeerInactivityExpirationEnabled sql.NullBool
	PeerInactivityExpiration        sql.NullInt64
}
