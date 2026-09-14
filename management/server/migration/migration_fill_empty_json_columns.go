package migration

import (
	"context"

	"gorm.io/gorm"
)

// name_server_groups
func FillEmptyNameserverGroupJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update name_server_groups set name_servers='[]' where id in (select id from name_server_groups where name_servers='' or name_servers=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update name_server_groups set groups='[]' where id in (select id from name_server_groups where groups='' or groups=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update name_server_groups set domains='[]' where id in (select id from name_server_groups where domains='' or domains=null order by id asc)`)
		return res.Error
	})
}

func FillEmptyPeerJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update peers set ip='{}' where id in (select id from peers where ip='' or ip=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set ipv6='{}' where id in (select id from peers where ipv6='' or ipv6=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set meta_network_addresses='[]' where id in (select id from peers where meta_network_addresses='' or meta_network_addresses=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set meta_environment='{}' where id in (select id from peers where meta_environment='' or meta_environment=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set meta_flags='{}' where id in (select id from peers where meta_flags='' or meta_flags=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set meta_files='[]' where id in (select id from peers where meta_files='' or meta_files=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set meta_capabilities='[]' where id in (select id from peers where meta_capabilities='' or meta_capabilities=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set location_connection_ip='{}' where id in (select id from peers where location_connection_ip='' or location_connection_ip=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set extra_dns_labels='[]' where id in (select id from peers where extra_dns_labels='' or extra_dns_labels=null order by id asc)`)
		return res.Error
	})
}

func FillEmptySettingsJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update accounts set settings_jwt_allow_groups='[]' where id in (select id from accounts where settings_jwt_allow_groups='' or settings_jwt_allow_groups=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update accounts set settings_network_range='{}' where id in (select id from accounts where settings_network_range='' or settings_network_range=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update accounts set settings_network_range_v6='{}' where id in (select id from accounts where settings_network_range_v6='' or settings_network_range_v6=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update accounts set settings_peer_expose_groups='[]' where id in (select id from accounts where settings_peer_expose_groups='' or settings_peer_expose_groups=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update accounts set settings_ipv6_enabled_groups='[]' where id in (select id from accounts where settings_ipv6_enabled_groups='' or settings_ipv6_enabled_groups=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update accounts set settings_extra_integrated_validator_groups='[]' where id in (select id from accounts where settings_extra_integrated_validator_groups='' or settings_extra_integrated_validator_groups=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}

		return res.Error
	})
}
